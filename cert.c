#include <sys/socket.h>

#include <arpa/inet.h>
#include <assert.h>
#include <err.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include "extern.h"

/*
 * A parsing sequence of a file (which may just be <stdin>).
 */
struct	parse {
	struct cert	*res; /* result */
	const char	*fn; /* currently-parsed file */
	int		 verbose; /* verbose output */
};

/* 
 * Wrap around the existing log macros. 
 * Do this to pass the "verbose" variable into the log.
 */

#define X509_WARNX(_p, _fmt, ...) \
	WARNX((_p)->verbose, (_fmt), ##__VA_ARGS__)
#define X509_WARNX1(_p, _fmt, ...) \
	WARNX1((_p)->verbose, (_fmt), ##__VA_ARGS__)
#define X509_LOG(_p, _fmt, ...) \
	LOG((_p)->verbose, (_fmt), __VA_ARGS__)
#define X509_CRYPTOX(_p, _fmt, ...) \
	CRYPTOX((_p)->verbose, (_fmt), __VA_ARGS__)

/*
 * Wrapper around ASN1_get_object() that preserves the current start
 * state and returns a more meaningful value.
 * Return zero on failure, non-zero on success.
 */
static int
ASN1_frame(struct parse *p, size_t sz,
	const unsigned char **cnt, long *cntsz, int *tag)
{
	int	 ret, pcls;

	assert(cnt != NULL && *cnt != NULL);
	assert(sz > 0);
	ret = ASN1_get_object(cnt, cntsz, tag, &pcls, sz);
	if ((ret & 0x80)) {
		X509_CRYPTOX(p, "%s: ASN1_get_object", p->fn);
		return 0;
	} 
	return ASN1_object_size((ret & 0x01) ? 2 : 0, *cntsz, *tag);
}

/*
 * Append an IP address structure to our list of results.
 */
static void
append_ip(struct parse *p, const struct cert_ip *ip)
{
	struct cert	*res = p->res;

	res->ips = reallocarray(res->ips, 
		res->ipsz + 1, sizeof(struct cert_ip));
	if (res->ips == NULL)
		err(EXIT_FAILURE, NULL);
	res->ips[res->ipsz++] = *ip;
}

/*
 * Append an AS identifier structure to our list of results.
 */
static void
append_as(struct parse *p, const struct cert_as *as)
{
	struct cert	*res = p->res;

	res->as = reallocarray(res->as, 
		res->asz + 1, sizeof(struct cert_as));
	if (res->as == NULL)
		err(EXIT_FAILURE, NULL);
	res->as[res->asz++] = *as;
}

/*
 * Parse an IP address, IPv4 or IPv6, as either a minimum or maximum
 * quantity (0x0 or 0xf filled).
 * Confirms to RFC 3779 2.2.3.8.
 * Return zero on failure, non-zero on success.
 */
static int
sbgp_ipaddr(struct parse *p, const struct cert_ip *ip,
	struct cert_ip_addr *addr, const ASN1_BIT_STRING *bs)
{
	long			 unused = 0;
	const unsigned char	*d;
	size_t			 dsz;

	d = bs->data;
	dsz = bs->length;

	/* Weird OpenSSL-ism to get unused bit count. */

	if ((ASN1_STRING_FLAG_BITS_LEFT & bs->flags))
		unused = ~ASN1_STRING_FLAG_BITS_LEFT & bs->flags;

	if ((ip->afi == 1 && dsz > 4) ||
	    (ip->afi == 2 && dsz > 16)) {
		X509_WARNX(p, "%s: IPv%s too large", 
			p->fn, 1 == ip->afi ? "4" : "6");
		return 0;
	} 

	addr->unused = unused;
	addr->sz = dsz;
	memcpy(addr->addr, d, dsz);
	return 1;
}

/*
 * Construct a RFC 3779 2.2.3.8 range by its bit string.
 * Return zero on failure, non-zero on success.
 */
static int
sbgp_addr(struct parse *p, 
	struct cert_ip *ip, const ASN1_BIT_STRING *bs)
{
	struct cert_ip_rng *rng = &ip->range;

	if (!sbgp_ipaddr(p, ip, &rng->min, bs)) {
		X509_WARNX1(p, "sbgp_ipaddr");
		return 0;
	} else if (!sbgp_ipaddr(p, ip, &rng->max, bs)) {
		X509_WARNX1(p, "sbgp_ipaddr");
		return 0;
	} 

	append_ip(p, ip);
	X509_LOG(p, "%s: parsed IPv%s address (singleton)", 
		p->fn, 1 == ip->afi ? "4" : "6");
	return 1;
}

/*
 * Parse X509v3 authority key identifier, RFC 6487 sec. 4.8.3.
 * Returns zero on failure, non-zero on success.
 */
static int
sbgp_akey_ident(struct parse *p, X509_EXTENSION *ext)
{
	unsigned char		*sv = NULL;
	const unsigned char 	*d;
	size_t			 dsz;
	const ASN1_TYPE		*type1, *type2;
	ASN1_SEQUENCE_ANY	*seq = NULL, *sseq = NULL;
	int			 rc = 0, ptag;
	long			 i, plen;
	char			 buf[4];

	if ((dsz = i2d_X509_EXTENSION(ext, &sv)) < 0) {
		X509_CRYPTOX(p, "%s: i2d_X509_EXTENSION", p->fn);
		goto out;
	} 

	/* Sequence consisting of OID and data. */

	d = sv;
	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		X509_WARNX1(p, "d2i_ASN1_SEQUENCE_ANY");
		goto out;
	} else if (sk_ASN1_TYPE_num(seq) != 2) {
		X509_WARNX(p, "%s: want 2 elements, have %d",
			p->fn, sk_ASN1_TYPE_num(seq));
		goto out;
	}

	type1 = sk_ASN1_TYPE_value(seq, 0);
	type2 = sk_ASN1_TYPE_value(seq, 1);

	if (type1->type != V_ASN1_OBJECT) {
		X509_WARNX(p, "%s: want ASN.1 object, "
			"have %s (NID %d)", p->fn, 
			ASN1_tag2str(type1->type), type1->type);
		goto out;
	} else if (type2->type != V_ASN1_OCTET_STRING) {
		X509_WARNX(p, "%s: want ASN.1 octet "
			"string, have %s (NID %d)", p->fn, 
			ASN1_tag2str(type2->type), type2->type);
		goto out;
	}

	/* Data is really a sub-sequence...? */

	d = type2->value.octet_string->data;
	dsz = type2->value.octet_string->length;

	if ((sseq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		X509_WARNX1(p, "d2i_ASN1_SEQUENCE_ANY");
		goto out;
	} else if (sk_ASN1_TYPE_num(sseq) != 1) {
		X509_WARNX(p, "%s: want one element, have %d",
			p->fn, sk_ASN1_TYPE_num(sseq));
		goto out;
	} 

	type1 = sk_ASN1_TYPE_value(sseq, 0);
	if (type1->type != V_ASN1_OTHER) {
		X509_WARNX(p, "%s: want ASN.1 other, "
			"have %s (NID %d)", p->fn, 
			ASN1_tag2str(type1->type), type1->type);
		goto out;
	}

	d = type1->value.asn1_string->data;
	dsz = type1->value.asn1_string->length;

	if (!ASN1_frame(p, dsz, &d, &plen, &ptag)) {
		X509_WARNX1(p, "ASN1_frame");
		goto out;
	} else if (p->res->aki != NULL)
		X509_LOG(p, "%s: reallocating", p->fn);


	/* Make room for [hex1, hex2, ":"]*, NUL. */

	free(p->res->aki);
	if ((p->res->aki = calloc(plen * 3 + 1, 1)) == NULL)
		err(EXIT_FAILURE, NULL);

	for (i = 0; i < plen; i++) {
		snprintf(buf, sizeof(buf), "%0.2X:", d[i]);
		strlcat(p->res->aki, buf, plen * 3 + 1);
	}
	p->res->aki[plen * 3 - 1] = '\0';

	X509_LOG(p, "%s: parsed authority key "
		"identifier: %s", p->fn, p->res->aki);
	rc = 1;
out:
	sk_ASN1_TYPE_free(seq);
	sk_ASN1_TYPE_free(sseq);
	free(sv);
	return rc;
}

/*
 * Parse X509v3 subject key identifier, RFC 6487 sec. 4.8.2.
 * Returns zero on failure, non-zero on success.
 */
static int
sbgp_skey_ident(struct parse *p, X509_EXTENSION *ext)
{
	size_t			 dsz;
	const unsigned char 	*d;
	ASN1_SEQUENCE_ANY	*seq = NULL;
	const ASN1_TYPE		*type1, *type2;
	int			 rc = 0, ptag;
	unsigned char		*sv = NULL;
	char			 buf[4];
	long			 j, plen;

	if ((dsz = i2d_X509_EXTENSION(ext, &sv)) < 0) {
		X509_CRYPTOX(p, "%s: i2d_X509_EXTENSION", p->fn);
		goto out;
	} 

	d = sv;
	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		X509_WARNX1(p, "d2i_ASN1_SEQUENCE_ANY");
		goto out;
	} else if (sk_ASN1_TYPE_num(seq) != 2) {
		X509_WARNX(p, "%s: want 2 elements, have %d",
			p->fn, sk_ASN1_TYPE_num(seq));
		goto out;
	}

	/* Consists of an OID (ignored) and octets. */

	type1 = sk_ASN1_TYPE_value(seq, 0);
	type2 = sk_ASN1_TYPE_value(seq, 1);

	if (type1->type != V_ASN1_OBJECT) {
		X509_WARNX(p, "%s: want ASN.1 object, "
			"have %s (NID %d)", p->fn, 
			ASN1_tag2str(type1->type), type1->type);
		goto out;
	} else if (type2->type != V_ASN1_OCTET_STRING) {
		X509_WARNX(p, "%s: want ASN.1 octet "
			"string, have %s (NID %d)", p->fn, 
			ASN1_tag2str(type2->type), type2->type);
		goto out;
	}

	/* 
	 * Parse the frame out of the ASN.1 octet string.
	 * The content is always a 20 B hash.
	 */

	d = type2->value.octet_string->data;
	dsz = type2->value.octet_string->length;

	if (!ASN1_frame(p, dsz, &d, &plen, &ptag)) {
		X509_WARNX1(p, "ASN1_frame");
		goto out;
	} else if (plen != 20) {
		X509_WARNX(p, "%s: expected 20 B "
			"hash, have %ld B", p->fn, plen);
		goto out;
	} else if (p->res->ski != NULL) 
		X509_LOG(p, "%s: reallocating key ident", p->fn);

	assert(V_ASN1_OCTET_STRING == ptag);

	/* Make room for [hex1, hex2, ":"]*, NUL. */

	free(p->res->ski);
	if ((p->res->ski = calloc(plen * 3 + 1, 1)) == NULL)
		err(EXIT_FAILURE, NULL);

	for (j = 0; j < plen; j++) {
		snprintf(buf, sizeof(buf), "%0.2X:", d[j]);
		strlcat(p->res->ski, buf, dsz * 3 + 1);
	}
	p->res->ski[plen * 3 - 1] = '\0';

	X509_LOG(p, "%s: parsed subject key "
		"identifier: %s", p->fn, p->res->ski);
	rc = 1;
out:
	sk_ASN1_TYPE_free(seq);
	free(sv);
	return rc;
}

/*
 * Parse either the CA repository or manifest, 4.8.8.1.
 * FIXME: 4.8.8.2?
 * Returns zero on failure, non-zero on success.
 */
static int
sbgp_sia_bits_repo(struct parse *p, const unsigned char *d, size_t dsz)
{
	ASN1_SEQUENCE_ANY	*seq;
	const ASN1_TYPE		*type1, *type2;
	int			 rc = 0, ptag;
	char		  	 buf[128];
	const char		*cp;
	long			 plen;

	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		X509_WARNX1(p, "d2i_ASN1_SEQUENCE_ANY");
		goto out;
	} else if (sk_ASN1_TYPE_num(seq) != 2) {
		X509_WARNX(p, "%s: want 2 elements, have %d",
			p->fn, sk_ASN1_TYPE_num(seq));
		goto out;
	}

	type1 = sk_ASN1_TYPE_value(seq, 0);
	type2 = sk_ASN1_TYPE_value(seq, 1);

	/* Composed of an OID and its continuation. */

	if (type1->type != V_ASN1_OBJECT) {
		X509_WARNX(p, "%s: want ASN.1 object, "
			"have %s (NID %d)", p->fn, 
			ASN1_tag2str(type1->type), type1->type);
		goto out;
	} else if (type2->type != V_ASN1_OTHER) {
		X509_WARNX(p, "%s: want ASN.1 other, "
			"have %s (NID %d)", p->fn, 
			ASN1_tag2str(type2->type), type2->type);
		goto out;
	}

	OBJ_obj2txt(buf, sizeof(buf), type1->value.object, 1);

	if (strcmp(buf, "1.3.6.1.5.5.7.48.10") &&
	    strcmp(buf, "1.3.6.1.5.5.7.48.5")) {
		X509_LOG(p, "%s: ignoring OID %s", p->fn, buf);
		rc = 1;
		goto out;
	}

	/* This is re-framed, so dig using low-level ASN1_frame. */

	d = type2->value.asn1_string->data;
	dsz = type2->value.asn1_string->length;
	if (!ASN1_frame(p, dsz, &d, &plen, &ptag)) {
		X509_WARNX1(p, "ASN1_frame");
		goto out;
	}

	if (strcmp(buf, "1.3.6.1.5.5.7.48.10") == 0) {
		free(p->res->mft);
		if ((cp = p->res->mft = strndup(d, plen)) == NULL)
			err(EXIT_FAILURE, NULL);
	} else {
		free(p->res->rep);
		if ((cp = p->res->rep = strndup(d, plen)) == NULL)
			err(EXIT_FAILURE, NULL);
	}

	X509_LOG(p, "%s: parsed %s: %s", p->fn, 
		strcmp(buf, "1.3.6.1.5.5.7.48.10") ? 
		"CA repository" : "manifest", cp);
	rc = 1;
out:
	sk_ASN1_TYPE_free(seq);
	return rc;
}

/*
 * Multiple locations as defined in RFC 6487, 4.8.8.1.
 * FIXME: 4.8.8.2?
 * Returns zero on failure, non-zero on success.
 */
static int
sbgp_sia_bits(struct parse *p, const unsigned char *d, size_t dsz)
{
	ASN1_SEQUENCE_ANY	*seq;
	const ASN1_TYPE		*type;
	int			 rc = 0, i;

	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		X509_WARNX1(p, "d2i_ASN1_SEQUENCE_ANY");
		goto out;
	} 

	for (i = 0; i < sk_ASN1_TYPE_num(seq); i++) {
		type = sk_ASN1_TYPE_value(seq, i);
		if (type->type != V_ASN1_SEQUENCE) {
			X509_WARNX(p, "%s: want ASN.1 sequence, "
				"have %s (NID %d)", p->fn,
				ASN1_tag2str(type->type), type->type);
			goto out;
		}

		d = type->value.asn1_string->data;
		dsz = type->value.asn1_string->length;
		if (!sbgp_sia_bits_repo(p, d, dsz)) {
			X509_WARNX1(p, "sbgp_sia_bits_repo");
			goto out;
		}
	}

	rc = 1;
out:
	sk_ASN1_TYPE_free(seq);
	return rc;
}

/*
 * Parse "Subject Information Access" extension, RFC 6487 4.8.8.
 * Returns zero on failure, non-zero on success.
 */
static int
sbgp_sia(struct parse *p, X509_EXTENSION *ext)
{
	unsigned char		*sv = NULL;
	const unsigned char 	*d;
	size_t		 	 dsz;
	ASN1_SEQUENCE_ANY	*seq = NULL;
	const ASN1_TYPE		*type1, *type2;
	int			 rc = 0;

	if ((dsz = i2d_X509_EXTENSION(ext, &sv)) < 0) {
		X509_CRYPTOX(p, "%s: i2d_X509_EXTENSION", p->fn);
		goto out;
	} 

	/* Parse through and ignore our OID/octet string pair. */

	d = sv;
	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		X509_WARNX1(p, "d2i_ASN1_SEQUENCE_ANY");
		goto out;
	} else if (sk_ASN1_TYPE_num(seq) != 2) {
		X509_WARNX(p, "%s: want 2 elements, have %d",
			p->fn, sk_ASN1_TYPE_num(seq));
		goto out;
	}

	type1 = sk_ASN1_TYPE_value(seq, 0);
	type2 = sk_ASN1_TYPE_value(seq, 1);

	if (type1->type != V_ASN1_OBJECT) {
		X509_WARNX(p, "%s: want ASN.1 object, "
			"have %s (NID %d)", p->fn, 
			ASN1_tag2str(type1->type), type1->type);
		goto out;
	} else if (type2->type != V_ASN1_OCTET_STRING) {
		X509_WARNX(p, "%s: want ASN.1 octet "
			"string, have %s (NID %d)", p->fn, 
			ASN1_tag2str(type2->type), type2->type);
		goto out;
	}

	/* Pass bits to underlying parser. */

	d = type2->value.octet_string->data;
	dsz = type2->value.octet_string->length;
	if (!sbgp_sia_bits(p, d, dsz)) {
		X509_WARNX1(p, "sbgp_sia_obj");
		goto out;
	}

	rc = 1;
out:
	sk_ASN1_TYPE_free(seq);
	free(sv);
	return rc;
}

/*
 * Parse a range of addresses as in 3.2.3.8.
 * Returns zero on failure, non-zero on success.
 */
static int
sbgp_asrange(struct parse *p, int rdi,
	const unsigned char *d, size_t dsz)
{
	struct cert_as	 	 as;
	ASN1_SEQUENCE_ANY	*seq;
	const ASN1_TYPE		*type1, *type2;
	int			 rc = 0;

	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		X509_WARNX1(p, "d2i_ASN1_SEQUENCE_ANY");
		goto out;
	} else if (sk_ASN1_TYPE_num(seq) != 2) {
		X509_WARNX(p, "%s: want two elements, have %d",
			p->fn, sk_ASN1_TYPE_num(seq));
		goto out;
	}

	/* We want two ASN.1 integer elements here. */

	type1 = sk_ASN1_TYPE_value(seq, 0);
	type2 = sk_ASN1_TYPE_value(seq, 1);

	if (type1->type != V_ASN1_INTEGER) {
		X509_WARNX(p, "%s: want ASN.1 integer, "
			"have %s (NID %d)", p->fn, 
			ASN1_tag2str(type1->type), type1->type);
		goto out;
	} else if (type2->type != V_ASN1_INTEGER) {
		X509_WARNX(p, "%s: want ASN.1 integer, "
			"have %s (NID %d)", p->fn, 
			ASN1_tag2str(type2->type), type2->type);
		goto out;
	}

	memset(&as, 0, sizeof(struct cert_as));
	as.type = CERT_AS_RANGE;
	as.rdi = rdi;

	/* The minimum component. */

	as.range.min = ASN1_INTEGER_get(type1->value.integer);
	X509_LOG(p, "%s: parsed AS range min: "
		"%" PRIu32, p->fn, as.range.min);

	/* Now the maximum. */

	as.range.max = ASN1_INTEGER_get(type2->value.integer);
	X509_LOG(p, "%s: parsed AS range max: "
		"%" PRIu32, p->fn, as.range.max);

	append_as(p, &as);
	rc = 1;
out:
	sk_ASN1_TYPE_free(seq);
	return rc;
}

/*
 * Parse an entire 3.2.3.10 integer type.
 */
static void
sbgp_asid(struct parse *p, int rdi, const ASN1_INTEGER *i)
{
	struct cert_as	 as;

	memset(&as, 0, sizeof(struct cert_as));

	as.rdi = rdi;
	as.type = CERT_AS_ID;
	as.id = ASN1_INTEGER_get(i);
	X509_LOG(p, "%s: parsed AS "
		"identifier: %" PRIu32, p->fn, as.id);
	append_as(p, &as);
}

/*
 * Parse one of RFC 3779 3.2.3.2.
 * Returns zero on failure, non-zero on success.
 */
static int
sbgp_asnum(struct parse *p, int rdi, 
	const unsigned char *d, size_t dsz)
{
	struct cert_as	 	 as;
	ASN1_TYPE		*type = NULL;
	ASN1_SEQUENCE_ANY	*seq = NULL;
	int			 i, rc = 0;
	const unsigned char	*sv = d;

	/* We can either be a null (inherit) or sequence. */

	if ((type = d2i_ASN1_TYPE(NULL, &d, dsz)) == NULL) {
		X509_WARNX1(p, "d2i_ASN1_TYPE");
		return 0;
	}

	/* 
	 * Section 3779 3.2.3.3 is to inherit with an ASN.1 NULL type,
	 * which is the easy case.
	 */

	if (type->type == V_ASN1_NULL) {
		memset(&as, 0, sizeof(struct cert_as));
		as.rdi = rdi;
		as.type = CERT_AS_NULL;
		X509_LOG(p, "%s: parsed inherited AS", p->fn);
		append_as(p, &as);
		rc = 1;
		goto out;
	} else if (type->type != V_ASN1_SEQUENCE) {
		X509_WARNX(p, "%s: want ASN.1 null or sequence, "
			"have %s (NID %d)", p->fn, 
			ASN1_tag2str(type->type), type->type);
		goto out;
	}

	/* This is RFC 3779 3.2.3.4. */

	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &sv, dsz)) == NULL) {
		X509_WARNX1(p, "d2i_ASN1_SEQUENCE_ANY");
		goto out;
	}

	/* Accepts RFC 3779 3.2.3.6 or 3.2.3.7 (sequence). */

	for (i = 0; i < sk_ASN1_TYPE_num(seq); i++) {
		type = sk_ASN1_TYPE_value(seq, i);
		if (type->type == V_ASN1_INTEGER) {
			sbgp_asid(p, rdi, type->value.integer);
		} else if (type->type == V_ASN1_SEQUENCE) {
			d = type->value.asn1_string->data;
			dsz = type->value.asn1_string->length;
			if (!sbgp_asrange(p, rdi, d, dsz)) {
				X509_WARNX1(p, "sbgp_asrange");
				goto out;
			}
		} else {
			X509_WARNX(p, "%s: want ASN.1 integer or "
				"sequence, have %s (NID %d)", p->fn, 
				ASN1_tag2str(type->type), type->type);
			goto out;
		}
	}

	rc = 1;
out:
	ASN1_TYPE_free(type);
	sk_ASN1_TYPE_free(seq);
	return rc;
}

/*
 * Parse RFC 6487 4.8.11 X509v3 extension, with syntax documented in RFC
 * 3779 starting in section 3.2.
 * Returns zero on failure, non-zero on success.
 */
static int
sbgp_assysnum(struct parse *p, X509_EXTENSION *ext)
{
	size_t	 	 	 dsz;
	unsigned char		*sv = NULL;
	const unsigned char 	*d;
	ASN1_SEQUENCE_ANY	*seq = NULL, *sseq = NULL;
	const ASN1_TYPE		*type = NULL;
	int			 rc = 0, i, ptag;
	long		 	 plen;

	if ((dsz = i2d_X509_EXTENSION(ext, &sv)) < 0) {
		X509_CRYPTOX(p, "%s: i2d_X509_EXTENSION", p->fn);
		goto out;
	} 

	/* Start with RFC 3770, section 3.2 top-level. */

	d = sv;
	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		X509_WARNX1(p, "d2i_ASN1_SEQUENCE_ANY");
		goto out;
	}

	/* Skip RFC 3779 3.2.1 and 3.2.2 til we reach 3.2.3. */

	for (i = 0; i < sk_ASN1_TYPE_num(seq); i++) {
		type = sk_ASN1_TYPE_value(seq, i);
		if (type->type == V_ASN1_OCTET_STRING)
			break;
		X509_LOG(p, "%s: ignoring %s (NID %d)", 
			p->fn, ASN1_tag2str(type->type), 
			type->type);
	}

	if (i == sk_ASN1_TYPE_num(seq)) {
		X509_WARNX(p, "%s: missing ASN.1 octet string", p->fn);
		goto out;
	}
	assert(type != NULL);

	/* Within RFC 3779 3.2.3, check 3.2.3.1. */

	d = type->value.octet_string->data;
	dsz = type->value.octet_string->length;

	if ((sseq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		X509_WARNX1(p, "d2i_ASN1_SEQUENCE_ANY");
		goto out;
	}

	/* Scan through for private 3.2.3.2 classes. */

	for (i = 0; i < sk_ASN1_TYPE_num(sseq); i++) {
		type = sk_ASN1_TYPE_value(sseq, i);
		if (type->type != V_ASN1_OTHER)
			continue;

		/* Use the low-level ASN1_frame. */

		d = type->value.asn1_string->data;
		dsz = type->value.asn1_string->length;

		if (!ASN1_frame(p, dsz, &d, &plen, &ptag)) {
			X509_WARNX1(p, "ASN1_frame");
			goto out;
		} else if (ptag > 0x01) {
			X509_WARNX(p, "%s: unknown ASnum tag "
				"0x%0.2X", p->fn, ptag);
			goto out;
		} else if (!sbgp_asnum(p, ptag, d, plen)) {
			X509_WARNX1(p, "sbgp_asnum");
			goto out;
		}
	}

	rc = 1;
out:
	sk_ASN1_TYPE_free(seq);
	sk_ASN1_TYPE_free(sseq);
	free(sv);
	return rc;
}

/*
 * Parse RFC 3779 2.2.3.9 range of addresses.
 * Return zero on failure, non-zero on success.
 */
static int
sbgp_range(struct parse *p, struct cert_ip *ip, 
	const unsigned char *d, size_t dsz)
{
	struct cert_ip_rng  	*rng = &ip->range;
	ASN1_SEQUENCE_ANY	*seq;
	const ASN1_TYPE		*type;
	int			 rc = 0;

	/* Sequence of two elements. */

	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		X509_WARNX1(p, "d2i_ASN1_SEQUENCE_ANY");
		goto out;
	} else if (sk_ASN1_TYPE_num(seq) != 2) {
		X509_WARNX(p, "%s: want two elements, have %d", 
			p->fn, sk_ASN1_TYPE_num(seq));
		goto out;
	}

	/* 
	 * Both elements are bit strings.
	 * Minimum element is 0x00-filled, max is 0xff-filled.
	 */

	type = sk_ASN1_TYPE_value(seq, 0);
	if (type->type != V_ASN1_BIT_STRING) {
		X509_WARNX(p, "%s: want ASN.1 bit string, "
			"have %s (NID %d)", p->fn,
			ASN1_tag2str(type->type), type->type);
		goto out;
	} 
	if (!sbgp_ipaddr(p, ip, &rng->min, type->value.bit_string)) {
		X509_WARNX1(p, "sbgp_ipaddr");
		return 0;
	}

	type = sk_ASN1_TYPE_value(seq, 1);
	if (type->type != V_ASN1_BIT_STRING) {
		X509_WARNX(p, "%s: want ASN.1 bit string, "
			"have %s (NID %d)", p->fn,
			ASN1_tag2str(type->type), type->type);
		goto out;
	} 
	if (!sbgp_ipaddr(p, ip, &rng->max, type->value.bit_string)) {
		X509_WARNX1(p, "sbgp_ipaddr");
		return 0;
	} 

	append_ip(p, ip);
	X509_LOG(p, "%s: parsed IPv%s address (range)", 
		p->fn, (ip->afi == 1) ? "4" : "6");
	rc = 1;
out:
	sk_ASN1_TYPE_free(seq);
	return rc;
}

/*
 * Parse an IP address or range, RFC 3779 2.2.3.7.
 * Puts results into "res".
 * Returns zero on failure, non-zero on success.
 */
static int
sbgp_addr_or_range(struct parse *p, struct cert_ip *ip, 
	const unsigned char *d, size_t dsz)
{
	struct cert_ip	 	 nip;
	ASN1_SEQUENCE_ANY	*seq;
	const ASN1_TYPE		*type;
	int			 i, rc;

	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		X509_WARNX1(p, "d2i_ASN1_SEQUENCE_ANY");
		return 0;
	}

	for (i = 0; i < sk_ASN1_TYPE_num(seq); i++) {
		nip = *ip;
		type = sk_ASN1_TYPE_value(seq, i);

		/* Either RFC 3779 2.2.3.8 or 2.2.3.9. */

		if (type->type == V_ASN1_BIT_STRING) {
			nip.type = CERT_IP_ADDR;
			if (!sbgp_addr(p, &nip, type->value.bit_string)) {
				X509_WARNX1(p, "sbgp_addr");
				break;
			}
		} else if (type->type == V_ASN1_SEQUENCE) {
			nip.type = CERT_IP_RANGE;
			d = type->value.asn1_string->data;
			dsz = type->value.asn1_string->length;
			if (!sbgp_range(p, &nip, d, dsz)) {
				X509_WARNX1(p, "sbgp_range");
				break;
			}
		} else {
			X509_WARNX(p, "%s: want ASN.1 bit string "
				"or sequence, have %s (NID %d)",
				p->fn, ASN1_tag2str(type->type),
				type->type);
			break;
		}
	}

	rc = (i == sk_ASN1_TYPE_num(seq));
	sk_ASN1_TYPE_free(seq);
	return rc;
}

/*
 * Parse a sequence of address families as in RFC 3779 sec. 2.2.3.2.
 * Returns zero no failure, non-zero on success.
 */
static int
sbgp_ipaddrfam(struct parse *p, const unsigned char *d, size_t dsz)
{
	struct cert_ip	 	 ip;
	ASN1_SEQUENCE_ANY	*seq;
	const ASN1_TYPE		*t;
	int			 rc = 0;

	memset(&ip, 0, sizeof(struct cert_ip));

	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		cryptowarnx("%s: RFC 3779 section 2.2.3.2: "
			"IPAddressFamily: failed ASN.1 sequence "
			"parse", p->fn);
		goto out;
	} else if (sk_ASN1_TYPE_num(seq) != 2) {
		warnx("%s: RFC 3779 section 2.2.3.2: "
			"IPAddressFamily: want 2 elements, have %d",
			p->fn, sk_ASN1_TYPE_num(seq));
		goto out;
	}

	/* Get address family, RFC 3779, 2.2.3.3. */

	t = sk_ASN1_TYPE_value(seq, 0);
	if (t->type != V_ASN1_OCTET_STRING) {
		warnx("%s: RFC 3779 section 2.2.3.2: addressFamily: "
			"want ASN.1 octet string, have %s (NID %d)", 
			p->fn, ASN1_tag2str(t->type), t->type);
		goto out;
	} 

	ip.has_safi = 0;
	if (!ip_addrfamily(t->value.octet_string, &ip.afi)) {
		warnx("%s: bad address family", p->fn);
		goto out;
	}

	/* Next, either sequence or null, RFC 3770 sec. 2.2.3.4. */

	t = sk_ASN1_TYPE_value(seq, 1);
	switch (t->type) {
	case V_ASN1_SEQUENCE:
		d = t->value.asn1_string->data;
		dsz = t->value.asn1_string->length;
		if (!sbgp_addr_or_range(p, &ip, d, dsz))
			goto out;
		break;
	case V_ASN1_NULL:
		ip.type = CERT_IP_INHERIT;
		append_ip(p, &ip);
		break;
	default:
		warnx("%s: RFC 3779 section 2.2.3.2: IPAddressChoice: "
			"want ASN.1 sequence or null, have %s (NID %d)", 
			p->fn, ASN1_tag2str(t->type), t->type);
		goto out;
	}

	rc = 1;
out:
	sk_ASN1_TYPE_free(seq);
	return rc;
}

/*
 * Parse an sbgp-ipAddrBlock X509 extension, RFC 6487 4.8.10, with
 * syntax documented in RFC 3779 starting in section 2.2.
 * Returns zero on failure, non-zero on success.
 */
static int
sbgp_ipaddrblk(struct parse *p, X509_EXTENSION *ext)
{
	int	 	 	 dsz, rc = 0;
	unsigned char		*sv = NULL;
	const unsigned char 	*d;
	ASN1_SEQUENCE_ANY	*seq = NULL, *sseq = NULL;
	const ASN1_TYPE		*t = NULL;
	int			 i;

	if ((dsz = i2d_X509_EXTENSION(ext, &sv)) < 0) {
		cryptowarnx("%s: RFC 6487 section 4.8.10: sbgp-"
			"ipAddrBlock: failed extension parse", p->fn);
		goto out;
	} 

	d = sv;
	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		cryptowarnx("%s: RFC 6487 section 4.8.10: sbgp-"
			"ipAddrBlock: failed ASN.1 sequence "
			"parse", p->fn);
		goto out;
	} else if (sk_ASN1_TYPE_num(seq) != 3) {
		warnx("%s: RFC 6487 section 4.8.10: sbgp-"
			"ipAddrBlock: want 3 elements, have %d",
			p->fn, sk_ASN1_TYPE_num(seq));
		goto out;
	}

	t = sk_ASN1_TYPE_value(seq, 0);
	if (t->type != V_ASN1_OBJECT) {
		warnx("%s: RFC 6486 section 4.2.1: sbgp-ipAddrBlock: "
			"want ASN.1 object, have %s (NID %d)", 
			p->fn, ASN1_tag2str(t->type), t->type);
		goto out;
	}

	t = sk_ASN1_TYPE_value(seq, 1);
	if (t->type != V_ASN1_BOOLEAN) {
		warnx("%s: RFC 6486 section 4.2.1: sbgp-ipAddrBlock: "
			"want ASN.1 boolean, have %s (NID %d)", 
			p->fn, ASN1_tag2str(t->type), t->type);
		goto out;
	}

	t = sk_ASN1_TYPE_value(seq, 2);
	if (t->type != V_ASN1_OCTET_STRING) {
		warnx("%s: RFC 6486 section 4.2.1: sbgp-ipAddrBlock: "
			"want ASN.1 octet string, have %s (NID %d)", 
			p->fn, ASN1_tag2str(t->type), t->type);
		goto out;
	}

	/* The blocks sequence, RFC 3779 2.2.3.1. */

	d = t->value.octet_string->data;
	dsz = t->value.octet_string->length;

	if ((sseq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		cryptowarnx("%s: RFC 3779 section 2.2.3.1: IPAddrBlocks: "
			"failed ASN.1 sequence parse", p->fn);
		goto out;
	} 

	/* Each sequence element contains RFC 3779 sec. 2.2.3.2. */

	for (i = 0; i < sk_ASN1_TYPE_num(sseq); i++) {
		t = sk_ASN1_TYPE_value(sseq, i);
		if (V_ASN1_SEQUENCE != t->type) {
			warnx("%s: RFC 3779 section 2.2.3.2: "
				"IPAddressFamily: want ASN.1 sequence, "
				"have %s (NID %d)", p->fn, 
				ASN1_tag2str(t->type), t->type);
			goto out;
		}
		d = t->value.asn1_string->data;
		dsz = t->value.asn1_string->length;
		if (!sbgp_ipaddrfam(p, d, dsz))
			goto out;
	}

	rc = 1;
out:
	sk_ASN1_TYPE_free(seq);
	sk_ASN1_TYPE_free(sseq);
	free(sv);
	return rc;
}

/*
 * Parse and optionally validate a signed X509 certificate.
 * Then parse the X509v3 extensions as defined in RFC 6487.
 * Returns the parse results or NULL on failure.
 * On success, free the pointer with cert_free().
 */
struct cert *
cert_parse(int verbose, X509 *cacert,
	const char *fn, const unsigned char *dgst)
{
	int	 	 rc = 0, extsz, c, sz;
	size_t		 i;
	X509		*x = NULL;
	X509_EXTENSION	*ext = NULL;
	ASN1_OBJECT	*obj;
	struct parse	 p;
	char		 objn[128];
	BIO		*bio = NULL, *shamd;
	EVP_MD		*md;
	unsigned char	 mdbuf[EVP_MAX_MD_SIZE];

	memset(&p, 0, sizeof(struct parse));
	p.fn = fn;
	p.verbose = verbose;
	if ((p.res = calloc(1, sizeof(struct cert))) == NULL)
		err(EXIT_FAILURE, NULL);
	if ((bio = BIO_new_file(fn, "rb")) == NULL)
		cryptoerrx("%s: BIO_new_file", p.fn);

	/*
	 * If we have a digest specified, create an MD chain that will
	 * automatically compute a digest during the X509 creation.
	 */

	if (dgst != NULL) {
		if ((shamd = BIO_new(BIO_f_md())) == NULL)
			cryptoerrx("BIO_new");
		if (!BIO_set_md(shamd, EVP_sha256()))
			cryptoerrx("BIO_set_md");
		if ((bio = BIO_push(shamd, bio)) == NULL)
			cryptoerrx("BIO_push");
	}

	if ((x = d2i_X509_bio(bio, NULL)) == NULL) {
		cryptowarnx("%s: d2i_X509_bio", p.fn);
		goto out;
	}
	
	/*
	 * If we have a digest, find it in the chain (we'll already have
	 * made it, so assert otherwise) and verify it.
	 */

	if (dgst != NULL) {
		shamd = BIO_find_type(bio, BIO_TYPE_MD);
		assert(shamd != NULL);

		if (!BIO_get_md(shamd, &md))
			cryptoerrx("BIO_get_md");
		assert(EVP_MD_type(md) == NID_sha256);

		if ((sz = BIO_gets(shamd, mdbuf, EVP_MAX_MD_SIZE)) < 0)
			cryptoerrx("BIO_gets");
		assert(sz == SHA256_DIGEST_LENGTH);

		if (memcmp(mdbuf, dgst, SHA256_DIGEST_LENGTH)) {
			warnx("%s: bad message digest", p.fn);
			goto out;
		}
	}
	
	/* 
	 * Conditionally validate.
	 * FIXME: there's more to do here.
	 */

	if (NULL != cacert &&
	    !X509_verify(x, X509_get_pubkey(cacert))) {
		cryptowarnx("%s: X509_verify", p.fn);
		goto out;
	}

	/* Look for X509v3 extensions. */

	if ((extsz = X509_get_ext_count(x)) < 0)
		cryptoerrx("X509_get_ext_count");

	for (i = 0; i < (size_t)extsz; i++) {
		ext = X509_get_ext(x, i);
		assert(ext != NULL);
		obj = X509_EXTENSION_get_object(ext);
		assert(obj != NULL);

		switch (OBJ_obj2nid(obj)) {
		case NID_sbgp_ipAddrBlock:
			c = sbgp_ipaddrblk(&p, ext);
			break;
		case NID_sbgp_autonomousSysNum:
			c = sbgp_assysnum(&p, ext);
			break;
		case NID_sinfo_access:
			c = sbgp_sia(&p, ext);
			break;
		case NID_subject_key_identifier:
			c = sbgp_skey_ident(&p, ext);
			break;
		case NID_authority_key_identifier:
			c = sbgp_akey_ident(&p, ext);
			break;
		default:
			c = 1;
			OBJ_obj2txt(objn, sizeof(objn), obj, 0);
			X509_LOG(&p, "%s: ignoring %s (NID %d)", 
				p.fn, objn, OBJ_obj2nid(obj));
			break;
		}
		if (c == 0)
			goto out;
	}

	rc = 1;
out:
	BIO_free_all(bio);
	X509_free(x);
	if (rc == 0)
		cert_free(p.res);
	return (rc == 0) ? NULL : p.res;
}

void
cert_free(struct cert *p)
{

	if (NULL == p)
		return;

	free(p->rep);
	free(p->mft);
	free(p->ski);
	free(p->aki);
	free(p->ips);
	free(p->as);
	free(p);
}

static void
cert_ip_addr_buffer(char **b, size_t *bsz,
	size_t *bmax, const struct cert_ip_addr *p)
{

	simple_buffer(b, bsz, bmax, &p->sz, sizeof(size_t));
	assert(p->sz <= 16);
	simple_buffer(b, bsz, bmax, p->addr, p->sz);
	simple_buffer(b, bsz, bmax, &p->unused, sizeof(long));
}

static void
cert_ip_buffer(char **b, size_t *bsz,
	size_t *bmax, const struct cert_ip *p)
{

	simple_buffer(b, bsz, bmax, &p->afi, sizeof(uint16_t));
	simple_buffer(b, bsz, bmax, &p->safi, sizeof(uint8_t));
	simple_buffer(b, bsz, bmax, &p->has_safi, sizeof(int));
	cert_ip_addr_buffer(b, bsz, bmax, &p->range.min);
	cert_ip_addr_buffer(b, bsz, bmax, &p->range.max);
}

static void
cert_as_buffer(char **b, size_t *bsz,
	size_t *bmax, const struct cert_as *p)
{

	simple_buffer(b, bsz, bmax, &p->rdi, sizeof(int));
	simple_buffer(b, bsz, bmax, &p->type, sizeof(enum cert_as_type));
	if (p->type == CERT_AS_RANGE) {
		simple_buffer(b, bsz, bmax, &p->range.min, sizeof(uint32_t));
		simple_buffer(b, bsz, bmax, &p->range.max, sizeof(uint32_t));
	} else if (p->type == CERT_AS_ID)
		simple_buffer(b, bsz, bmax, &p->id, sizeof(uint32_t));
}

/*
 * Write certificate parsed content.
 * See cert_read() for the other side of the pipe.
 */
void
cert_buffer(char **b, size_t *bsz, size_t *bmax, const struct cert *p)
{
	size_t	 i;

	simple_buffer(b, bsz, bmax, &p->ipsz, sizeof(size_t));
	for (i = 0; i < p->ipsz; i++)
		cert_ip_buffer(b, bsz, bmax, &p->ips[i]);

	simple_buffer(b, bsz, bmax, &p->asz, sizeof(size_t));
	for (i = 0; i < p->asz; i++)
		cert_as_buffer(b, bsz, bmax, &p->as[i]);

	str_buffer(b, bsz, bmax, p->rep);
	str_buffer(b, bsz, bmax, p->mft);
	str_buffer(b, bsz, bmax, p->ski);
	str_buffer(b, bsz, bmax, p->aki);
}

static void
cert_ip_addr_read(int fd, struct cert_ip_addr *p)
{

	simple_read(fd, &p->sz, sizeof(size_t));
	assert(p->sz <= 16);
	simple_read(fd, p->addr, p->sz);
	simple_read(fd, &p->unused, sizeof(long));
}

static void
cert_ip_read(int fd, struct cert_ip *p)
{

	simple_read(fd, &p->afi, sizeof(uint16_t));
	simple_read(fd, &p->safi, sizeof(uint8_t));
	simple_read(fd, &p->has_safi, sizeof(int));
	cert_ip_addr_read(fd, &p->range.min);
	cert_ip_addr_read(fd, &p->range.max);
}

static void
cert_as_read(int fd, struct cert_as *p)
{

	simple_read(fd, &p->rdi, sizeof(int));
	simple_read(fd, &p->type, sizeof(enum cert_as_type));
	if (p->type == CERT_AS_RANGE) {
		simple_read(fd, &p->range.min, sizeof(uint32_t));
		simple_read(fd, &p->range.max, sizeof(uint32_t));
	} else if (p->type == CERT_AS_ID)
		simple_read(fd, &p->id, sizeof(uint32_t));
}

/*
 * Read parsed certificate content.
 * The pointer must be freed with cert_free().
 */
struct cert *
cert_read(int fd)
{
	struct cert	*p;
	size_t		 i;

	if ((p = calloc(1, sizeof(struct cert))) == NULL)
		err(EXIT_FAILURE, NULL);

	simple_read(fd, &p->ipsz, sizeof(size_t));
	p->ips = calloc(p->ipsz, sizeof(struct cert_ip));
	if (p->ips == NULL)
		err(EXIT_FAILURE, NULL);
	for (i = 0; i < p->ipsz; i++)
		cert_ip_read(fd, &p->ips[i]);

	simple_read(fd, &p->asz, sizeof(size_t));
	p->as = calloc(p->asz, sizeof(struct cert_as));
	if (p->as == NULL)
		err(EXIT_FAILURE, NULL);
	for (i = 0; i < p->asz; i++)
		cert_as_read(fd, &p->as[i]);

	str_read(fd, &p->rep);
	str_read(fd, &p->mft);
	str_read(fd, &p->ski);
	str_read(fd, &p->aki);
	return p;
}

