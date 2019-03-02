#include <sys/socket.h>

#include <arpa/inet.h>
#include <assert.h>
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
 * Return zero on failure or the length of the full frame otherwise.
 */
static int
ASN1_frame(struct parse *p, size_t sz,
	const unsigned char **cnt, long *cntsz, int *tag)
{
	int	 ret, pcls;

	assert(NULL != cnt && NULL != *cnt);
	assert(sz > 0);
	ret = ASN1_get_object(cnt, cntsz, tag, &pcls, sz);
	if (0x80 & ret) {
		X509_CRYPTOX(p, "%s: ASN1_get_object", p->fn);
		return 0;
	} 
	return ASN1_object_size((ret & 0x01) ? 2 : 0, *cntsz, *tag);
}

/*
 * Append an IP address structure to our list of results.
 * Returns zero on failure (memory allocation), non-zero on success.
 */
static int
append_ip(struct parse *p, const struct x509_ip *ip)
{
	void		*pp;
	struct cert	*res = p->res;

	pp = reallocarray(res->ips, 
		res->ipsz + 1, sizeof(struct x509_ip));
	if (NULL == pp) {
		WARN("reallocarray");
		return 0;
	}
	res->ips = pp;
	res->ips[res->ipsz++] = *ip;
	return 1;
}

/*
 * Append an AS identifier structure to our list of results.
 * Returns zero on failure (memory allocation), non-zero on success.
 */
static int
append_as(struct parse *p, const struct x509_as *as)
{
	void		*pp;
	struct cert	*res = p->res;

	pp = reallocarray(res->as, 
		res->asz + 1, sizeof(struct x509_as));
	if (NULL == pp) {
		WARN("reallocarray");
		return 0;
	}
	res->as = pp;
	res->as[res->asz++] = *as;
	return 1;
}

/*
 * Parse an IP address, IPv4 or IPv6, as either a minimum or maximum
 * quantity depending upon whether "mask" is 0x00 or 0xFF.
 * Confirms to RFC 3779 2.2.3.8.
 * Return zero on failure, non-zero on success.
 */
static int
sbgp_ipaddr(struct parse *p, unsigned char mask, 
	const struct x509_ip *ip, struct x509_ip_addr *addr, 
	const ASN1_BIT_STRING *bs)
{
	long			 unused = 0;
	const unsigned char	*d;
	size_t			 dsz;

	d = bs->data;
	dsz = bs->length;

	/* Weird OpenSSL-ism to get unused bit count. */

	if (ASN1_STRING_FLAG_BITS_LEFT & bs->flags)
		unused = ~ASN1_STRING_FLAG_BITS_LEFT & bs->flags;

	if ((1 == ip->afi && dsz > 4) ||
	    (2 == ip->afi && dsz > 16)) {
		X509_WARNX(p, "%s: IPv%s too large", 
			p->fn, 1 == ip->afi ? "4" : "6");
		return 0;
	} 

	/* FIXME: process unused bit. */

	addr->unused = unused;
	addr->sz = (1 == ip->afi) ? 4 : 16;
	memset(addr->addr, mask, addr->sz);
	memcpy(addr->addr, d, dsz);
	return 1;
}

/*
 * Construct a RFC 3779 2.2.3.8 range by its bit string.
 * Return zero on failure, non-zero on success.
 */
static int
sbgp_addr(struct parse *p, 
	struct x509_ip *ip, const ASN1_BIT_STRING *bs)
{
	struct x509_ip_rng *rng = &ip->range;

	if ( ! sbgp_ipaddr(p, 0x00, ip, &rng->min, bs)) {
		X509_WARNX1(p, "sbgp_ipaddr");
		return 0;
	} else if ( ! sbgp_ipaddr(p, 0xFF, ip, &rng->max, bs)) {
		X509_WARNX1(p, "sbgp_ipaddr");
		return 0;
	} else if ( ! append_ip(p, ip)) {
		X509_WARNX1(p, "append_ip");
		return 0;
	}

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
	seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz);
	if (NULL == seq) {
		X509_WARNX1(p, "d2i_ASN1_SEQUENCE_ANY");
		goto out;
	} else if (2 != sk_ASN1_TYPE_num(seq)) {
		X509_WARNX(p, "%s: want 2 elements, have %d",
			p->fn, sk_ASN1_TYPE_num(seq));
		goto out;
	}

	type1 = sk_ASN1_TYPE_value(seq, 0);
	type2 = sk_ASN1_TYPE_value(seq, 1);

	if (V_ASN1_OBJECT != type1->type) {
		X509_WARNX(p, "%s: want ASN.1 object, "
			"have %s (NID %d)", p->fn, 
			ASN1_tag2str(type1->type), type1->type);
		goto out;
	} else if (V_ASN1_OCTET_STRING != type2->type) {
		X509_WARNX(p, "%s: want ASN.1 octet "
			"string, have %s (NID %d)", p->fn, 
			ASN1_tag2str(type2->type), type2->type);
		goto out;
	}

	/* Data is really a sub-sequence...? */

	d = type2->value.octet_string->data;
	dsz = type2->value.octet_string->length;

	sseq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz);
	if (NULL == sseq) {
		X509_WARNX1(p, "d2i_ASN1_SEQUENCE_ANY");
		goto out;
	} else if (1 != sk_ASN1_TYPE_num(sseq)) {
		X509_WARNX(p, "%s: want one element, have %d",
			p->fn, sk_ASN1_TYPE_num(sseq));
		goto out;
	} 

	type1 = sk_ASN1_TYPE_value(sseq, 0);
	if (V_ASN1_OTHER != type1->type) {
		X509_WARNX(p, "%s: want ASN.1 other, "
			"have %s (NID %d)", p->fn, 
			ASN1_tag2str(type1->type), type1->type);
		goto out;
	}

	d = type1->value.asn1_string->data;
	dsz = type1->value.asn1_string->length;

	if (0 == ASN1_frame(p, dsz, &d, &plen, &ptag)) {
		X509_WARNX1(p, "ASN1_frame");
		goto out;
	} else if (NULL != p->res->aki)
		X509_LOG(p, "%s: reallocating", p->fn);

	free(p->res->aki);

	/* Make room for [hex1, hex2, ":"]*, NUL. */

	if (NULL == (p->res->aki = calloc(plen * 3 + 1, 1))) {
		WARN("calloc");
		goto out;
	}
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
	seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz);
	if (NULL == seq) {
		X509_WARNX1(p, "d2i_ASN1_SEQUENCE_ANY");
		goto out;
	} else if (2 != sk_ASN1_TYPE_num(seq)) {
		X509_WARNX(p, "%s: want 2 elements, have %d",
			p->fn, sk_ASN1_TYPE_num(seq));
		goto out;
	}

	/* Consists of an OID (ignored) and octets. */

	type1 = sk_ASN1_TYPE_value(seq, 0);
	type2 = sk_ASN1_TYPE_value(seq, 1);

	if (V_ASN1_OBJECT != type1->type) {
		X509_WARNX(p, "%s: want ASN.1 object, "
			"have %s (NID %d)", p->fn, 
			ASN1_tag2str(type1->type), type1->type);
		goto out;
	} else if (V_ASN1_OCTET_STRING != type2->type) {
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

	if (0 == ASN1_frame(p, dsz, &d, &plen, &ptag)) {
		X509_WARNX1(p, "ASN1_frame");
		goto out;
	} else if (20 != plen) {
		X509_WARNX(p, "%s: expected 20 B "
			"hash, have %ld B", p->fn, plen);
		goto out;
	} else if (NULL != p->res->ski) 
		X509_LOG(p, "%s: reallocating key ident", p->fn);

	assert(V_ASN1_OCTET_STRING == ptag);
	free(p->res->ski);

	/* Make room for [hex1, hex2, ":"]*, NUL. */

	if (NULL == (p->res->ski = calloc(plen * 3 + 1, 1))) {
		WARN("calloc");
		return 0;
	}
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

	seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz);
	if (NULL == seq) {
		X509_WARNX1(p, "d2i_ASN1_SEQUENCE_ANY");
		goto out;
	} else if (2 != sk_ASN1_TYPE_num(seq)) {
		X509_WARNX(p, "%s: want 2 elements, have %d",
			p->fn, sk_ASN1_TYPE_num(seq));
		goto out;
	}

	type1 = sk_ASN1_TYPE_value(seq, 0);
	type2 = sk_ASN1_TYPE_value(seq, 1);

	/* Composed of an OID and its continuation. */

	if (V_ASN1_OBJECT != type1->type) {
		X509_WARNX(p, "%s: want ASN.1 object, "
			"have %s (NID %d)", p->fn, 
			ASN1_tag2str(type1->type), type1->type);
		goto out;
	} else if (V_ASN1_OTHER != type2->type) {
		X509_WARNX(p, "%s: want ASN.1 other, "
			"have %s (NID %d)", p->fn, 
			ASN1_tag2str(type2->type), type2->type);
		goto out;
	}

	OBJ_obj2txt(buf, sizeof(buf), 
		type1->value.object, 1);
	if (strcmp(buf, "1.3.6.1.5.5.7.48.10") &&
	    strcmp(buf, "1.3.6.1.5.5.7.48.5")) {
		X509_LOG(p, "%s: ignoring OID %s", p->fn, buf);
		rc = 1;
		goto out;
	}

	/* This is re-framed, so dig using low-level ASN1_frame. */

	d = type2->value.asn1_string->data;
	dsz = type2->value.asn1_string->length;
	if (0 == ASN1_frame(p, dsz, &d, &plen, &ptag)) {
		X509_WARNX1(p, "ASN1_frame");
		goto out;
	}
	if (0 == strcmp(buf, "1.3.6.1.5.5.7.48.10")) {
		free(p->res->mft);
		cp = p->res->mft = strndup(d, plen);
	} else {
		free(p->res->rep);
		cp = p->res->rep = strndup(d, plen);
	}

	if (NULL == cp) {
		WARN("strndup");
		goto out;
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

	seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz);
	if (NULL == seq) {
		X509_WARNX1(p, "d2i_ASN1_SEQUENCE_ANY");
		goto out;
	} 

	for (i = 0; i < sk_ASN1_TYPE_num(seq); i++) {
		type = sk_ASN1_TYPE_value(seq, i);
		if (V_ASN1_SEQUENCE != type->type) {
			X509_WARNX(p, "%s: want ASN.1 sequence, "
				"have %s (NID %d)", p->fn,
				ASN1_tag2str(type->type), type->type);
			goto out;
		}

		d = type->value.asn1_string->data;
		dsz = type->value.asn1_string->length;
		if ( ! sbgp_sia_bits_repo(p, d, dsz)) {
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
	seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz);
	if (NULL == seq) {
		X509_WARNX1(p, "d2i_ASN1_SEQUENCE_ANY");
		goto out;
	} else if (2 != sk_ASN1_TYPE_num(seq)) {
		X509_WARNX(p, "%s: want 2 elements, have %d",
			p->fn, sk_ASN1_TYPE_num(seq));
		goto out;
	}

	type1 = sk_ASN1_TYPE_value(seq, 0);
	type2 = sk_ASN1_TYPE_value(seq, 1);

	if (V_ASN1_OBJECT != type1->type) {
		X509_WARNX(p, "%s: want ASN.1 object, "
			"have %s (NID %d)", p->fn, 
			ASN1_tag2str(type1->type), type1->type);
		goto out;
	} else if (V_ASN1_OCTET_STRING != type2->type) {
		X509_WARNX(p, "%s: want ASN.1 octet "
			"string, have %s (NID %d)", p->fn, 
			ASN1_tag2str(type2->type), type2->type);
		goto out;
	}

	/* Pass bits to underlying parser. */

	d = type2->value.octet_string->data;
	dsz = type2->value.octet_string->length;
	if ( ! sbgp_sia_bits(p, d, dsz)) {
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
	struct x509_as	 	 as;
	ASN1_SEQUENCE_ANY	*seq;
	const ASN1_TYPE		*type1, *type2;
	int			 rc = 0;

	seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz);
	if (NULL == seq) {
		X509_WARNX1(p, "d2i_ASN1_SEQUENCE_ANY");
		goto out;
	} else if (2 != sk_ASN1_TYPE_num(seq)) {
		X509_WARNX(p, "%s: want two elements, have %d",
			p->fn, sk_ASN1_TYPE_num(seq));
		goto out;
	}

	/* We want two ASN.1 integer elements here. */

	type1 = sk_ASN1_TYPE_value(seq, 0);
	type2 = sk_ASN1_TYPE_value(seq, 1);

	if (V_ASN1_INTEGER != type1->type) {
		X509_WARNX(p, "%s: want ASN.1 integer, "
			"have %s (NID %d)", p->fn, 
			ASN1_tag2str(type1->type), type1->type);
		goto out;
	} else if (V_ASN1_INTEGER != type2->type) {
		X509_WARNX(p, "%s: want ASN.1 integer, "
			"have %s (NID %d)", p->fn, 
			ASN1_tag2str(type2->type), type2->type);
		goto out;
	}

	memset(&as, 0, sizeof(struct x509_as));
	as.type = ASN1_AS_RANGE;
	as.rdi = rdi;

	/* The minimum component. */

	as.range.min = ASN1_INTEGER_get(type1->value.integer);
	X509_LOG(p, "%s: parsed AS range min: "
		"%" PRIu32, p->fn, as.range.min);

	/* Now the maximum. */

	as.range.max = ASN1_INTEGER_get(type2->value.integer);
	X509_LOG(p, "%s: parsed AS range max: "
		"%" PRIu32, p->fn, as.range.max);

	if ( ! append_as(p, &as)) {
		X509_WARNX1(p, "append_as");
		goto out;
	}

	rc = 1;
out:
	sk_ASN1_TYPE_free(seq);
	return rc;
}

/*
 * Parse an entire 3.2.3.10 integer type.
 * Return zero on failure, non-zero on success.
 */
static int
sbgp_asid(struct parse *p, int rdi, const ASN1_INTEGER *i)
{
	struct x509_as	 as;

	memset(&as, 0, sizeof(struct x509_as));

	as.rdi = rdi;
	as.type = ASN1_AS_ID;
	as.id = ASN1_INTEGER_get(i);
	X509_LOG(p, "%s: parsed AS "
		"identifier: %" PRIu32, p->fn, as.id);
	return append_as(p, &as);
}

/*
 * Parse one of RFC 3779 3.2.3.2.
 * Returns zero on failure, non-zero on success.
 */
static int
sbgp_asnum(struct parse *p, int rdi, 
	const unsigned char *d, size_t dsz)
{
	struct x509_as	 	 as;
	ASN1_TYPE		*type = NULL;
	ASN1_SEQUENCE_ANY	*seq = NULL;
	int			 i, rc = 0;
	const unsigned char	*sv = d;

	/* We can either be a null (inherit) or sequence. */

	if (NULL == (type = d2i_ASN1_TYPE(NULL, &d, dsz))) {
		X509_WARNX1(p, "d2i_ASN1_TYPE");
		return 0;
	}

	/* 
	 * Section 3779 3.2.3.3 is to inherit with an ASN.1 NULL type,
	 * which is the easy case.
	 */

	if (V_ASN1_NULL == type->type) {
		memset(&as, 0, sizeof(struct x509_as));
		as.rdi = rdi;
		as.type = ASN1_AS_NULL;
		X509_LOG(p, "%s: parsed inherited AS", p->fn);
		if ( ! append_as(p, &as)) {
			X509_WARNX1(p, "append_as");
			goto out;
		}
		rc = 1;
		goto out;
	} else if (V_ASN1_SEQUENCE != type->type) {
		X509_WARNX(p, "%s: want ASN.1 null or sequence, "
			"have %s (NID %d)", p->fn, 
			ASN1_tag2str(type->type), type->type);
		goto out;
	}

	/* This is RFC 3779 3.2.3.4. */

	seq = d2i_ASN1_SEQUENCE_ANY(NULL, &sv, dsz);
	if (NULL == seq) {
		X509_WARNX1(p, "d2i_ASN1_SEQUENCE_ANY");
		goto out;
	}

	/* Accepts RFC 3779 3.2.3.6 or 3.2.3.7 (sequence). */

	for (i = 0; i < sk_ASN1_TYPE_num(seq); i++) {
		type = sk_ASN1_TYPE_value(seq, i);
		if (V_ASN1_INTEGER == type->type) {
			if ( ! sbgp_asid(p, rdi, type->value.integer)) {
				X509_WARNX1(p, "sbgp_asid");
				goto out;
			}
		} else if (V_ASN1_SEQUENCE == type->type) {
			d = type->value.asn1_string->data;
			dsz = type->value.asn1_string->length;
			if ( ! sbgp_asrange(p, rdi, d, dsz)) {
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
	seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz);
	if (NULL == seq) {
		X509_WARNX1(p, "d2i_ASN1_SEQUENCE_ANY");
		goto out;
	}

	/* Skip RFC 3779 3.2.1 and 3.2.2 til we reach 3.2.3. */

	for (i = 0; i < sk_ASN1_TYPE_num(seq); i++) {
		type = sk_ASN1_TYPE_value(seq, i);
		if (V_ASN1_OCTET_STRING == type->type)
			break;
		X509_LOG(p, "%s: ignoring %s (NID %d)", 
			p->fn, ASN1_tag2str(type->type), 
			type->type);
	}

	if (i == sk_ASN1_TYPE_num(seq)) {
		X509_WARNX(p, "%s: missing ASN.1 octet string", p->fn);
		goto out;
	}
	assert(NULL != type);

	/* Within RFC 3779 3.2.3, check 3.2.3.1. */

	d = type->value.octet_string->data;
	dsz = type->value.octet_string->length;

	sseq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz);
	if (NULL == seq) {
		X509_WARNX1(p, "d2i_ASN1_SEQUENCE_ANY");
		goto out;
	}

	/* Scan through for private 3.2.3.2 classes. */

	for (i = 0; i < sk_ASN1_TYPE_num(sseq); i++) {
		type = sk_ASN1_TYPE_value(sseq, i);
		if (V_ASN1_OTHER != type->type) 
			continue;

		/* Use the low-level ASN1_frame. */

		d = type->value.asn1_string->data;
		dsz = type->value.asn1_string->length;

		if (0 == ASN1_frame(p, dsz, &d, &plen, &ptag)) {
			X509_WARNX1(p, "ASN1_frame");
			goto out;
		} else if (ptag > 0x01) {
			X509_WARNX(p, "%s: unknown ASnum tag "
				"0x%0.2X", p->fn, ptag);
			goto out;
		} else if ( ! sbgp_asnum(p, ptag, d, plen)) {
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
sbgp_range(struct parse *p, struct x509_ip *ip, 
	const unsigned char *d, size_t dsz)
{
	struct x509_ip_rng  	*rng = &ip->range;
	ASN1_SEQUENCE_ANY	*seq;
	const ASN1_TYPE		*type;
	int			 rc = 0;

	/* Sequence of two elements. */

	seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz);
	if (NULL == seq) {
		X509_WARNX1(p, "d2i_ASN1_SEQUENCE_ANY");
		goto out;
	} else if (2 != sk_ASN1_TYPE_num(seq)) {
		X509_WARNX(p, "%s: want two elements, have %d", 
			p->fn, sk_ASN1_TYPE_num(seq));
		goto out;
	}

	/* 
	 * Both elements are bit strings.
	 * Minimum element is 0x00-filled, max is 0xff-filled.
	 */

	type = sk_ASN1_TYPE_value(seq, 0);
	if (V_ASN1_BIT_STRING != type->type) {
		X509_WARNX(p, "%s: want ASN.1 bit string, "
			"have %s (NID %d)", p->fn,
			ASN1_tag2str(type->type), type->type);
		goto out;
	} 
	if ( ! sbgp_ipaddr(p, 0x00, ip, 
	    &rng->min, type->value.bit_string)) {
		X509_WARNX1(p, "sbgp_ipaddr");
		return 0;
	}

	type = sk_ASN1_TYPE_value(seq, 0);
	if (V_ASN1_BIT_STRING != type->type) {
		X509_WARNX(p, "%s: want ASN.1 bit string, "
			"have %s (NID %d)", p->fn,
			ASN1_tag2str(type->type), type->type);
		goto out;
	} 
	if ( ! sbgp_ipaddr(p, 0xFF, ip, 
	    &rng->max, type->value.bit_string)) {
		X509_WARNX1(p, "sbgp_ipaddr");
		return 0;
	} 

	/* Minimum and maximum parsed properly: append. */
	
	if ( ! append_ip(p, ip)) {
		X509_WARNX1(p, "append_ip");
		return 0;
	}

	X509_LOG(p, "%s: parsed IPv%s address (range)", 
		p->fn, 1 == ip->afi ? "4" : "6");
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
sbgp_addr_or_range(struct parse *p, struct x509_ip *ip, 
	const unsigned char *d, size_t dsz)
{
	struct x509_ip	 	 nip;
	ASN1_SEQUENCE_ANY	*seq;
	const ASN1_TYPE		*type;
	int			 i, rc;

	seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz);
	if (NULL == seq) {
		X509_WARNX1(p, "d2i_ASN1_SEQUENCE_ANY");
		return 0;
	}

	for (i = 0; i < sk_ASN1_TYPE_num(seq); i++) {
		nip = *ip;
		type = sk_ASN1_TYPE_value(seq, i);

		/* Either RFC 3779 2.2.3.8 or 2.2.3.9. */

		if (V_ASN1_BIT_STRING == type->type) {
			nip.type = ASN1_IP_ADDR;
			if ( ! sbgp_addr(p, &nip, 
			    type->value.bit_string)) {
				X509_WARNX1(p, "sbgp_addr");
				break;
			}
		} else if (V_ASN1_SEQUENCE == type->type) {
			nip.type = ASN1_IP_RANGE;
			d = type->value.asn1_string->data;
			dsz = type->value.asn1_string->length;
			if ( ! sbgp_range(p, &nip, d, dsz)) {
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

	rc = i == sk_ASN1_TYPE_num(seq);
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
	struct x509_ip	 	 ip;
	char		 	 buf[2];
	ASN1_SEQUENCE_ANY	*seq;
	const ASN1_TYPE		*type;
	int			 rc = 0;

	memset(&ip, 0, sizeof(struct x509_ip));

	seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz);
	if (NULL == seq) {
		X509_WARNX1(p, "d2i_ASN1_SEQUENCE_ANY");
		goto out;
	} else if (2 != sk_ASN1_TYPE_num(seq)) {
		X509_WARNX(p, "%s: want two sequence "
			"elements, have %d", 
			p->fn, sk_ASN1_TYPE_num(seq));
		goto out;
	}

	/* Get address family, RFC 3779, 2.2.3.3. */

	type = sk_ASN1_TYPE_value(seq, 0);
	if (V_ASN1_OCTET_STRING != type->type) {
		X509_WARNX(p, "%s: want ASN.1 octet "
			"string, have %s (NID %d)", p->fn, 
			ASN1_tag2str(type->type), type->type);
		goto out;
	} 

	d = type->value.octet_string->data;
	dsz = type->value.octet_string->length;

	if (0 == dsz || dsz > 3) {
		X509_WARNX(p, "%s: invalid IP address "
			"length, have %zu", p->fn, dsz);
		goto out;
	} 

	/* Parse AFI and (optionally) SAFI. */

	memcpy(buf, d, sizeof(uint16_t));
	ip.afi = ntohs(*(uint16_t *)buf);

	if (1 != ip.afi && 2 != ip.afi) {
		X509_WARNX(p, "%s: invalid AFI, "
			"have %u", p->fn, ip.afi);
		goto out;
	} else if (3 == dsz) {
		ip.safi = d[2];
		ip.has_safi = 1;
		X509_LOG(p, "%s: parsed IPv%s address family: "
			"SAFI %u", p->fn, 1 == ip.afi ? "4" : "6",
			ip.safi);
	} else
		X509_LOG(p, "%s: parsed IPv%s address family",
			p->fn, 1 == ip.afi ? "4" : "6");

	/* Next, either sequence or null, RFC 3770 sec. 2.2.3.4. */

	type = sk_ASN1_TYPE_value(seq, 1);
	if (V_ASN1_SEQUENCE == type->type) {
		d = type->value.asn1_string->data;
		dsz = type->value.asn1_string->length;

		if ( ! sbgp_addr_or_range(p, &ip, d, dsz)) {
			X509_WARNX1(p, "sbgp_addr_or_range");
			goto out;
		}
	} else if (V_ASN1_NULL == type->type) {
		ip.type = ASN1_IP_INHERIT;
		if ( ! append_ip(p, &ip)) {
			X509_WARNX1(p, "append_ip");
			goto out;
		}
		X509_LOG(p, "%s: parsed IPv%s address (inherit)", 
			p->fn, 1 == ip.afi ? "4" : "6");
	} else {
		X509_WARNX(p, "%s: want ASN.1 null or "
			"sequence, have %s (NID %d)", p->fn, 
			ASN1_tag2str(type->type), type->type);
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
	const ASN1_TYPE		*type = NULL;
	int			 i;

	if ((dsz = i2d_X509_EXTENSION(ext, &sv)) < 0) {
		X509_CRYPTOX(p, "%s: i2d_X509_EXTENSION", p->fn);
		goto out;
	} 
	d = sv;

	/* Top-level sequence. */

	if (NULL == (seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz))) {
		X509_WARNX1(p, "d2i_ASN1_SEQUENCE_ANY");
		goto out;
	} 

	/* Skip RFC 3779 2.2.1 and 2.2.2, stop at 2.2.3. */

	for (i = 0; i < sk_ASN1_TYPE_num(seq); i++) {
		type = sk_ASN1_TYPE_value(seq, i);
		if (V_ASN1_OCTET_STRING == type->type)
			break;
		X509_LOG(p, "%s: ignoring %s (NID %d)", p->fn, 
			ASN1_tag2str(type->type), type->type);
	}

	if (i == sk_ASN1_TYPE_num(seq)) {
		X509_WARNX(p, "%s: missing ASN.1 octet string", p->fn);
		goto out;
	}
	assert(NULL != type);

	/* The blocks sequence, RFC 3779 2.2.3.1. */

	d = type->value.octet_string->data;
	dsz = type->value.octet_string->length;

	sseq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz);
	if (NULL == sseq) {
		X509_WARNX1(p, "d2i_ASN1_SEQUENCE_ANY");
		goto out;
	} 

	/* Each sequence element contains RFC 3779 sec. 2.2.3.2. */

	for (i = 0; i < sk_ASN1_TYPE_num(sseq); i++) {
		type = sk_ASN1_TYPE_value(sseq, i);
		if (V_ASN1_SEQUENCE != type->type) {
			X509_WARNX(p, "%s: want ASN.1 "
				"sequence, have %s (NID %d)", p->fn,
				ASN1_tag2str(type->type), type->type);
			goto out;
		}

		d = type->value.asn1_string->data;
		dsz = type->value.asn1_string->length;

		if ( ! sbgp_ipaddrfam(p, d, dsz)) {
			X509_WARNX1(p, "sbgp_ipaddrfam");
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
	p.res = calloc(1, sizeof(struct cert));
	if (NULL == p.res) {
		WARN("calloc");
		goto out;
	}

	if (NULL == (bio = BIO_new_file(fn, "rb"))) {
		X509_CRYPTOX(&p, "%s: BIO_new_file", p.fn);
		goto out;
	}

	/*
	 * If we have a digest specified, create an MD chain that will
	 * automatically compute a digest during the X509 creation.
	 */

	if (dgst != NULL) {
		if ((shamd = BIO_new(BIO_f_md())) == NULL) {
			X509_CRYPTOX(&p, "%s: BIO_new", p.fn);
			goto out;
		} else if (!BIO_set_md(shamd, EVP_sha256())) {
			X509_CRYPTOX(&p, "%s: BIO_set_md", p.fn);
			goto out;
		}
		bio = BIO_push(shamd, bio);
	}

	if (NULL == (x = d2i_X509_bio(bio, NULL))) {
		X509_CRYPTOX(&p, "%s: d2i_X509_bio", p.fn);
		goto out;
	}
	
	/*
	 * If we have a digest, find it in the chain (we'll already have
	 * made it, so assert otherwise) and verify it.
	 */

	if (dgst != NULL) {
		shamd = BIO_find_type(bio, BIO_TYPE_MD);
		assert(shamd != NULL);
		if (!BIO_get_md(shamd, &md)) {
			X509_CRYPTOX(&p, "%s: BIO_get_md", p.fn);
			goto out;
		}
		assert(EVP_MD_type(md) == NID_sha256);
		sz = BIO_gets(shamd, mdbuf, EVP_MAX_MD_SIZE);
		if (sz < 0) {
			X509_CRYPTOX(&p, "%s: BIO_gets", p.fn);
			goto out;
		}
		assert(sz == SHA256_DIGEST_LENGTH);
		if (memcmp(mdbuf, dgst, SHA256_DIGEST_LENGTH)) {
			X509_WARNX(&p, "%s: bad digest", p.fn);
			goto out;
		}
	}
	
	/* 
	 * Conditionally validate.
	 * FIXME: there's more to do here.
	 */

	if (NULL != cacert) {
		if ( ! X509_verify(x, X509_get_pubkey(cacert))) {
			X509_CRYPTOX(&p, "%s: X509_verify", p.fn);
			goto out;
		}
		X509_LOG(&p, "%s: verified signature", p.fn);
	} else
		X509_LOG(&p, "%s: unverified signature", p.fn);

	/* Look for X509v3 extensions. */

	if ((extsz = X509_get_ext_count(x)) < 0) {
		X509_CRYPTOX(&p, "%s: X509_get_ext_count", p.fn);
		goto out;
	}

	for (i = 0; i < (size_t)extsz; i++) {
		ext = X509_get_ext(x, i);
		assert(NULL != ext);
		obj = X509_EXTENSION_get_object(ext);
		assert(NULL != obj);

		switch (OBJ_obj2nid(obj)) {
		case NID_sbgp_ipAddrBlock:
			if (0 == (c = sbgp_ipaddrblk(&p, ext)))
				X509_WARNX1(&p, "sbgp_ipaddrblk");
			break;
		case NID_sbgp_autonomousSysNum:
			if (0 == (c = sbgp_assysnum(&p, ext)))
				X509_WARNX1(&p, "sbgp_assysnum");
			break;
		case NID_sinfo_access:
			if (0 == (c = sbgp_sia(&p, ext)))
				X509_WARNX1(&p, "sbgp_sia");
			break;
		case NID_subject_key_identifier:
			if (0 == (c = sbgp_skey_ident(&p, ext)))
				X509_WARNX1(&p, "sbgp_skey_ident");
			break;
		case NID_authority_key_identifier:
			if (0 == (c = sbgp_akey_ident(&p, ext)))
				X509_WARNX1(&p, "sbgp_akey_ident");
			break;
		default:
			c = 1;
			OBJ_obj2txt(objn, sizeof(objn), obj, 0);
			X509_LOG(&p, "%s: ignoring %s (NID %d)", 
				p.fn, objn, OBJ_obj2nid(obj));
			break;
		}
		if (0 == c)
			goto out;
	}

	rc = 1;
out:
	BIO_free_all(bio);
	X509_free(x);
	if (0 == rc)
		cert_free(p.res);
	return 0 == rc ? NULL : p.res;
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

/*
 * Write certificate parsed content.
 * Returns zero on failure, non-zero on success.
 */
int
cert_buffer(char **b, size_t *bsz, size_t *bmax,
	int verb, const struct cert *x)
{

	if (!str_buffer(b, bsz, bmax, verb, x->rep))
		WARNX1(verb, "str_buffer");
	else if (!str_buffer(b, bsz, bmax, verb, x->mft))
		WARNX1(verb, "str_buffer");
	else
		return 1;

	return 0;
}

/*
 * Read parsed certificate content.
 * Returns a valid pointer or NULL on failure.
 * The pointer must be freed with cert_free().
 */
struct cert *
cert_read(int fd, int verb)
{
	struct cert	*p;

	if ((p = calloc(1, sizeof(struct cert))) == NULL)
		WARN("calloc");
	else if (!str_read(fd, verb, &p->rep))
		WARNX1(verb, "str_read");
	else if (!str_read(fd, verb, &p->mft))
		WARNX1(verb, "str_read");
	else
		return p;

	cert_free(p);
	return NULL;
}

