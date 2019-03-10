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
};

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
		cryptowarnx("%s: ASN1_get_object", p->fn);
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
 * Parse an IP address, IPv4 or IPv6.
 * Confirms to RFC 3779 2.2.3.8.
 * Return zero on failure, non-zero on success.
 */
static int
sbgp_ipaddr(struct parse *p, const struct cert_ip *ip,
	struct ip_addr *addr, const ASN1_BIT_STRING *bs)
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
		warnx("%s: IPv%s address too long: %zu", 
			p->fn, 1 == ip->afi ? "4" : "6", dsz);
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

	if (!sbgp_ipaddr(p, ip, &rng->min, bs) ||
	    !sbgp_ipaddr(p, ip, &rng->max, bs))
		return 0;

	append_ip(p, ip);
	return 1;
}

/*
 * Parse either the CA repository or manifest, 4.8.8.1.
 * Returns zero on failure, non-zero on success.
 */
static int
sbgp_sia_bits_repo(struct parse *p, const unsigned char *d, size_t dsz)
{
	const ASN1_SEQUENCE_ANY	*seq;
	const ASN1_TYPE		*t;
	int			 rc = 0, ptag;
	char		  	 buf[128];
	const char		*cp;
	long			 plen;

	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		cryptowarnx("%s: RFC 6487 section 4.8.8: SIA: "
			"failed ASN.1 sequence parse", p->fn);
		goto out;
	} else if (sk_ASN1_TYPE_num(seq) != 2) {
		warnx("%s: RFC 6487 section 4.8.8: SIA: "
			"want 2 elements, have %d",
			p->fn, sk_ASN1_TYPE_num(seq));
		goto out;
	}

	/* Composed of an OID and its continuation. */

	t = sk_ASN1_TYPE_value(seq, 0);
	if (t->type != V_ASN1_OBJECT) {
		warnx("%s: RFC 6487 section 4.8.8: SIA: "
			"want ASN.1 object, have %s (NID %d)", 
			p->fn, ASN1_tag2str(t->type), t->type);
		goto out;
	}
	OBJ_obj2txt(buf, sizeof(buf), t->value.object, 1);

	/* Ignore rpkiNotify access descriptor. */

	if (strcmp(buf, "1.3.6.1.5.5.7.48.13") == 0) {
		rc = 1;
		goto out;
	}

	/* Accept manifest and CA repository. */

	if (strcmp(buf, "1.3.6.1.5.5.7.48.10") &&
	    strcmp(buf, "1.3.6.1.5.5.7.48.5")) {
		warnx("%s: RFC 6487 section 4.8.8: SIA: "
			"unknown OID: %s", p->fn, buf);
		goto out;
	}

	t = sk_ASN1_TYPE_value(seq, 1);
	if (t->type != V_ASN1_OTHER) {
		warnx("%s: RFC 6487 section 4.8.8: SIA: "
			"want ASN.1 external, have %s (NID %d)", 
			p->fn, ASN1_tag2str(t->type), t->type);
		goto out;
	}

	/* This is re-framed, so dig using low-level ASN1_frame. */

	d = t->value.asn1_string->data;
	dsz = t->value.asn1_string->length;
	if (!ASN1_frame(p, dsz, &d, &plen, &ptag))
		goto out;

	if (strcmp(buf, "1.3.6.1.5.5.7.48.10") == 0) {
		free(p->res->mft);
		if ((cp = p->res->mft = strndup(d, plen)) == NULL)
			err(EXIT_FAILURE, NULL);
	} else {
		free(p->res->rep);
		if ((cp = p->res->rep = strndup(d, plen)) == NULL)
			err(EXIT_FAILURE, NULL);
	}

	rc = 1;
out:
	sk_ASN1_TYPE_free(seq);
	return rc;
}

/*
 * Multiple locations as defined in RFC 6487, 4.8.8.1.
 * Returns zero on failure, non-zero on success.
 */
static int
sbgp_sia_bits(struct parse *p, const unsigned char *d, size_t dsz)
{
	const ASN1_SEQUENCE_ANY	*seq;
	const ASN1_TYPE		*t;
	int			 rc = 0, i;

	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		cryptowarnx("%s: RFC 6487 section 4.8.8: SIA: "
			"failed ASN.1 sequence parse", p->fn);
		goto out;
	} 

	for (i = 0; i < sk_ASN1_TYPE_num(seq); i++) {
		t = sk_ASN1_TYPE_value(seq, i);
		if (t->type != V_ASN1_SEQUENCE) {
			warnx("%s: RFC 6487 section 4.8.8: SIA: "
				"want ASN.1 sequence, have %s (NID %d)", 
				p->fn, ASN1_tag2str(t->type), t->type);
			goto out;
		}
		d = t->value.asn1_string->data;
		dsz = t->value.asn1_string->length;
		if (!sbgp_sia_bits_repo(p, d, dsz))
			goto out;
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
	const ASN1_TYPE		*t;
	int			 rc = 0;

	if ((dsz = i2d_X509_EXTENSION(ext, &sv)) < 0) {
		cryptowarnx("%s: RFC 6487 section 4.8.8: SIA: "
			"failed extension parse", p->fn);
		goto out;
	} 
	d = sv;

	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		cryptowarnx("%s: RFC 6487 section 4.8.8: SIA: "
			"failed ASN.1 sequence parse", p->fn);
		goto out;
	} else if (sk_ASN1_TYPE_num(seq) != 2) {
		warnx("%s: RFC 6487 section 4.8.8: SIA: "
			"want 2 elements, have %d", p->fn, 
			sk_ASN1_TYPE_num(seq));
		goto out;
	}

	t = sk_ASN1_TYPE_value(seq, 0);
	if (t->type != V_ASN1_OBJECT) {
		warnx("%s: RFC 6487 section 4.8.8: SIA: "
			"want ASN.1 object, have %s (NID %d)", 
			p->fn, ASN1_tag2str(t->type), t->type);
		goto out;
	} else if (OBJ_obj2nid(t->value.object) != NID_sinfo_access) {
		warnx("%s: RFC 6487 section 4.8.8: SIA: "
			"incorrect OID, have %s (NID %d)", p->fn, 
			ASN1_tag2str(OBJ_obj2nid(t->value.object)), 
			OBJ_obj2nid(t->value.object));
		goto out;
	}

	t = sk_ASN1_TYPE_value(seq, 1);
	if (t->type != V_ASN1_OCTET_STRING) {
		warnx("%s: RFC 6487 section 4.8.8: SIA: "
			"want ASN.1 octet string, have %s (NID %d)", 
			p->fn, ASN1_tag2str(t->type), t->type);
		goto out;
	}

	d = t->value.octet_string->data;
	dsz = t->value.octet_string->length;
	if (!sbgp_sia_bits(p, d, dsz))
		goto out;

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
	const ASN1_TYPE		*t;
	int			 rc = 0;

	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		cryptowarnx("%s: RFC 3779 section 3.2.3.8: "
			"ASRange: failed ASN.1 sequence parse", p->fn);
		goto out;
	} else if (sk_ASN1_TYPE_num(seq) != 2) {
		warnx("%s: RFC 3779 section 3.2.3.8: ASRange: "
			"want 2 elements, have %d", p->fn,
			sk_ASN1_TYPE_num(seq));
		goto out;
	}

	memset(&as, 0, sizeof(struct cert_as));
	as.type = CERT_AS_RANGE;
	as.rdi = rdi;

	t = sk_ASN1_TYPE_value(seq, 0);
	if (t->type != V_ASN1_INTEGER) {
		warnx("%s: RFC 3779 section 3.2.3.8: ASRange: "
			"want ASN.1 integer, have %s (NID %d)", 
			p->fn, ASN1_tag2str(t->type), t->type);
		goto out;
	} 
	as.range.min = ASN1_INTEGER_get(t->value.integer);
	
	t = sk_ASN1_TYPE_value(seq, 1);
	if (t->type != V_ASN1_INTEGER) {
		warnx("%s: RFC 3779 section 3.2.3.8: ASRange: "
			"want ASN.1 integer, have %s (NID %d)", 
			p->fn, ASN1_tag2str(t->type), t->type);
		goto out;
	}
	as.range.max = ASN1_INTEGER_get(t->value.integer);

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
	ASN1_TYPE		*t;
	ASN1_SEQUENCE_ANY	*seq = NULL;
	int			 i, rc = 0;
	const unsigned char	*sv = d;

	/* We can either be a null (inherit) or sequence. */

	if ((t = d2i_ASN1_TYPE(NULL, &d, dsz)) == NULL) {
		cryptowarnx("%s: RFC 3779 section 3.2.3.2: "
			"ASIdentifierChoice: failed ASN.1 "
			"type parse", p->fn);
		goto out;
	}

	/* 
	 * Section 3779 3.2.3.3 is to inherit with an ASN.1 NULL type,
	 * which is the easy case.
	 */

	switch (t->type) {
	case V_ASN1_NULL:
		memset(&as, 0, sizeof(struct cert_as));
		as.rdi = rdi;
		as.type = CERT_AS_NULL;
		append_as(p, &as);
		rc = 1;
		goto out;
	case V_ASN1_SEQUENCE:
		break;
	default:
		warnx("%s: RFC 3779 section 3.2.3.2: "
			"ASIdentifierChoice: want ASN.1 sequence "
			"or null, have %s (NID %d)", 
			p->fn, ASN1_tag2str(t->type), t->type);
		goto out;
	}

	/* This is RFC 3779 3.2.3.4. */

	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &sv, dsz)) == NULL) {
		cryptowarnx("%s: RFC 3779 section 3.2.3.2: "
			"ASIdentifierChoice: failed ASN.1 sequence "
			"parse", p->fn);
		goto out;
	}

	/* Accepts RFC 3779 3.2.3.6 or 3.2.3.7 (sequence). */

	for (i = 0; i < sk_ASN1_TYPE_num(seq); i++) {
		t = sk_ASN1_TYPE_value(seq, i);
		switch (t->type) {
		case V_ASN1_INTEGER:
			sbgp_asid(p, rdi, t->value.integer);
			break;
		case V_ASN1_SEQUENCE:
			d = t->value.asn1_string->data;
			dsz = t->value.asn1_string->length;
			if (!sbgp_asrange(p, rdi, d, dsz))
				goto out;
			break;
		default:
			warnx("%s: RFC 3779 section 3.2.3.4: "
				"IPAddressOrRange: want ASN.1 sequence "
				"or integer, have %s (NID %d)", 
				p->fn, ASN1_tag2str(t->type), t->type);
			goto out;
		}
	}

	rc = 1;
out:
	ASN1_TYPE_free(t);
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
	const ASN1_TYPE		*t;
	int			 rc = 0, i, ptag;
	long		 	 plen;

	if ((dsz = i2d_X509_EXTENSION(ext, &sv)) < 0) {
		cryptowarnx("%s: RFC 6487 section 4.8.11: autonomous"
			"SysNum: failed extension parse", p->fn);
		goto out;
	} 

	/* Start with RFC 3770, section 3.2 top-level. */

	d = sv;
	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		cryptowarnx("%s: RFC 6487 section 4.8.11: autonomous"
			"SysNum: failed ASN.1 sequence parse", p->fn);
		goto out;
	} else if (sk_ASN1_TYPE_num(seq) != 3) {
		warnx("%s: RFC 6487 section 4.8.11: autonomousSysNum: "
			"want 3 elements, have %d", p->fn,
			sk_ASN1_TYPE_num(seq));
		goto out;
	}

	t = sk_ASN1_TYPE_value(seq, 0);
	if (t->type != V_ASN1_OBJECT) {
		warnx("%s: RFC 6487 section 4.8.11: autonomomusSysNum: "
			"want ASN.1 object, have %s (NID %d)", 
			p->fn, ASN1_tag2str(t->type), t->type);
		goto out;
	}

	/* FIXME: verify OID. */

	t = sk_ASN1_TYPE_value(seq, 1);
	if (t->type != V_ASN1_BOOLEAN) {
		warnx("%s: RFC 6487 section 4.8.11: autonomomusSysNum: "
			"want ASN.1 boolean, have %s (NID %d)", 
			p->fn, ASN1_tag2str(t->type), t->type);
		goto out;
	}

	t = sk_ASN1_TYPE_value(seq, 2);
	if (t->type != V_ASN1_OCTET_STRING) {
		warnx("%s: RFC 6487 section 4.8.11: autonomomusSysNum: "
			"want ASN.1 octet string, have %s (NID %d)", 
			p->fn, ASN1_tag2str(t->type), t->type);
		goto out;
	}

	/* Within RFC 3779 3.2.3, check 3.2.3.1. */

	d = t->value.octet_string->data;
	dsz = t->value.octet_string->length;

	if ((sseq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		cryptowarnx("%s: RFC 3779 section 3.2.3.1: ASIdentifiers: "
			"failed ASN.1 sequence parse", p->fn);
		goto out;
	}

	/* Scan through for private 3.2.3.2 classes. */

	for (i = 0; i < sk_ASN1_TYPE_num(sseq); i++) {
		t = sk_ASN1_TYPE_value(sseq, i);
		if (t->type != V_ASN1_OTHER) {
			warnx("%s: RFC 3779 section 3.2.3.1: "
				"ASIdentifiers: want ASN.1 explicit, "
				"have %s (NID %d)", p->fn, 
				ASN1_tag2str(t->type), t->type);
			goto out;
		}

		/* Use the low-level ASN1_frame. */

		d = t->value.asn1_string->data;
		dsz = t->value.asn1_string->length;
		if (!ASN1_frame(p, dsz, &d, &plen, &ptag))
			goto out;

		if (ptag > 0x01) {
			warnx("%s: RFC 3779 section 3.2.3.1: "
				"ASIdentifiers: unknown explicit "
				"tag 0x%0.2x", p->fn, ptag);
			goto out;
		} else if (!sbgp_asnum(p, ptag, d, plen))
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
 * Parse RFC 3779 2.2.3.9 range of addresses.
 * Return zero on failure, non-zero on success.
 */
static int
sbgp_range(struct parse *p, struct cert_ip *ip, 
	const unsigned char *d, size_t dsz)
{
	struct cert_ip_rng  	*rng = &ip->range;
	ASN1_SEQUENCE_ANY	*seq;
	const ASN1_TYPE		*t;
	int			 rc = 0;

	/* Sequence of two elements. */

	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		cryptowarnx("%s: RFC 3779 section 2.2.3.9: "
			"IPAddressRange: failed ASN.1 sequence "
			"parse", p->fn);
		goto out;
	} else if (sk_ASN1_TYPE_num(seq) != 2) {
		warnx("%s: RFC 3779 section 2.2.3.9: "
			"IPAddressRange: want 2 elements, have %d",
			p->fn, sk_ASN1_TYPE_num(seq));
		goto out;
	}

	/* Both elements are bit strings. */

	t = sk_ASN1_TYPE_value(seq, 0);
	if (t->type != V_ASN1_BIT_STRING) {
		warnx("%s: RFC 3779 section 2.2.3.9: IPAddress: "
			"want ASN.1 bit string, have %s (NID %d)", 
			p->fn, ASN1_tag2str(t->type), t->type);
		goto out;
	} else if (!sbgp_ipaddr(p, ip, &rng->min, t->value.bit_string))
		goto out;

	t = sk_ASN1_TYPE_value(seq, 1);
	if (t->type != V_ASN1_BIT_STRING) {
		warnx("%s: RFC 3779 section 2.2.3.9: IPAddress: "
			"want ASN.1 bit string, have %s (NID %d)", 
			p->fn, ASN1_tag2str(t->type), t->type);
		goto out;
	} else if (!sbgp_ipaddr(p, ip, &rng->max, t->value.bit_string))
		goto out;

	append_ip(p, ip);
	rc = 1;
out:
	sk_ASN1_TYPE_free(seq);
	return rc;
}

/*
 * Parse an IP address or range, RFC 3779 2.2.3.7.
 * Returns zero on failure, non-zero on success.
 */
static int
sbgp_addr_or_range(struct parse *p, struct cert_ip *ip, 
	const unsigned char *d, size_t dsz)
{
	struct cert_ip	 	 nip;
	ASN1_SEQUENCE_ANY	*seq;
	const ASN1_TYPE		*t;
	int			 i, rc = 0;

	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		cryptowarnx("%s: RFC 3779 section 2.2.3.7: "
			"IPAddressOrRange: failed ASN.1 sequence "
			"parse", p->fn);
		goto out;
	}

	/* Either RFC 3779 2.2.3.8 or 2.2.3.9. */

	for (i = 0; i < sk_ASN1_TYPE_num(seq); i++) {
		nip = *ip;
		t = sk_ASN1_TYPE_value(seq, i);
		switch (t->type) {
		case V_ASN1_BIT_STRING:
			nip.type = CERT_IP_ADDR;
			if (!sbgp_addr(p, &nip, t->value.bit_string))
				goto out;
			break;
		case V_ASN1_SEQUENCE:
			nip.type = CERT_IP_RANGE;
			d = t->value.asn1_string->data;
			dsz = t->value.asn1_string->length;
			if (!sbgp_range(p, &nip, d, dsz))
				goto out;
			break;
		default:
			warnx("%s: RFC 3779 section 2.2.3.7: "
				"IPAddressOrRange: want ASN.1 sequence "
				"or bit string, have %s (NID %d)", 
				p->fn, ASN1_tag2str(t->type), t->type);
			goto out;
		}
	}

	rc = 1;
out:
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
	if (!ip_addr_afi_parse(t->value.octet_string, &ip.afi)) {
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
		warnx("%s: RFC 6487 section 4.8.10: sbgp-ipAddrBlock: "
			"want ASN.1 object, have %s (NID %d)", 
			p->fn, ASN1_tag2str(t->type), t->type);
		goto out;
	}

	/* FIXME: verify OID. */

	t = sk_ASN1_TYPE_value(seq, 1);
	if (t->type != V_ASN1_BOOLEAN) {
		warnx("%s: RFC 6487 section 4.8.10: sbgp-ipAddrBlock: "
			"want ASN.1 boolean, have %s (NID %d)", 
			p->fn, ASN1_tag2str(t->type), t->type);
		goto out;
	}

	t = sk_ASN1_TYPE_value(seq, 2);
	if (t->type != V_ASN1_OCTET_STRING) {
		warnx("%s: RFC 6487 section 4.8.10: sbgp-ipAddrBlock: "
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
cert_parse(X509 **xp, const char *fn, const unsigned char *dgst)
{
	int	 	 rc = 0, extsz, c, sz;
	size_t		 i;
	X509		*x = NULL;
	X509_EXTENSION	*ext = NULL;
	ASN1_OBJECT	*obj;
	struct parse	 p;
	BIO		*bio = NULL, *shamd;
	EVP_MD		*md;
	unsigned char	 mdbuf[EVP_MAX_MD_SIZE];

	*xp = NULL;
	memset(&p, 0, sizeof(struct parse));
	p.fn = fn;
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

	if ((x = *xp = d2i_X509_bio(bio, NULL)) == NULL) {
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

	/* RFC 6487, section 4.1. */

	if (X509_get_version(x) != 2) {
		warnx("%s: RFC 6487 section 4.1: bad certificate "
			"version: %ld ", p.fn, X509_get_version(x));
		goto out;
	}

	/* RFC 6487, section 4.6.1, 4.6.2. */

	if (X509_get_notBefore(x) == NULL || X509_get_notAfter(x) == NULL) {
		warnx("%s: RFC 6487 section 4.6.1, 4.6.2: "
			"lacks time validity constraints", p.fn);
		goto out;
	}
	if (X509_cmp_current_time(X509_get_notBefore(x)) > 0 ||
	    X509_cmp_current_time(X509_get_notAfter(x)) < 0) {
		warnx("%s: RFC 6487 section 4.6.1, 4.6.2: "
			"time validity constraint violation", p.fn);
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
		default:
			c = 1;
			/*
			OBJ_obj2txt(objn, sizeof(objn), obj, 0);
			warnx("%s: ignoring %s (NID %d)", 
				p.fn, objn, OBJ_obj2nid(obj));
			*/
			break;
		}
		if (c == 0)
			goto out;
	}

	rc = 1;
out:
	BIO_free_all(bio);
	if (rc == 0) {
		cert_free(p.res);
		X509_free(x);
		*xp = NULL;
	}
	return (rc == 0) ? NULL : p.res;
}

void
cert_free(struct cert *p)
{

	if (NULL == p)
		return;

	free(p->rep);
	free(p->mft);
	free(p->ips);
	free(p->as);
	free(p);
}

static void
cert_ip_buffer(char **b, size_t *bsz,
	size_t *bmax, const struct cert_ip *p)
{

	simple_buffer(b, bsz, bmax, &p->afi, sizeof(uint16_t));
	simple_buffer(b, bsz, bmax, &p->safi, sizeof(uint8_t));
	simple_buffer(b, bsz, bmax, &p->has_safi, sizeof(int));
	ip_addr_buffer(b, bsz, bmax, &p->range.min);
	ip_addr_buffer(b, bsz, bmax, &p->range.max);
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
}

static void
cert_ip_read(int fd, struct cert_ip *p)
{

	simple_read(fd, &p->afi, sizeof(uint16_t));
	simple_read(fd, &p->safi, sizeof(uint8_t));
	simple_read(fd, &p->has_safi, sizeof(int));
	ip_addr_read(fd, &p->range.min);
	ip_addr_read(fd, &p->range.max);
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
	return p;
}

