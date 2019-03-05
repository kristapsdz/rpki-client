#include <assert.h>
#include <err.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include "extern.h"

/*
 * Parse results and data of the manifest file.
 */
struct	parse {
	const char	 *fn; /* manifest file name */
	struct roa	 *res; /* results */
};

/*
 * Parse IP address (ROAIPAddress), RFC 6482, section 3.3.
 * Returns zero on failure, non-zero on success.
 */
static int
roa_parse_addr(const ASN1_OCTET_STRING *os,
	uint16_t afi, struct parse *p)
{
	const ASN1_SEQUENCE_ANY *seq;
	const unsigned char     *d = os->data;
	size_t		         dsz = os->length;
	int			 rc = 0;
	const ASN1_TYPE		*t;
	const ASN1_INTEGER	*maxlength = NULL;
	struct cert_ip_addr	 addr;
	struct roa_ip		*res;

	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		cryptowarnx("%s: RFC 6482 section 3.3: address: "
			"failed ASN.1 sequence parse", p->fn);
		goto out;
	}

	/* ROAIPAddress has the address and optional maxlength. */

	if (sk_ASN1_TYPE_num(seq) != 1 &&
	    sk_ASN1_TYPE_num(seq) != 2) {
		warnx("%s: RFC 6482 section 3.3: adddress: "
			"want 1 or 2 elements, have %d", 
			p->fn, sk_ASN1_TYPE_num(seq));
		goto out;
	}

	t = sk_ASN1_TYPE_value(seq, 0);
	if (t->type != V_ASN1_BIT_STRING) {
		warnx("%s: RFC 6482 section 3.3: address: "
			"want ASN.1 bit string, have %s (NID %d)", 
			p->fn, ASN1_tag2str(t->type), t->type);
		goto out;
	} else if (!ip_addr(t->value.bit_string, afi, &addr)) {
		warnx("%s: RFC 6482 section 3.3: "
			"address: invalid", p->fn);
		goto out;
	}

	/* 
	 * RFC 6482, section 3.3 doesn't ever actually state that the
	 * maximum length can't be negative, but it needs to be >=0.
	 */

	if (sk_ASN1_TYPE_num(seq) == 2) {
		t = sk_ASN1_TYPE_value(seq, 1);
		if (t->type != V_ASN1_INTEGER) {
			warnx("%s: RFC 6482 section 3.1: maxLength: "
				"want ASN.1 integer, have %s (NID %d)", 
				p->fn, ASN1_tag2str(t->type), t->type);
			goto out;
		}
		maxlength = t->value.integer;
		if (ASN1_INTEGER_get(maxlength) < 0) {
			warnx("%s: RFC 6482 section 3.2: maxLength: "
				"want positive integer, have %ld",
				p->fn, ASN1_INTEGER_get(maxlength));
			goto out;
		}
	}

	p->res->ips = reallocarray(p->res->ips,
		p->res->ipsz + 1, sizeof(struct roa_ip));
	if (p->res->ips == NULL)
		err(EXIT_FAILURE, NULL);
	res = &p->res->ips[p->res->ipsz++];
	memset(res, 0, sizeof(struct roa_ip));

	res->addr = addr;
	res->afi = afi;
	res->maxlength = (maxlength == NULL) ?
		0: ASN1_INTEGER_get(maxlength);

	rc = 1;
out:
	sk_ASN1_TYPE_free(seq);
	return rc;
}

/*
 * Parse IP address family, RFC 6482, section 3.3.
 * Returns zero on failure, non-zero on success.
 */
static int
roa_parse_ipfam(const ASN1_OCTET_STRING *os, struct parse *p)
{
	const ASN1_SEQUENCE_ANY *seq, *sseq = NULL;
	const unsigned char     *d = os->data;
	size_t		         dsz = os->length;
	int			 i, rc = 0;
	const ASN1_TYPE		*t;
	uint16_t		 afi;

	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		cryptowarnx("%s: RFC 6482 section 3.3: "
			"ROAIPAddressFamily: failed ASN.1 "
			"sequence parse", p->fn);
		goto out;
	} else if (sk_ASN1_TYPE_num(seq) != 2) {
		warnx("%s: RFC 6482 section 3.3: "
			"ROAIPAddressFamily: "
			"want 2 elements, have %d", 
			p->fn, sk_ASN1_TYPE_num(seq));
		goto out;
	}

	t = sk_ASN1_TYPE_value(seq, 0);
	if (t->type != V_ASN1_OCTET_STRING) {
		warnx("%s: RFC 6482 section 3.3: "
			"addressFamily: want ASN.1 "
			"octet string, have %s (NID %d)", 
			p->fn, ASN1_tag2str(t->type), t->type);
		goto out;
	} else if (!ip_addrfamily(t->value.octet_string, &afi)) {
		warnx("%s: RFC 6482 section 3.3: "
			"addressFamily: invalid", p->fn);
		goto out;
	}
	
	t = sk_ASN1_TYPE_value(seq, 1);
	if (t->type != V_ASN1_SEQUENCE) {
		warnx("%s: RFC 6482 section 3.3: addresses: "
			"want ASN.1 sequence, have %s (NID %d)", 
			p->fn, ASN1_tag2str(t->type), t->type);
		goto out;
	}

	d = t->value.octet_string->data;
	dsz = t->value.octet_string->length;

	if ((sseq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		cryptowarnx("%s: RFC 6482 section 3.3: addresses: "
			"failed ASN.1 sequence parse", p->fn);
		goto out;
	}

	for (i = 0; i < sk_ASN1_TYPE_num(sseq); i++) {
		t = sk_ASN1_TYPE_value(sseq, i);
		if (t->type != V_ASN1_SEQUENCE) {
			warnx("%s: RFC 6482 section 3.3: ROAIPAddress: "
				"want ASN.1 sequence, have %s (NID %d)", 
				p->fn, ASN1_tag2str(t->type), t->type);
			goto out;
		}
		if (!roa_parse_addr(t->value.octet_string, afi, p))
			goto out;
	}

	rc = 1;
out:
	sk_ASN1_TYPE_free(seq);
	sk_ASN1_TYPE_free(sseq);
	return rc;
}

/*
 * Parse IP blocks, RFC 6482, section 3.3.
 * Returns zero on failure, non-zero on success.
 */
static int
roa_parse_ipblocks(const ASN1_OCTET_STRING *os, struct parse *p)
{
	const ASN1_SEQUENCE_ANY *seq;
	const unsigned char     *d = os->data;
	size_t		         dsz = os->length;
	int			 i, rc = 0;
	const ASN1_TYPE		*t;

	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		cryptowarnx("%s: RFC 6482 section 3.3: ipAddrBlocks: "
			"failed ASN.1 sequence parse", p->fn);
		goto out;
	}

	for (i = 0; i < sk_ASN1_TYPE_num(seq); i++) {
		t = sk_ASN1_TYPE_value(seq, i);
		if (t->type != V_ASN1_SEQUENCE) {
			warnx("%s: RFC 6482 section 3.3: "
				"ROAIPAddressFamily: want ASN.1 "
				"sequence, have %s (NID %d)", 
				p->fn, ASN1_tag2str(t->type), t->type);
			goto out;
		} else if (!roa_parse_ipfam(t->value.octet_string, p))
			goto out;
	}

	rc = 1;
out:
	sk_ASN1_TYPE_free(seq);
	return rc;
}

/*
 * Parses the eContent section of an ROA file, RFC 6482, section 3.
 * Returns zero on failure, non-zero on success.
 */
static int
roa_parse_econtent(const ASN1_OCTET_STRING *os, struct parse *p)
{
	const ASN1_SEQUENCE_ANY *seq;
	const unsigned char     *d;
	size_t		         dsz;
	int		         i = 0, rc = 0, sz;
	const ASN1_TYPE		*t;
	long			 id;

	d = os->data;
	dsz = os->length;

	/* RFC 6482, section 3. */

	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		cryptowarnx("%s: RFC 6482 section 3: "
			"RouteOriginAttestation: "
			"failed ASN.1 sequence parse", p->fn);
		goto out;
	} 

	if ((sz = sk_ASN1_TYPE_num(seq)) != 2 && sz != 3) {
		warnx("%s: RFC 6482 section 3: "
			"RouteOriginAttestation: "
			"want 2 or 3 elements, have %d", 
			p->fn, sk_ASN1_TYPE_num(seq));
		goto out;
	}

	/* RFC 6482, section 3.1. */

	if (sz == 3) {
		t = sk_ASN1_TYPE_value(seq, i++);
		if (t->type != V_ASN1_INTEGER) {
			warnx("%s: RFC 6482 section 3.1: version: "
				"want ASN.1 integer, have %s (NID %d)", 
				p->fn, ASN1_tag2str(t->type), t->type);
			goto out;
		} else if (ASN1_INTEGER_get(t->value.integer) != 0) {
			warnx("%s: RFC 6482 section 3.1: version: "
				"want version 0, have %ld", 
				p->fn, ASN1_INTEGER_get(t->value.integer));
			goto out;
		}
	} 

	/* 
	 * RFC 6482, section 3.2.
	 * It doesn't ever actually state that AS numbers can't be
	 * negative, but...?
	 */

	t = sk_ASN1_TYPE_value(seq, i++);
	if (t->type != V_ASN1_INTEGER) {
		warnx("%s: RFC 6482 section 3.2: asID: "
			"want ASN.1 integer, have %s (NID %d)", 
			p->fn, ASN1_tag2str(t->type), t->type);
		goto out;
	} else if ((id = ASN1_INTEGER_get(t->value.integer)) < 0) {
		warnx("%s: RFC 6482 section 3.2: asID: want "
			"positive integer, have %ld", p->fn, id);
		goto out;
	}
	p->res->asid = id;

	/* RFC 6482, section 3.3. */

	t = sk_ASN1_TYPE_value(seq, i++);
	if (t->type != V_ASN1_SEQUENCE) {
		warnx("%s: RFC 6482 section 3.3: ipAddrBlocks: "
			"want ASN.1 sequence, have %s (NID %d)", 
			p->fn, ASN1_tag2str(t->type), t->type);
		goto out;
	} else if (!roa_parse_ipblocks(t->value.octet_string, p))
		goto out;

	rc = 1;
out:
	sk_ASN1_TYPE_free(seq);
	return rc;
}

struct roa *
roa_parse(X509 *cacert, const char *fn, const unsigned char *dgst)
{
	struct parse		 p;
	const ASN1_OCTET_STRING	*os;

	memset(&p, 0, sizeof(struct parse));
	p.fn = fn;

	/* OID from section 2, RFC 6482. */

	os = cms_parse_validate(cacert, fn,
		"1.2.840.113549.1.9.16.1.24", dgst);

	if (os == NULL)
		return NULL;

	if ((p.res = calloc(1, sizeof(struct roa))) == NULL)
		err(EXIT_FAILURE, NULL);

	if (!roa_parse_econtent(os, &p)) {
		roa_free(p.res);
		p.res = NULL;
	}
	return p.res;

}

void
roa_free(struct roa *p)
{

	if (p == NULL)
		return;

	free(p->ips);
	free(p);
}

void
roa_buffer(char **b, size_t *bsz, size_t *bmax, const struct roa *p)
{
	size_t	 i;

	simple_buffer(b, bsz, bmax, &p->asid, sizeof(uint32_t));
	simple_buffer(b, bsz, bmax, &p->ipsz, sizeof(size_t));

	for (i = 0; i < p->ipsz; i++) {
		simple_buffer(b, bsz, bmax,
			&p->ips[i].afi, sizeof(uint16_t));
		simple_buffer(b, bsz, bmax,
			&p->ips[i].maxlength, sizeof(size_t));
		simple_buffer(b, bsz, bmax,
			&p->ips[i].addr.sz, sizeof(size_t));
		simple_buffer(b, bsz, bmax,
			p->ips[i].addr.addr, p->ips[i].addr.sz);
		simple_buffer(b, bsz, bmax,
			&p->ips[i].addr.unused, sizeof(long));
	}
}

/*
 * Read parsed ROA content.
 * Result must be passed to roa_free().
 */
struct roa *
roa_read(int fd)
{
	struct roa 	*p;
	size_t		 i;

	if ((p = calloc(1, sizeof(struct roa))) == NULL)
		err(EXIT_FAILURE, NULL);

	simple_read(fd, 0, &p->asid, sizeof(uint32_t));
	simple_read(fd, 0, &p->ipsz, sizeof(size_t));

	if ((p->ips = calloc(p->ipsz, sizeof(struct roa_ip))) == NULL)
		err(EXIT_FAILURE, NULL);

	for (i = 0; i < p->ipsz; i++) {
		simple_read(fd, 0, &p->ips[i].afi, sizeof(uint16_t));
		simple_read(fd, 0, &p->ips[i].maxlength, sizeof(size_t));
		simple_read(fd, 0, &p->ips[i].addr.sz, sizeof(size_t));
		simple_read(fd, 0, p->ips[i].addr.addr, p->ips[i].addr.sz);
		simple_read(fd, 0, &p->ips[i].addr.unused, sizeof(long));
	}

	return p;
}

