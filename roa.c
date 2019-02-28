#include <assert.h>
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
	int		  verbose; /* parse verbosity */
	struct roa	 *res;
};

/* 
 * Wrap around the existing log macros. 
 * Do this to pass the "verbose" variable into the log.
 */

#define ROA_WARNX(_p, _fmt, ...) \
	WARNX((_p)->verbose, (_fmt), ##__VA_ARGS__)
#define ROA_WARNX1(_p, _fmt, ...) \
	WARNX1((_p)->verbose, (_fmt), ##__VA_ARGS__)
#define ROA_LOG(_p, _fmt, ...) \
	LOG((_p)->verbose, (_fmt), __VA_ARGS__)
#define ROA_CRYPTOX(_p, _fmt, ...) \
	CRYPTOX((_p)->verbose, (_fmt), __VA_ARGS__)

/*
 * Parse an IP block structure, RFC 6482, section 3.3.
 * The incoming octet string is an ASN1_SEQUENCE.
 * Returns zero on failure, non-zero on success.
 */
static int
roa_parse_ipblock(const ASN1_OCTET_STRING *os, struct parse *p)
{
	const ASN1_SEQUENCE_ANY *seq;
	const unsigned char     *d;
	size_t		         dsz;

	d = os->data;
	dsz = os->length;
	seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz);
	assert(NULL != seq);

	if (0 == sk_ASN1_TYPE_num(seq)) {
		ROA_WARNX(p, "%s: no IP blocks assigned", p->fn);
		return 0;
	}

	ROA_LOG(p, "%s: have %d addresses", 
		p->fn, sk_ASN1_TYPE_num(seq));
	return 1;
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
	int		         i = 0, rc = 0;
	long			 id;
	const ASN1_TYPE		*ver = NULL, *asid, *ipblks;

	d = os->data;
	dsz = os->length;

	seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz);
	if (NULL == seq) {
		ROA_CRYPTOX(p, "%s: want ASN.1 sequence", p->fn);
		goto out;
	} 

	if (2 != sk_ASN1_TYPE_num(seq) &&
	    3 != sk_ASN1_TYPE_num(seq)) {
		ROA_WARNX(p, "%s: want 2 or 3 elements", p->fn);
		goto out;
	}

	/* The version number (section 3.1) is optional. */

	if (3 == sk_ASN1_TYPE_num(seq)) {
		ver = sk_ASN1_TYPE_value(seq, i++);
		if (V_ASN1_INTEGER != ver->type) {
			ROA_WARNX(p, "%s: want ASN.1 integer", p->fn);
			goto out;
		} 
	} 

	/* AS identifier (section 3.2). */

	asid = sk_ASN1_TYPE_value(seq, i++);
	if (V_ASN1_INTEGER != asid->type) {
		ROA_WARNX(p, "%s: want ASN.1 integer", p->fn);
		goto out;
	} 
	id = ASN1_INTEGER_get(asid->value.integer);
	if (id < 0) {
		ROA_WARNX(p, "%s: negative AS identifier", p->fn);
		goto out;
	}
	ROA_LOG(p, "%s: parsed AS identifier: %ld", p->fn, id);
	p->res->asid = id;

	/* IP block sequence (section 3.3). */

	ipblks = sk_ASN1_TYPE_value(seq, i++);
	if (V_ASN1_SEQUENCE != ipblks->type) {
		ROA_WARNX(p, "%s: want ASN.1 sequence", p->fn);
		goto out;
	} 
	if ( ! roa_parse_ipblock(ipblks->value.octet_string, p)) {
		ROA_WARNX1(p, "roa_parse_ipblock");
		goto out;
	}

	rc = 1;
out:
	sk_ASN1_TYPE_free(seq);
	return rc;
}

struct roa *
roa_parse(int verb, X509 *cacert, const char *fn)
{
	struct parse		 p;
	const ASN1_OCTET_STRING	*os;

	memset(&p, 0, sizeof(struct parse));
	p.fn = fn;
	p.verbose = verb;

	/* OID from section 2, RFC 6482. */

	os = cms_parse_validate(verb, cacert, 
		fn, "1.2.840.113549.1.9.16.1.24");

	if (NULL == os) {
		ROA_WARNX1(&p, "cms_parse_validate");
		return NULL;
	} else if (NULL == (p.res = calloc(1, sizeof(struct roa)))) {
		WARN("calloc");
		return NULL;
	} else if (roa_parse_econtent(os, &p))
		return p.res;

	ROA_WARNX1(&p, "roa_parse_econtent");
	roa_free(p.res);
	return NULL;
}

void
roa_free(struct roa *p)
{

	free(p);
}

int
roa_buffer(char **b, size_t *bsz, size_t *bmax,
	int verb, const struct roa *p)
{

	return 1;
}

/*
 * Read parsed ROA content.
 * Returns NULL on failure or the valid pointer otherwise.
 * Result must be passed to roa_free().
 */
struct roa *
roa_read(int fd, int verb)
{
	struct roa 	*p;

	if ((p = calloc(1, sizeof(struct roa))) == NULL)
		WARN("calloc");

	return p;
}

