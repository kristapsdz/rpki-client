/*	$Id$ */
/*
 * Copyright (c) 2019 Kristaps Dzonsons <kristaps@bsd.lv>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
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
	struct crl	*res; /* result */
	const char	*fn; /* currently-parsed file */
};

struct crl *
crl_parse(X509_CRL **xp, const char *fn, const unsigned char *dgst)
{
	int	 	 i, rc = 0, sz;
	X509_CRL	*x = NULL;
	struct parse	 p;
	BIO		*bio = NULL, *shamd;
	EVP_MD		*md;
	char	 	 mdbuf[EVP_MAX_MD_SIZE];
	STACK_OF(X509_REVOKED) *revs = NULL;
	const ASN1_INTEGER *sn;
	X509_REVOKED	*r;
	long		 v;

	memset(&p, 0, sizeof(struct parse));
	p.fn = fn;
	if ((p.res = calloc(1, sizeof(struct crl))) == NULL)
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

	if ((x = *xp = d2i_X509_CRL_bio(bio, NULL)) == NULL) {
		cryptowarnx("%s: d2i_X509_CRL_bio", p.fn);
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

	if (X509_CRL_get_version(x) != 1) {
		warnx("%s: RFC 6487 section 5: bad CRL version: "
			"%ld ", p.fn, X509_CRL_get_version(x));
		goto out;
	}

	if (X509_CRL_get_lastUpdate(x) == NULL ||
	    X509_CRL_get_nextUpdate(x) == NULL) {
		warnx("%s: RFC 6487 section 5: CRL "
			"lacks time validity constraints", p.fn);
		goto out;
	}

	/* Time boundaries set by RFC 5280. */

	if (X509_cmp_current_time(X509_CRL_get_nextUpdate(x)) < 0) {
		warnx("%s: RFC 5280 section 5.1.2.5: nextUpdate: "
			"stale CRL", p.fn);
		goto out;
	}
	if (X509_cmp_current_time(X509_CRL_get_lastUpdate(x)) > 0) {
		warnx("%s: RFC 5280 section 5.1.2.5: lastUpdate: "
			"before date interval (clock drift?)", p.fn);
		goto out;
	}

	/* FIXME: use ASN1_INTEGER: don't cast to uint32_t. */

	if ((v = ASN1_INTEGER_get(x->crl_number)) < 0) {
		warnx("%s: RFC 6487 section 5: "
			"negative CRL number: %ld ", p.fn, v);
		goto out;
	}
	p.res->num = v;

	/*
	 * FIXME: in the ports version of OpenSSL, I need to use the
	 * direct structure items.
	 * In libressl, we have X509_REVOKED_get0_serialNumber() and
	 * friends to access these values.
	 */

	revs = X509_CRL_get_REVOKED(x);
	for (i = 0; i < sk_X509_REVOKED_num(revs); i++) {
		r = sk_X509_REVOKED_value(revs, i);
		if (X509_cmp_current_time(r->revocationDate) > 0)
			continue;
		sn = r->serialNumber;
		assert(sn != NULL);
		if ((v = ASN1_INTEGER_get(sn)) < 0) {
			warnx("%s: RFC 6487 section 5: negative "
				"CRL serial number: %ld", p.fn, v);
			goto out;
		}
		p.res->sns = reallocarray
			(p.res->sns, p.res->snsz + 1, sizeof(uint32_t));
		if (p.res->sns == NULL)
			err(EXIT_FAILURE, NULL);
		p.res->sns[p.res->snsz++] = v;
	}

	rc = 1;
out:
	BIO_free_all(bio);
	if (rc == 0) {
		crl_free(p.res);
		X509_CRL_free(x);
		*xp = NULL;
	}
	return (rc == 0) ? NULL : p.res;
}

void
crl_free(struct crl *p)
{

	if (p == NULL)
		return;
	free(p->sns);
	free(p);
}

/*
 * Write certificate revocation list parsed content.
 * See crl_read() for the other side of the pipe.
 */
void
crl_buffer(char **b, size_t *bsz, size_t *bmax, const struct crl *p)
{
	size_t	 i;

	io_simple_buffer(b, bsz, bmax, &p->snsz, sizeof(size_t));
	for (i = 0; i < p->snsz; i++)
		io_simple_buffer(b, bsz, bmax, &p->sns[i], sizeof(uint32_t));
}

/*
 * Read parsed certificate revocation list content.
 * The pointer must be freed with crl_free().
 */
struct crl *
crl_read(int fd)
{
	struct crl	*p;
	size_t	 	 i;

	if ((p = calloc(1, sizeof(struct crl))) == NULL)
		err(EXIT_FAILURE, NULL);

	io_simple_read(fd, &p->snsz, sizeof(size_t));
	if ((p->sns = calloc(p->snsz, sizeof(size_t))) == NULL)
		err(EXIT_FAILURE, NULL);
	for (i = 0; i < p->snsz; i++) 
		io_simple_read(fd, &p->sns[i], sizeof(uint32_t));
	return p;
}

