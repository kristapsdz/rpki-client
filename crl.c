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
crl_parse(const char *fn, const unsigned char *dgst)
{
	int	 	 rc = 0, sz;
	X509_CRL	*x = NULL;
	struct parse	 p;
	BIO		*bio = NULL, *shamd;
	EVP_MD		*md;
	unsigned char	 mdbuf[EVP_MAX_MD_SIZE];

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

	if ((x = d2i_X509_CRL_bio(bio, NULL)) == NULL) {
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

	rc = 1;
out:
	BIO_free_all(bio);
	if (rc == 0)
		crl_free(p.res);
	return (rc == 0) ? NULL : p.res;
}

void
crl_free(struct crl *p)
{

	free(p);
}

/*
 * Write certificate revocation list parsed content.
 * See crl_read() for the other side of the pipe.
 */
void
crl_buffer(char **b, size_t *bsz, size_t *bmax, const struct crl *p)
{
}

/*
 * Read parsed certificate revocation list content.
 * The pointer must be freed with crl_free().
 */
struct crl *
crl_read(int fd)
{
	struct crl	*p;

	if ((p = calloc(1, sizeof(struct cert))) == NULL)
		err(EXIT_FAILURE, NULL);

	return p;
}

