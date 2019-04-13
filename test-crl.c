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
#include <arpa/inet.h>
#include <sys/socket.h>

#include <assert.h>
#include <err.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "extern.h"

static void
crl_print(const struct crl *p)
{
	size_t	 i;
	BIO	*ob;
	
	if ((ob = BIO_new_fp(stdout, BIO_NOCLOSE)) == NULL)
		errx(EXIT_FAILURE, "BIO_new_fp");

	if (p->num != NULL) {
		printf("CRL number: ");
		i2a_ASN1_INTEGER(ob, p->num);
		printf("\n");
	}

	for (i = 0; i < p->snsz; i++) {
		assert(p->sns[i] != NULL);
		printf("%5zu: ", i + 1);
		i2a_ASN1_INTEGER(ob, p->sns[i]);
		printf("\n");
	}

	BIO_free(ob);
}

int
main(int argc, char *argv[])
{
	int		 c, verb = 0;
	size_t		 i;
	struct crl	*p;
	X509_CRL	*x;

	SSL_library_init();
	SSL_load_error_strings();

	while ((c = getopt(argc, argv, "v")) != -1) 
		switch (c) {
		case 'v':
			verb++;
			break;
		default:
			return EXIT_FAILURE;
		}

	argv += optind;
	argc -= optind;

	for (i = 0; i < (size_t)argc; i++) {
		if ((p = crl_parse(&x, argv[i], NULL)) == NULL)
			break;
		if (verb)
			crl_print(p);
		crl_free(p);
		X509_CRL_free(x);
	}

	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_state(0);
	ERR_free_strings();
	return i < (size_t)argc ? EXIT_FAILURE : EXIT_SUCCESS;
}
