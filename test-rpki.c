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
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "extern.h"
#include "test-core.h"

int	 verbose = 1;

int
main(int argc, char *argv[])
{
	size_t		 i;
	size_t		 sz;
	struct cert	*cert;
	struct mft	*mft;
	struct roa	*roa;
	struct tal	*tal;
	char 		*fn;
	X509_CRL	*crl;
	X509		*xp = NULL;

	SSL_library_init();
	SSL_load_error_strings();

	for (i = 1; i < (size_t)argc; i++) {
		fn = argv[i];
		sz = strlen(argv[i]);
		if (strcasecmp(fn + sz - 4, ".mft") == 0) {
			if ((mft = mft_parse(&xp, fn, 1)) != NULL) {
				print_mft(mft);
				mft_free(mft);
			}
		}
		else if (strcasecmp(fn + sz - 4, ".roa") == 0) {
			if ((roa = roa_parse(&xp,fn, NULL)) != NULL) {
				print_roa(roa);
				roa_free(roa);
			}
		}
		else if (strcasecmp(fn + sz - 4, ".crl") == 0) {
			if ((crl = crl_parse(fn, NULL)) != NULL) {
				print_crl(crl);
				X509_CRL_free(crl);
			}
		}
		else {
			crypto_set_silent(1);
			// Try checking a TAL
			tal = tal_parse(fn);
			crypto_set_silent(0);
			if (tal != NULL) {
				print_tal(tal);
				tal_free(tal);
			}
			else {
				crypto_set_silent(1);
				// Try checking a TA cert
				cert = ta_parse(&xp, fn, NULL, 0);
				crypto_set_silent(0);
				if (cert != NULL) {
					print_cert(cert);
					cert_free(cert);
				} else {
					cert = cert_parse(&xp, fn, NULL);
					if (cert != NULL) {
						print_cert(cert);
						cert_free(cert);
					}
				}
			}
		}

		if (xp != NULL) {
			X509_free(xp);
			xp = NULL;
		}
	}

	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_state(0);
	ERR_free_strings();
	return i < (size_t)argc ? EXIT_FAILURE : EXIT_SUCCESS;
}
