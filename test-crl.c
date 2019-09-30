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

#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "asn1.h"
#include "extern.h"

int	 verbose;

// http://www.geo-complex.com/shares/soft/unix/CentOS/OpenVPN/openssl-1.1.0c/crypto/x509/x_crl.c
static void
crl_print(const X509_CRL *p)
{
	int i, numRevoked;
	char caRevocationDate[64];
	long crlNumber;
	struct tm tm;
	STACK_OF(X509_REVOKED) *revoked;

	revoked = X509_CRL_get_REVOKED(p);
	crlNumber = ASN1_INTEGER_get(p->crl_number);
	printf ("Certificate Revocation List (CRL):\n");
	printf ("        CRL extensions:\n");
	printf ("            X509v3 CRL Number:\n");
	printf ("                %ld\n", crlNumber);
	numRevoked = sk_X509_REVOKED_num(revoked);
	if (numRevoked > 0) {
		printf ("Revoked Certificates:\n");
		for (i = 0; i < numRevoked; i++) {
			X509_REVOKED *rev = sk_X509_REVOKED_value(revoked, i);
			if (rev != NULL) {
				BIGNUM *bnSrl = ASN1_INTEGER_to_BN(rev->serialNumber, NULL);
				if (bnSrl != NULL) {
					char *lpcSrl = BN_bn2hex(bnSrl);
					if (lpcSrl != NULL) {
						printf ("    Serial Number: %s\n", lpcSrl);
						OPENSSL_free(lpcSrl);
					}
					BN_free(bnSrl);
				}
			}
			tm = asn1Time2Time(rev->revocationDate);
			strftime(caRevocationDate, sizeof(caRevocationDate)-1, "%Y-%m-%d %H:%M:%S GMT", &tm);
			printf ("        Revokation Date: %s\n", caRevocationDate);
		}
	}
}


int
main(int argc, char *argv[])
{
	int		 c;
	size_t		 i;
	X509_CRL	*p;
	X509		*xp = NULL;

	SSL_library_init();
	SSL_load_error_strings();

	while (-1 != (c = getopt(argc, argv, "v")))
		switch (c) {
		case 'v':
			verbose++;
			break;
		default:
			return EXIT_FAILURE;
		}

	argv += optind;
	argc -= optind;

	for (i = 0; i < (size_t)argc; i++) {
		if ((p = crl_parse(argv[i], NULL)) == NULL)
			break;
		if (verbose)
			crl_print(p);
		X509_CRL_free(p);
		X509_free(xp);
	}

	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_state(0);
	ERR_free_strings();
	return i < (size_t)argc ? EXIT_FAILURE : EXIT_SUCCESS;
}