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

#include "extern.h"
#include "test-core.h"

#define TAB 30

int	 verbose;

static void
mft_print(const struct mft *p)
{
	size_t	 i;
	unsigned char caSHA256[64 + 1];
	char caNotAfter[64], caNotBefore[64], caThis[64], caNext[64], caNow[64];
	time_t now;
	struct tm *tm;

	assert(p != NULL);

    now = time(NULL);
	tm = gmtime(&now);
	strftime(caNow, sizeof(caNow)-1, "%Y-%m-%d %H:%M:%S GMT", tm);

	tm = gmtime(&p->thisUpdate);
	strftime(caThis, sizeof(caThis)-1, "%Y-%m-%d %H:%M:%S GMT", tm);

	tm = gmtime(&p->nextUpdate);
	strftime(caNext, sizeof(caNext)-1, "%Y-%m-%d %H:%M:%S GMT", tm);

	tm = gmtime(&p->notBefore);
	strftime(caNotBefore, sizeof(caNotBefore)-1, "%Y-%m-%d %H:%M:%S GMT", tm);

	tm = gmtime(&p->notAfter);
	strftime(caNotAfter, sizeof(caNotAfter)-1, "%Y-%m-%d %H:%M:%S GMT", tm);

	printf("%*.*s: %s\n", TAB, TAB, "Now", caNow);
	print_sep_line("EE Certificate", 110);
	printf("%*.*s: %s\n", TAB, TAB, "Not Before", caNotBefore);
	printf("%*.*s: %s\n", TAB, TAB, "Not After", caNotAfter);
	printf("%*.*s: %s\n", TAB, TAB, "Subject key identifier", p->ski);
	printf("%*.*s: %s\n", TAB, TAB, "Authority key identifier", p->aki);
	print_sep_line("Manifest", 110);

	printf("%*.*s: %ld\n", TAB, TAB, "Manifest Number", p->manifestNumber);
	printf("%*.*s: %s\n", TAB, TAB, "This Update", caThis);
	printf("%*.*s: %s\n", TAB, TAB, "Next Update", caNext);
	for (i = 0; i < p->filesz; i++) {
		memset (caSHA256, 0, sizeof (caSHA256));
		hex_encode(caSHA256, p->files[i].hash, 32);
		printf("%s  %s\n", caSHA256, p->files[i].file);
	}
}


int
main(int argc, char *argv[])
{
	int		 c, force = 0;
	size_t		 i;
	struct mft	*p;
	X509		*xp = NULL;

	SSL_library_init();
	SSL_load_error_strings();

	while (-1 != (c = getopt(argc, argv, "fv")))
		switch (c) {
		case 'f':
			force = 1;
			break;
		case 'v':
			verbose++;
			break;
		default:
			return EXIT_FAILURE;
		}

	argv += optind;
	argc -= optind;

	for (i = 0; i < (size_t)argc; i++) {
		if ((p = mft_parse(&xp, argv[i], force)) == NULL)
			break;
		if (verbose)
			mft_print(p);
		mft_free(p);
		X509_free(xp);
	}

	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_state(0);
	ERR_free_strings();
	return i < (size_t)argc ? EXIT_FAILURE : EXIT_SUCCESS;
}
