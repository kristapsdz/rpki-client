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
cert_print(const struct cert *p)
{
	size_t	 i;
	char	 buf1[64], buf2[64];
	int	 sockt;

	assert(p != NULL);

	fprintf(stderr, "Manifest: %s\n", p->mft);
	if (p->crl != NULL)
		fprintf(stderr, "Revocation list: %s\n", p->crl);

	for (i = 0; i < p->asz; i++)
		switch (p->as[i].type) {
		case CERT_AS_ID:
			fprintf(stderr, "%5zu: AS: %" 
				PRIu32 "\n", i + 1, p->as[i].id);
			break;
		case CERT_AS_INHERIT:
			fprintf(stderr, "%5zu: AS: inherit\n", i + 1);
			break;
		case CERT_AS_RANGE:
			fprintf(stderr, "%5zu: AS: %" 
				PRIu32 "--%" PRIu32 "\n", i + 1, 
				p->as[i].range.min, p->as[i].range.max);
			break;
		}

	for (i = 0; i < p->ipsz; i++)
		switch (p->ips[i].type) {
		case CERT_IP_INHERIT:
			fprintf(stderr, "%5zu: IP: inherit\n", i + 1);
			break;
		case CERT_IP_ADDR:
			ip_addr_print(&p->ips[i].ip, 
				p->ips[i].afi, buf1, sizeof(buf1));
			fprintf(stderr, "%5zu: IP: %s\n", i + 1, buf1);
			break;
		case CERT_IP_RANGE:
			sockt = (p->ips[i].afi == AFI_IPV4) ? 
				AF_INET : AF_INET6;
			inet_ntop(sockt, p->ips[i].min, buf1, sizeof(buf1));
			inet_ntop(sockt, p->ips[i].max, buf2, sizeof(buf2));
			fprintf(stderr, "%5zu: IP: %s--%s\n", i + 1, buf1, buf2);
			break;
		}
}

int
main(int argc, char *argv[])
{
	int		 c, verb = 0;
	size_t		 i;
	X509		*xp = NULL;
	struct cert	*p;

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
		if ((p = cert_parse(&xp, argv[i], NULL)) == NULL)
			break;
		if (verb)
			cert_print(p);
		cert_free(p);
		X509_free(xp);
	}

	ERR_free_strings();
	return i < (size_t)argc ? EXIT_FAILURE : EXIT_SUCCESS;
}
