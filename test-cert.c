#include <sys/socket.h>

#include <arpa/inet.h>
#include <assert.h>
#include <err.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include "extern.h"

static void
cert_print(const struct cert *p)
{
	size_t		 i;
	char		 buf1[128], buf2[128];
	const char	*cp1, *cp2;

	assert(NULL != p);

	if (NULL != p->rep)
		fprintf(stderr, "CA repository: %s\n", p->rep);
	if (NULL != p->mft)
		fprintf(stderr, "Manifest: %s\n", p->mft);
	if (NULL != p->ski)
		fprintf(stderr, "Subject key identifier: %s\n", p->ski);
	if (NULL != p->aki)
		fprintf(stderr, "Authority key identifier: %s\n", p->ski);

	for (i = 0; i < p->asz; i++)
		switch (p->as[i].type) {
		case CERT_AS_ID:
			fprintf(stderr, 
				"%5zu: AS%s: %" PRIu32 "\n", i + 1, 
				p->as[i].rdi ? " (rdi)" : "", 
				p->as[i].id);
			break;
		case CERT_AS_NULL:
			fprintf(stderr,
				"%5zu: AS%s: inherit\n", i + 1, 
				p->as[i].rdi ? " (rdi)" : "");
			break;
		case CERT_AS_RANGE:
			fprintf(stderr,
				"%5zu: AS%s: %" PRIu32 
				" -- %" PRIu32 "\n", i + 1, 
				p->as[i].rdi ? " (rdi)" : "", 
				p->as[i].range.min, 
				p->as[i].range.max);
			break;
		}

	for (i = 0; i < p->ipsz; i++)
		switch (p->ips[i].type) {
		case CERT_IP_INHERIT:
			fprintf(stderr, 
				"%5zu: IPv%s: inherit\n", i + 1, 
				1 == p->ips[i].afi ? "4" : "6");
			break;
		case CERT_IP_ADDR:
			/* FALLTHROUGH */
		case CERT_IP_RANGE:
			cp1 = inet_ntop(1 == p->ips[i].afi ? 
				AF_INET : AF_INET6,
				p->ips[i].range.min.addr, 
				buf1, sizeof(buf1));
			cp2 = inet_ntop(1 == p->ips[i].afi ? 
				AF_INET : AF_INET6,
				p->ips[i].range.max.addr, 
				buf2, sizeof(buf2));
			if (NULL == cp1 || NULL == cp2)
				continue;
			fprintf(stderr, 
				"%5zu: IPv%s: %s -- %s\n", i + 1, 
				1 == p->ips[i].afi ? "4" : "6",
				cp1, cp2);
			break;
		}
}

int
main(int argc, char *argv[])
{
	int		 c, verb = 0;
	size_t		 i;
	BIO		*bio;
	X509		*x = NULL;
	const char	*cert = NULL;
	struct cert	*p;

	SSL_library_init();
	rpki_log_open();

	while (-1 != (c = getopt(argc, argv, "c:v"))) 
		switch (c) {
		case 'c':
			cert = optarg;
			break;
		case 'v':
			verb++;
			break;
		default:
			return EXIT_FAILURE;
		}

	argv += optind;
	argc -= optind;

	if (NULL != cert) {
		if (NULL == (bio = BIO_new_file(cert, "rb"))) {
			CRYPTOX(verb, "%s: BIO_new_file", cert);
			return EXIT_FAILURE;
		} else if (NULL == (x = d2i_X509_bio(bio, NULL))) {
			CRYPTOX(verb, "%s: d2i_X509_bio", cert);
			BIO_free(bio);
			return EXIT_FAILURE;
		}
		BIO_free(bio);
		LOG(verb, "%s: attached certificate", cert);
	}

	for (i = 0; i < (size_t)argc; i++) {
		p = cert_parse(verb, x, argv[i], NULL);
		if (NULL == p)
			break;
		cert_print(p);
		cert_free(p);
	}

	X509_free(x);
	rpki_log_close();
	return i < (size_t)argc ? EXIT_FAILURE : EXIT_SUCCESS;
}
