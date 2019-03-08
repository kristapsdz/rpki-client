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
	size_t		 i;
	char		 buf1[128], buf2[128];

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
			fprintf(stderr, "%5zu: AS%s: %" PRIu32 "\n", i + 1, 
				p->as[i].rdi ? " (rdi)" : "", p->as[i].id);
			break;
		case CERT_AS_NULL:
			fprintf(stderr, "%5zu: AS%s: inherit\n", i + 1, 
				p->as[i].rdi ? " (rdi)" : "");
			break;
		case CERT_AS_RANGE:
			fprintf(stderr,
				"%5zu: AS%s: %" PRIu32 "--%" PRIu32 "\n", 
				i + 1, p->as[i].rdi ? " (rdi)" : "", 
				p->as[i].range.min, p->as[i].range.max);
			break;
		}

	for (i = 0; i < p->ipsz; i++)
		switch (p->ips[i].type) {
		case CERT_IP_INHERIT:
			fprintf(stderr, "%5zu: IP: inherit\n", i + 1);
			break;
		case CERT_IP_ADDR:
			ip_addr_print(&p->ips[i].range.min, 
				p->ips[i].afi, buf1, sizeof(buf1));
			fprintf(stderr, "%5zu: IP: %s\n", i + 1, buf1);
			break;
		case CERT_IP_RANGE:
			ip_addr_range_print(&p->ips[i].range.min, 
				p->ips[i].afi, buf1, sizeof(buf1), 0);
			ip_addr_range_print(&p->ips[i].range.max, 
				p->ips[i].afi, buf2, sizeof(buf2), 1);
			fprintf(stderr, "%5zu: IP: %s--%s\n", i + 1, buf1, buf2);
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
	SSL_load_error_strings();

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
		if ((bio = BIO_new_file(cert, "rb")) == NULL)
			cryptoerrx("%s: BIO_new_file", cert);
		if ((x = d2i_X509_bio(bio, NULL)) == NULL)
			cryptoerrx("%s: d2i_X509_bio", cert);
		BIO_free(bio);
	}

	for (i = 0; i < (size_t)argc; i++) {
		if ((p = cert_parse(argv[i], NULL, NULL, 0)) == NULL)
			break;
		if (verb)
			cert_print(p);
		cert_free(p);
	}

	X509_free(x);
	ERR_free_strings();
	return i < (size_t)argc ? EXIT_FAILURE : EXIT_SUCCESS;
}
