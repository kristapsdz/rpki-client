#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include "extern.h"

int
main(int argc, char *argv[])
{
	int		 c, verb = 0;
	size_t		 i;
	const char	*cert = NULL;
	BIO		*bio;
	X509		*x = NULL;
	struct roa	*p;

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
		p = roa_parse_file(verb, x, argv[i]);
		if (NULL == p)
			break;
		roa_free(p);
	}

	X509_free(x);
	rpki_log_close();
	return i < (size_t)argc ? EXIT_FAILURE : EXIT_SUCCESS;
}
