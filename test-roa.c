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
roa_print(const struct roa *p)
{

	assert(p != NULL);
	fprintf(stderr, "asID: %" PRIu32 "\n", p->asid);
}

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
	SSL_load_error_strings();

	while ((c = getopt(argc, argv, "c:v")) != -1) 
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

	if (cert != NULL) {
		if ((bio = BIO_new_file(cert, "rb")) == NULL)
			cryptoerrx("%s: BIO_new_file", cert);
		if ((x = d2i_X509_bio(bio, NULL)) == NULL)
			cryptoerrx("%s: d2i_X509_bio", cert);
		BIO_free(bio);
	}

	for (i = 0; i < (size_t)argc; i++) {
		if ((p = roa_parse(x, argv[i], NULL)) == NULL)
			break;
		if (verb)
			roa_print(p);
		roa_free(p);
	}

	X509_free(x);
	ERR_free_strings();
	return i < (size_t)argc ? EXIT_FAILURE : EXIT_SUCCESS;
}
