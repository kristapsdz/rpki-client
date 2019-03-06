#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "extern.h"

static void
mft_print(const struct mft *p)
{
	size_t	 i;

	assert(p != NULL);
	for (i = 0; i < p->filesz; i++)
		fprintf(stderr, "%5zu: %s\n", i + 1, p->files[i].file);
}


int
main(int argc, char *argv[])
{
	int		 c, verb = 0;
	size_t		 i;
	const char	*cert = NULL;
	BIO		*bio;
	X509		*x = NULL;
	struct mft	*p;

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
		if (NULL == (bio = BIO_new_file(cert, "rb")))
			cryptoerrx("%s: BIO_new_file", cert);
		if (NULL == (x = d2i_X509_bio(bio, NULL)))
			cryptoerrx("%s: d2i_X509_bio", cert);
		BIO_free(bio);
	}

	for (i = 0; i < (size_t)argc; i++) {
		if ((p = mft_parse(x, argv[i])) == NULL)
			break;
		if (verb)
			mft_print(p);
		mft_free(p);
	}

	X509_free(x);
	ERR_free_strings();
	return i < (size_t)argc ? EXIT_FAILURE : EXIT_SUCCESS;
}
