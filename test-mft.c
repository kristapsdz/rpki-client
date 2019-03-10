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
	struct mft	*p;
	X509		*xp = NULL;

	SSL_library_init();
	SSL_load_error_strings();

	while (-1 != (c = getopt(argc, argv, "v"))) 
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
		if ((p = mft_parse(&xp, argv[i])) == NULL)
			break;
		if (verb)
			mft_print(p);
		mft_free(p);
		X509_free(xp);
	}

	ERR_free_strings();
	return i < (size_t)argc ? EXIT_FAILURE : EXIT_SUCCESS;
}
