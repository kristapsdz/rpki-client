#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/x509.h>

#include "extern.h"

static void
tal_print(const struct tal *tal)
{
	size_t	 i;

	assert(tal != NULL);
	for (i = 0; i < tal->urisz; i++)
		fprintf(stderr, "%5zu: URI: %s\n", i + 1, tal->uri[i]);
}

int
main(int argc, char *argv[])
{
	int		 c, verb = 0;
	struct tal	*tal;
	size_t		 i;

	rpki_log_open();

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
		if (NULL == (tal = tal_parse(verb, argv[i])))
			break;
		tal_print(tal);
		tal_free(tal);
	}

	rpki_log_close();
	return i < (size_t)argc ? EXIT_FAILURE : EXIT_SUCCESS;
}
