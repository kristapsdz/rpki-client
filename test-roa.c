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
	char	 buf[128];
	size_t	 i;

	assert(p != NULL);
	fprintf(stderr, "asID: %" PRIu32 "\n", p->asid);
	for (i = 0; i < p->ipsz; i++) {
		ip_addr_print(&p->ips[i].addr, 
			p->ips[i].afi, buf, sizeof(buf));
		fprintf(stderr, "%5zu: %s (max: %zu)\n", i + 1, 
			buf, p->ips[i].maxlength);
	}
}

int
main(int argc, char *argv[])
{
	int		 c, verb = 0;
	size_t		 i;
	X509		*xp = NULL;
	struct roa	*p;

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
		if ((p = roa_parse(&xp, argv[i], NULL)) == NULL)
			break;
		if (verb)
			roa_print(p);
		roa_free(p);
		X509_free(xp);
	}

	ERR_free_strings();
	return i < (size_t)argc ? EXIT_FAILURE : EXIT_SUCCESS;
}
