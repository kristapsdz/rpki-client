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
test(const char *res, uint16_t afi, size_t sz, size_t unused, ...)
{
	va_list	 	    ap;
	struct cert_ip_addr addr;
	char		    buf[64];
	size_t		    i;

	memset(&addr, 0, sizeof(struct cert_ip_addr));

	va_start(ap, unused);
	for (i = 0; i < sz - 1; i++) 
		addr.addr[i] = (unsigned char)va_arg(ap, int);
	va_end(ap);

	addr.sz = sz - 1;
	addr.unused = unused;
	ip_addr2str(&addr, afi, buf, sizeof(buf));
	if (res != NULL && strcmp(res, buf)) 
		errx(EXIT_FAILURE, "fail: %s != %s\n", res, buf);
	else if (res != NULL)
		warnx("pass: %s", buf);
	else 
		warnx("check: %s", buf);
}

int
main(int argc, char *argv[])
{

	SSL_library_init();
	SSL_load_error_strings();

	test("10.5.0.4",
	     1, 0x05, 0x00, 0x0a, 0x05, 0x00, 0x04);

	test("10.5.0/23",
	     1, 0x04, 0x01, 0x0a, 0x05, 0x00);

	test("2001:0:200:3:0:0:0:1",
	     2, 0x11, 0x00, 0x20, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x03,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01);

	test("2001:0:200/39",
	     2, 0x06, 0x01, 0x20, 0x01, 0x00, 0x00, 0x02);

	test(NULL,
	     1, 0x03, 0x00, 0x0a, 0x05);

	test(NULL,
	     1, 0x04, 0x01, 0x0a, 0x05, 0x00);

	test(NULL,
	     2, 0x06, 0x01, 0x20, 0x01, 0x00, 0x00, 0x02);

	test(NULL,
	     2, 0x06, 0x02, 0x20, 0x01, 0x00, 0x00, 0x00);

	test("0/0",
	     1, 0x01, 0x00);

	test("10.64/12",
	     1, 0x03, 0x04, 0x0a, 0x40);

	test("10.64.0/20",
	     1, 0x04, 0x04, 0x0a, 0x40, 0x00);

	ERR_free_strings();
	return EXIT_SUCCESS;
}
