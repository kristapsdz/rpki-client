#include <err.h>
#include <stdarg.h>
#include <stdio.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

void
logx(int verbose, const char *fmt, ...)
{
	va_list	 ap;

	if (verbose && fmt != NULL) {
		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}
}

void
cryptoerrx(int code, const char *fmt, ...)
{
	unsigned long	 er;
	char		 buf[BUFSIZ];
	va_list	  	 ap;

	while ((er = ERR_get_error()) > 0) {
		ERR_error_string_n(er, buf, sizeof(buf));
		warnx("%s", buf);
	}

	if (fmt != NULL) {
		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}

	exit(code);
}

void
cryptowarnx(const char *fmt, ...)
{
	unsigned long	 er;
	char		 buf[BUFSIZ];
	va_list	  	 ap;

	while ((er = ERR_get_error()) > 0) {
		ERR_error_string_n(er, buf, sizeof(buf));
		warnx("%s", buf);
	}

	if (fmt != NULL) {
		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}
}
