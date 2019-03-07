#include <err.h>
#include <stdarg.h>
#include <stdio.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

/*
 * Log a message to stderr if and only if "verbose" is non-zero.
 * This uses the err(3) functionality.
 */
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

/*
 * Print the chain of openssl errors that led to the current one.
 * This should only be invoked in the event that OpenSSL fails with
 * something.
 * It's followed by the (optional) given error message, then terminates.
 */
void
cryptoerrx(int code, const char *fmt, ...)
{
	unsigned long	 er;
	char		 buf[BUFSIZ];
	va_list	  	 ap;

	while ((er = ERR_get_error()) > 0) {
		ERR_error_string_n(er, buf, sizeof(buf));
		warnx("backtrace: %s", buf);
	}

	if (fmt != NULL) {
		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}

	exit(code);
}

/*
 * Like cryptoerrx(), but without exiting.
 */
void
cryptowarnx(const char *fmt, ...)
{
	unsigned long	 er;
	char		 buf[BUFSIZ];
	va_list	  	 ap;

	while ((er = ERR_get_error()) > 0) {
		ERR_error_string_n(er, buf, sizeof(buf));
		warnx("backtrace: %s", buf);
	}

	if (fmt != NULL) {
		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}
}
