#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

void
rpki_errx(const char *fn, size_t line, const char *fmt, ...)
{
	va_list	 ap;

	if (NULL == fmt)
		return;
	fprintf(stderr, "%s:%zu: FATAL ERROR: ", fn, line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(EXIT_FAILURE);
}

void
rpki_warnx(int verbose, int level,
	const char *fn, size_t line, const char *fmt, ...)
{
	va_list	 ap;

	if (verbose < level)
		return;
	if (NULL == fmt)
		return;

	fprintf(stderr, "%s:%zu: %s: ", 
		fn, line, level ? "TRACE" : "WARN");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

void
rpki_warn(const char *fn, size_t line, const char *fmt, ...)
{
	va_list	 ap;
	int	 er = errno;

	fprintf(stderr, "%s:%zu: WARN: ", fn, line);
	if (NULL != fmt) {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
		fputs(": ", stderr);
	}
	fprintf(stderr, "%s\n", strerror(er));
}

void
rpki_err(const char *fn, size_t line, const char *fmt, ...)
{
	va_list	 ap;
	int	 er = errno;

	fprintf(stderr, "%s:%zu: FATAL ERROR: ", fn, line);
	if (NULL != fmt) {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
		fputs(": ", stderr);
	}
	fprintf(stderr, "%s\n", strerror(er));
	exit(EXIT_FAILURE);
}

void
rpki_log(int verbose, const char *fn, 
	size_t line, const char *fmt, ...)
{
	va_list	 ap;

	if (verbose < 2)
		return;
	if (NULL == fmt)
		return;

	fprintf(stderr, "%s:%zu: ", fn, line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

/*
 * If we have any errors in the crypto library, use this instead of
 * using just WARNX() with some information.
 * Not only does it print the crypto error, it follows that with the
 * given error message if non-NULL.
 */
void
rpki_cryptox(int verbose, const char *fn,
	size_t line, const char *fmt, ...)
{
	unsigned long	 er;
	char		 buf[BUFSIZ];
	va_list	  	 ap;

	if (verbose)
		while ((er = ERR_get_error()) > 0) {
			ERR_error_string_n(er, buf, sizeof(buf));
			fprintf(stderr, "%s\n", buf);
		}

	if (NULL == fmt) 
		return;

	fprintf(stderr, "%s:%zu: WARN: ", fn, line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

void
rpki_log_open(void)
{

	SSL_load_error_strings();
}

void
rpki_log_close(void)
{

	ERR_free_strings();
}
