/*	$Id$ */
/*
 * Copyright (c) 2019 Kristaps Dzonsons <kristaps@bsd.lv>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include "config.h"

#include <err.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "extern.h"

/*
 * 0 for no output but results, 1 for status, 2 for detailed debugging
 * messages during operation.
 */
int	 verbose;

/*
 * Log a message to stderr if and only if "verbose" is non-zero.
 * This uses the err(3) functionality.
 */
void
logx(const char *fmt, ...)
{
	va_list		 ap;

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
cryptoerrx(const char *fmt, ...)
{
	unsigned long	 er;
	char		 buf[BUFSIZ];
	va_list		 ap;

	while ((er = ERR_get_error()) > 0) {
		ERR_error_string_n(er, buf, sizeof(buf));
		warnx(" ...trace: %s", buf);
	}

	if (fmt != NULL) {
		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}

	exit(1);
}

/*
 * Like cryptoerrx(), but without exiting.
 */
void
cryptowarnx(const char *fmt, ...)
{
	unsigned long	 er;
	char		 buf[BUFSIZ];
	va_list		 ap;

	while ((er = ERR_get_error()) > 0) {
		ERR_error_string_n(er, buf, sizeof(buf));
		warnx(" ...trace: %s", buf);
	}

	if (fmt != NULL) {
		va_start(ap, fmt);
		vwarnx(fmt, ap);
		va_end(ap);
	}
}
