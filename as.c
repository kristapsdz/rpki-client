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
#include <sys/socket.h>

#include <assert.h>
#include <err.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include "extern.h"

/*
 * Given a newly-parsed AS number or range "a", make sure that "a" does
 * not overlap with any other numbers or ranges in the "as" array.
 * This is defined by RFC 3779 section 3.2.3.4.
 * Returns zero on failure, non-zero on success.
 */
int
as_check_overlap(const struct cert_as *a, const char *fn,
	const struct cert_as *as, size_t asz)
{
	size_t	 i;

	/* We can have only one inheritence statement. */

	if (asz &&
	    (a->type == CERT_AS_INHERIT ||
	     as[0].type == CERT_AS_INHERIT)) {
		warnx("%s: RFC 3779 section 3.2.3.3: cannot have "
			"inheritence and multiple ASnum or "
			"multiple inheritence", fn);
		return 0;
	}

	/* Now check for overlaps between singletons/ranges. */

	for (i = 0; i < asz; i++)
		switch (as[i].type) {
		case CERT_AS_ID:
			switch (a->type) {
			case CERT_AS_ID:
				if (a->id != as[i].id)
					break;
				warnx("%s: RFC 3779 section 3.2.3.4: "
					"cannot have overlapping "
					"ASnum", fn);
				return 0;
			case CERT_AS_RANGE:
				if (as->range.min > as[i].id ||
				    as->range.max < as[i].id)
					break;
				warnx("%s: RFC 3779 section 3.2.3.4: "
					"cannot have overlapping "
					"ASnum", fn);
				return 0;
			default:
				abort();
			}
			break;
		case CERT_AS_RANGE:
			switch (a->type) {
			case CERT_AS_ID:
				if (as[i].range.min > a->id ||
				    as[i].range.max < a->id)
					break;
				warnx("%s: RFC 3779 section 3.2.3.4: "
					"cannot have overlapping "
					"ASnum", fn);
				return 0;
			case CERT_AS_RANGE:
				if (a->range.max < as[i].range.min ||
				    a->range.min > as[i].range.max)
					break;
				warnx("%s: RFC 3779 section 3.2.3.4: "
					"cannot have overlapping "
					"ASnum", fn);
				return 0;
			default:
				abort();
			}
			break;
		default:
			abort();
		}

	return 1;
}

/*
 * See if a given AS number is covered by the AS numbers or ranges
 * specified in the "as" array.
 * Return zero if there is no cover, non-zero if there is.
 */
int
as_check_covered(uint32_t asid, const struct cert_as *as, size_t asz)
{
	size_t	 i;

	for (i = 0; i < asz; i++)
		switch (as[i].type) {
		case CERT_AS_ID:
			if (asid == as[i].id)
				return 1;
			break;
		case CERT_AS_RANGE:
			if (asid >= as[i].range.min &&
			    asid <= as[i].range.max)
				return 1;
			break;
		case CERT_AS_INHERIT:
			break;
		default:
			abort();
		}

	return 0;
}
