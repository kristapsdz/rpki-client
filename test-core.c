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

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#include "test-core.h"

static unsigned char ToAsc (unsigned char c)
{
	unsigned char nib = c & 0x0f;
  	if (nib <= 9)
    	return (nib + '0');
	return (nib - 10 + 'a');
}

void hex_encode (unsigned char *lpcAsc, unsigned char *lpcBcd, size_t szBcd)
{
	size_t i;
	for (i = 0; i < szBcd; i++) {
		*lpcAsc++ = ToAsc (lpcBcd[i] >> 4);
		*lpcAsc++ = ToAsc (lpcBcd[i]);
	}
}

void print_sep_line (const char *title, size_t count)
{
	size_t i;

	if (title && *title) {
		printf ("%s ", title);
		count -= strlen(title) + 1;
	}
	for (i = 0; i < count; i++) {
		printf("=");
	}
	printf("\n");
}
