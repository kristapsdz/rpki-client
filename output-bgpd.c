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
#include <assert.h>
#include <err.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>

#include <openssl/ssl.h>

#include "extern.h"

/*
 * FIXME: sort output.
 */
void
output_bgpd(const struct roa **roas, size_t roasz)
{
	size_t	  i, j;
	char	  buf[64];

	puts("roa-set {");
	for (i = 0; i < roasz; i++)
		for (j = 0; j < roas[i]->ipsz; j++) {
			ip_addr_print(&roas[i]->ips[j].addr, 
				roas[i]->ips[j].afi, buf, sizeof(buf));
			printf("    %s ", buf);
			if (roas[i]->ips[j].maxlength >
			    (roas[i]->ips[j].addr.sz * 8 - 
			     roas[i]->ips[j].addr.unused))
				printf("maxlen %zu ", roas[i]->ips[j].maxlength);
			printf("source-as %" PRIu32 "\n", roas[i]->asid);
		}
	puts("}");
}
