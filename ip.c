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
 * Parse an IP address family, RFC 3779, 2.2.3.3.
 * Return zero on failure, non-zero on success.
 */
int
ip_addr_afi_parse(const ASN1_OCTET_STRING *p, uint16_t *afi)
{
	char	 buf[2];

	if (p->length == 0 || p->length > 3)
		return 0;

	memcpy(buf, p->data, sizeof(uint16_t));
	*afi = ntohs(*(uint16_t *)buf);

	/* Only accept IPv4 and IPv6 AFIs. */

	if (*afi != 1 && *afi != 2)
		return 0;

	/* Disallow the optional SAFI. */

	if (p->length == 3)
		return 0;

	return 1;
}

/*
 * Given a newly-parsed IP address or range "ip", make sure that "ip"
 * does not overlap with any addresses or ranges in the "ips" array.
 * This is defined by RFC 3779 section 2.2.3.6.
 * FIXME: check for increasing values as noted in the same section.
 * Returns zero on failure, non-zero on success.
 */
int
ip_addr_check_overlap(const struct cert_ip *ip, const char *fn,
	const struct cert_ip *ips, size_t ipsz)
{

	/* TODO */

	return 1;
}

/*
 * Parse an IP address, RFC 3779, 2.2.3.8.
 * Return zero on failure, non-zero on success.
 */
int
ip_addr_parse(const ASN1_BIT_STRING *p,
	uint16_t afi, const char *fn, struct ip_addr *addr)
{
	long	 unused = 0;

	/* Weird OpenSSL-ism to get unused bit count. */

	if ((ASN1_STRING_FLAG_BITS_LEFT & p->flags))
		unused = ~ASN1_STRING_FLAG_BITS_LEFT & p->flags;

	/* Limit possible sizes of addresses. */

	if ((afi == 1 && p->length > 4) ||
	    (afi == 2 && p->length > 16)) {
		warnx("%s: RFC 3779, section 2.2.3.8: "
			"IP address too long", fn);
		return 0;
	}

	addr->unused = unused;
	addr->sz = p->length;
	memcpy(addr->addr, p->data, p->length);
	return 1;
}

/*
 * Convert the IPv4 address into CIDR notation.
 * Buffer should be able to hold xxx.yyy.zzz.www (the longest prefix is
 * the same).
 */
static void
ip4_addr2str(const struct ip_addr *addr,
	char *b, size_t bsz, unsigned char fill)
{
	size_t	 pos = 0, i;

	assert(bsz >= addr->sz * 4);

	for (i = 0; i < addr->sz; i++)
		pos += snprintf(b + pos, bsz - pos, "%u.", addr->addr[i]);
	if (addr->sz == 0)
		pos = strlcpy(b, (fill == 0) ? "0." : "255.", bsz);

	assert(pos > 1);
	b[--pos] = '\0';

	/* Prefix mask only if we don't have all bits set. */

	if (addr->sz == 4)
		return;
	snprintf(b + pos, bsz - pos, "/%zu", addr->sz * 8 - addr->unused);
}

/*
 * Convert the IPv6 address into CIDR notation.
 */
static void
ip6_addr2str(const struct ip_addr *addr,
	char *b, size_t bsz, unsigned char fill)
{
	size_t	 i, sz, pos = 0;
	char	 buf[16];
	uint16_t v;

	/* 
	 * Address is grouped into pairs of bytes and we may have an odd
	 * number of bytes, so fill into a well-sized buffer to avoid
	 * complexities of handling the odd man out.
	 */

	assert(addr->sz <= sizeof(buf));
	memset(buf, 0, sizeof(buf));
	memcpy(buf, addr->addr, addr->sz);
	sz = addr->sz;
	if ((sz % 2))
		sz++;
	assert(sz <= sizeof(buf));

	for (i = 0; i < sz; i += 2) {
		v = htons(*(uint16_t *)&buf[i]);
		pos += snprintf(b + pos, bsz - pos, "%hx:", v);
	}

	if (sz == 0)
		pos = strlcpy(b, (fill == 0) ? "0:" : "ffff:", bsz);

	assert(pos > 1);
	b[--pos] = '\0';

	if (addr->sz == 16)
		return;
	snprintf(b + pos, bsz - pos, "/%zu", addr->sz * 8 - addr->unused);
}

/*
 * Convert a ip_addr into a NUL-terminated CIDR notation string.
 * The size of the buffer must be at least 64.
 * The AFI must be 1 (IPv4) or 2 (IPv6).
 */
void
ip_addr_print(const struct ip_addr *addr,
	uint16_t afi, char *buf, size_t bufsz)
{

	if (afi == 1)
		ip4_addr2str(addr, buf, bufsz, 0);
	else
		ip6_addr2str(addr, buf, bufsz, 0);
}

/*
 * Convert a ip_addr into a NUL-terminated CIDR notation string.
 * The size of the buffer must be at least 64.
 * The AFI must be 1 (IPv4) or 2 (IPv6).
 */
void
ip_addr_range_print(const struct ip_addr *addr,
	uint16_t afi, char *buf, size_t bufsz, int min)
{

	if (afi == 1)
		ip4_addr2str(addr, buf, bufsz, min ? 0 : 1);
	else
		ip6_addr2str(addr, buf, bufsz, min ? 0 : 1);
}

/*
 * Serialise an ip_addr for sending over the wire.
 * Matched with ip_addr_read().
 */
void
ip_addr_buffer(char **b, size_t *bsz,
	size_t *bmax, const struct ip_addr *p)
{

	io_simple_buffer(b, bsz, bmax, &p->sz, sizeof(size_t));
	assert(p->sz <= 16);
	io_simple_buffer(b, bsz, bmax, p->addr, p->sz);
	io_simple_buffer(b, bsz, bmax, &p->unused, sizeof(long));
}

/*
 * Serialise an ip_addr_range for sending over the wire.
 * Matched with ip_addr_range_read().
 */
void
ip_addr_range_buffer(char **b, size_t *bsz,
	size_t *bmax, const struct ip_addr_range *p)
{

	ip_addr_buffer(b, bsz, bmax, &p->min);
	ip_addr_buffer(b, bsz, bmax, &p->max);
}

/*
 * Read an ip_addr from the wire.
 * Matched with ip_addr_buffer().
 */
void
ip_addr_read(int fd, struct ip_addr *p)
{

	io_simple_read(fd, &p->sz, sizeof(size_t));
	assert(p->sz <= 16);
	io_simple_read(fd, p->addr, p->sz);
	io_simple_read(fd, &p->unused, sizeof(long));
}

/*
 * Read an ip_addr_range from the wire.
 * Matched with ip_addr_range_buffer().
 */
void
ip_addr_range_read(int fd, struct ip_addr_range *p)
{

	ip_addr_read(fd, &p->min);
	ip_addr_read(fd, &p->max);
}
