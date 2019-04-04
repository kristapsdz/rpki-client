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
 * Parse an IP address family.
 * This is defined in different places in the ROA/X509 standards, but
 * it's the same thing.
 * We prohibit all but IPv4 and IPv6, without SAFI.
 * Return zero on failure, non-zero on success.
 */
int
ip_addr_afi_parse(const char *fn,
	const ASN1_OCTET_STRING *p, enum afi *afi)
{
	char	 buf[2];
	short	 v;

	if (p->length == 0 || p->length > 3) {
		warnx("%s: invalid field length, "
			"want 1--3, have %d", fn, p->length);
		return 0;
	}

	memcpy(buf, p->data, sizeof(uint16_t));
	v = ntohs(*(uint16_t *)buf);

	/* Only accept IPv4 and IPv6 AFIs. */

	if (v != 1 && v != 2) {
		warnx("%s: only AFI for IPV4 (1) and "
			"IPV6 (2) allowed: have %hd", fn, v);
		return 0;
	}

	/* Disallow the optional SAFI. */

	if (p->length == 3) {
		warnx("%s: SAFI not allowed", fn);
		return 0;
	}

	*afi = (v == 1) ? AFI_IPV4 : AFI_IPV6;
	return 1;
}

/*
 * See if a given IP prefix is covered by the IP prefixes or ranges
 * specified in the "ips" array.
 * Return zero if there is no cover, non-zero if there is.
 */
int
ip_addr_check_covered(const struct roa_ip *ip,
	const struct cert_ip *ips, size_t ipsz)
{

	/* TODO */

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
	size_t	 i;
	int	 inherit_v4 = 0, inherit_v6 = 0,
		 has_v4 = 0, has_v6 = 0;

	/* 
	 * FIXME: cache this by having a flag on the cert_ip, else we're
	 * going to need to do a lot of scanning for big allocations.
	 */

	for (i = 0; i < ipsz; i++) 
		if (ips[i].type == CERT_IP_INHERIT) {
			if (ips[i].afi == AFI_IPV4)
				inherit_v4 = 1;
			else
				inherit_v6 = 1;
		} else {
			if (ips[i].afi == AFI_IPV4)
				has_v4 = 1;
			else
				has_v6 = 1;
		}

	/* Disallow multiple inheritence per type. */

	if ((inherit_v4 && ip->afi == AFI_IPV4) ||
	    (inherit_v6 && ip->afi == AFI_IPV6) ||
	    (has_v4 && ip->afi == AFI_IPV4 && 
	     ip->type == CERT_IP_INHERIT) ||
	    (has_v6 && ip->afi == AFI_IPV6 && 
	     ip->type == CERT_IP_INHERIT)) {
		warnx("%s: RFC 3779 section 2.2.3.5: cannot have "
			"multiple inheritence or inheritence and "
			"addresses of the same class", fn);
		return 0;
	}

	/* TODO: more. */

	return 1;
}

/*
 * Parse an IP address, RFC 3779, 2.2.3.8.
 * Return zero on failure, non-zero on success.
 */
int
ip_addr_parse(const ASN1_BIT_STRING *p,
	enum afi afi, const char *fn, struct ip_addr *addr)
{
	long	 unused = 0;

	/* Weird OpenSSL-ism to get unused bit count. */

	if ((ASN1_STRING_FLAG_BITS_LEFT & p->flags))
		unused = ~ASN1_STRING_FLAG_BITS_LEFT & p->flags;

	if (unused < 0) {
		warnx("%s: RFC 3779 section 2.2.3.8: unused "
			"bit count must be non-negative", fn);
		return 0;
	}

	/* Limit possible sizes of addresses. */

	if ((afi == AFI_IPV4 && p->length > 4) ||
	    (afi == AFI_IPV6 && p->length > 16)) {
		warnx("%s: RFC 3779 section 2.2.3.8: "
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
	enum afi afi, char *buf, size_t bufsz)
{

	if (afi == AFI_IPV4)
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
	enum afi afi, char *buf, size_t bufsz, int min)
{

	if (afi == AFI_IPV4)
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
	io_simple_buffer(b, bsz, bmax, &p->unused, sizeof(size_t));
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
	io_simple_read(fd, &p->unused, sizeof(size_t));
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
