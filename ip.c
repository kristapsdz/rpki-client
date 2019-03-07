#include <sys/socket.h>

#include <arpa/inet.h>
#include <assert.h>
#include <err.h>
#include <inttypes.h>
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
ip_addrfamily(const ASN1_OCTET_STRING *p, uint16_t *afi)
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
 * Parse an IP address, RFC 3779, 2.2.3.8.
 * Return zero on failure, non-zero on success.
 */
int
ip_addr(const ASN1_BIT_STRING *p,
	uint16_t afi, struct cert_ip_addr *addr)
{
	long	 unused = 0;

	/* Weird OpenSSL-ism to get unused bit count. */

	if ((ASN1_STRING_FLAG_BITS_LEFT & p->flags))
		unused = ~ASN1_STRING_FLAG_BITS_LEFT & p->flags;

	/* Limit possible sizes of addresses. */

	if ((afi == 1 && p->length > 4) ||
	    (afi == 2 && p->length > 16))
		return 0;

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
ip4_addr2str(const struct cert_ip_addr *addr,
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
ip6_addr2str(const struct cert_ip_addr *addr,
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
 * Convert a cert_ip_addr into a NUL-terminated CIDR notation string.
 * The size of the buffer must be at least 64.
 * The AFI must be 1 (IPv4) or 2 (IPv6).
 */
void
ip_addr2str(const struct cert_ip_addr *addr,
	uint16_t afi, char *buf, size_t bufsz)
{

	if (afi == 1)
		ip4_addr2str(addr, buf, bufsz, 0);
	else
		ip6_addr2str(addr, buf, bufsz, 0);
}

/*
 * Convert a cert_ip_addr into a NUL-terminated CIDR notation string.
 * The size of the buffer must be at least 64.
 * The AFI must be 1 (IPv4) or 2 (IPv6).
 */
void
ip_addrrange2str(const struct cert_ip_addr *addr,
	uint16_t afi, char *buf, size_t bufsz, int min)
{

	if (afi == 1)
		ip4_addr2str(addr, buf, bufsz, min ? 0 : 1);
	else
		ip6_addr2str(addr, buf, bufsz, min ? 0 : 1);
}
