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
