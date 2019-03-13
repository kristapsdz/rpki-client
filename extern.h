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
#ifndef EXTERN_H
#define EXTERN_H

enum	cert_as_type {
	CERT_AS_ID, /* single identifier */
	CERT_AS_INHERIT, /* inherit from parent */
	CERT_AS_RANGE, /* range of identifiers */
};

/*
 * An AS identifier range.
 */
struct	cert_as_range {
	uint32_t	 min; /* minimum non-zero */
	uint32_t	 max; /* maximum */
};

/*
 * An autonomous system (AS) object.
 */
struct	cert_as {
	enum cert_as_type type; /* type of AS specification */
	union {
		uint32_t id; /* singleton */
		struct cert_as_range range; /* range */
	};
};

/*
 * An IP address as parsed from a RFC 3779 document.
 * This may either be IPv4 or IPv6.
 */
struct	ip_addr {
	size_t		 sz; /* length of valid bytes */
	unsigned char	 addr[16]; /* binary address prefix */
	long		 unused; /* unused bits in last byte */
};

/*
 * An IP address (IPv4 or IPv6) range starting at the minimum and making
 * its way to the maximum.
 */
struct	cert_ip_rng {
	struct ip_addr min; /* minimum ip */
	struct ip_addr max; /* maximum ip */
};

enum	cert_ip_type {
	CERT_IP_ADDR, /* IP address range w/shared prefix */
	CERT_IP_INHERIT, /* inherited IP address */
	CERT_IP_RANGE /* range of IP addresses */
};

/*
 * An IP address range defined by RFC 3779.
 */
struct	cert_ip {
	uint16_t	   afi; /* AFI value (1 or 2) */
	uint8_t		   safi; /* SAFI value (if has_safi) */
	int		   has_safi; /* whether safi is set */
	enum cert_ip_type  type; /* type of IP entry */
	struct cert_ip_rng range; /* range */
};

/*
 * Parsed components of a validated X509 certificate stipulated by RFC
 * 6847 and further (within) by RFC 3779.
 * All AS numbers are guaranteed to be non-overlapping and properly
 * inheriting.
 */
struct	cert {
	struct cert_ip	*ips; /* list of IP address ranges */
	size_t		 ipsz; /* length of "ips" */
	struct cert_as	*as; /* list of AS numbers and ranges */
	size_t		 asz; /* length of "asz" */
	char		*rep; /* CA repository */
	char		*mft; /* manifest (rsync:// uri) */
};

/*
 * The TAL file conforms to RFC 7730.
 * It is the top-level structure of RPKI and defines where we can find
 * certificates for TAs (trust anchors).
 * It also includes the public key for verifying those trust anchor
 * certificates.
 */
struct	tal {
	char		**uri; /* well-formed rsync URIs */
	size_t		  urisz; /* number of URIs */
	unsigned char	 *pkey; /* DER-encoded public key */
	size_t		  pkeysz; /* length of pkey */
};

/*
 * Files specified in an MFT have their bodies hashed with SHA256.
 */
struct	mftfile {
	char		*file; /* filename (CER/ROA/CRL, no path) */
	unsigned char	 hash[SHA256_DIGEST_LENGTH]; /* sha256 of body */
};

/*
 * A manifest, RFC 6486.
 * This consists of a bunch of files found in the same directory as the
 * manifest file.
 */
struct	mft {
	char		*file; /* full path of MFT file */
	struct mftfile	*files; /* file and hash */
	size_t		 filesz; /* number of filenames */
	int		 stale; /* if a stale manifest */
};

struct	roa_ip {
	uint16_t	 afi; /* AFI value (1 or 2) */
	size_t		 maxlength; /* max length or zero */
	struct ip_addr	 addr;
};

/*
 * An ROA, RFC 6482.
 * This consists of the concerned ASID and its IP prefixes.
 */
struct	roa {
	uint32_t	 asid; /* asID of ROA */
	struct roa_ip	*ips; /* IP prefixes */
	size_t		 ipsz; /* number of IP prefixes */
};

/*
 * An authentication tuple.
 * This specifies a public key and a subject key identifier used to
 * verify children nodes in the tree of entities.
 */
struct	auth {
	char		*ski; /* subject key identifier */
	EVP_PKEY	*pkey; /* public key */
	struct cert	*cert; /* owner information */
	size_t		 id; /* self-index */
	size_t		 parent; /* index of parent pair (or self) */
	char		*fn; /* FIXME: debugging */
};

/*
 * Resource types specified by the RPKI profiles.
 * There are others (e.g., gbr, crl) that we don't consider.
 */
enum	rtype {
	RTYPE_EOF = 0,
	RTYPE_TAL,
	RTYPE_MFT,
	RTYPE_ROA,
	RTYPE_CER
};

/* Routines for RPKI entities. */

void		 tal_buffer(char **, size_t *, size_t *, const struct tal *);
void		 tal_free(struct tal *);
struct tal	*tal_parse(const char *);
struct tal	*tal_read(int);

void		 cert_buffer(char **, size_t *, size_t *, const struct cert *);
void		 cert_free(struct cert *);
struct cert	*cert_parse(X509 **, const char *, const unsigned char *);
struct cert	*cert_read(int);

void		 mft_buffer(char **, size_t *, size_t *, const struct mft *);
void		 mft_free(struct mft *);
struct mft 	*mft_parse(X509 **, const char *, int);
struct mft 	*mft_read(int);

void		 roa_buffer(char **, size_t *, size_t *, const struct roa *);
void		 roa_free(struct roa *);
struct roa 	*roa_parse(X509 **, const char *, const unsigned char *);
struct roa	*roa_read(int);

/* Authentication of X509 objects. */

int		 x509_auth_signed_cert(X509 *, const char *,
			struct auth **, size_t *, struct cert *);
int		 x509_auth_signed_mft(X509 *, const char *,
			struct auth **, size_t *, struct mft *);
int		 x509_auth_signed_roa(X509 *, const char *,
			struct auth **, size_t *, struct roa *);
int		 x509_auth_selfsigned_cert(X509 *, const char *,
			struct auth **, size_t *, const unsigned char *,
			size_t, struct cert *);

/* Working with CMS files. */

const ASN1_OCTET_STRING
 		*cms_parse_validate(X509 **, const char *,
			const char *, const unsigned char *);

/* Work with RFC 3779 IP addresses, prefixes, ranges. */

int		 ip_addr_afi_parse(const ASN1_OCTET_STRING *, uint16_t *);
int		 ip_addr_parse(const ASN1_BIT_STRING *, uint16_t, struct ip_addr *);
void		 ip_addr_print(const struct ip_addr *, uint16_t, char *, size_t);
void		 ip_addr_range_print(const struct ip_addr *, uint16_t, char *, size_t, int);
void		 ip_addr_buffer(char **, size_t *, size_t *, const struct ip_addr *);
void	 	 ip_addr_read(int, struct ip_addr *);

/* Work with RFC 3779 AS numbers, ranges. */

int		 as_check_overlap(const struct cert_as *, const char *,
			const struct cert_as *, size_t);
int		 as_check_covered(uint32_t, const struct cert_as *, size_t);

/* Rsync-specific. */

int	 	 rsync_uri_parse(const char **, size_t *,
			const char **, size_t *, const char **, size_t *,
			enum rtype *, const char *);

/* Logging (though really used for OpenSSL errors). */

void		 logx(int, const char *, ...)
			__attribute__((format(printf, 2, 3)));
void		 cryptowarnx(const char *, ...)
			__attribute__((format(printf, 1, 2)));
void		 cryptoerrx(const char *, ...)
			__attribute__((format(printf, 1, 2)))
			__attribute__((noreturn));

/* Functions for moving data between processes. */

void		 io_socket_blocking(int);
void		 io_socket_nonblocking(int);
void		 io_simple_buffer(char **, size_t *, size_t *, const void *, size_t);
void		 io_simple_read(int, void *, size_t);
void		 io_simple_write(int, const void *, size_t);
void		 io_buf_buffer(char **, size_t *, size_t *, const void *, size_t);
void		 io_buf_read_alloc(int, void **, size_t *);
void		 io_buf_write(int, const void *, size_t);
void		 io_str_buffer(char **, size_t *, size_t *, const char *);
void		 io_str_read(int, char **);
void		 io_str_write(int, const char *);

#endif /* ! EXTERN_H */
