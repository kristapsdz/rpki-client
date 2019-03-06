#ifndef EXTERN_H
#define EXTERN_H

enum	cert_as_type {
	CERT_AS_ID, /* single identifier */
	CERT_AS_NULL, /* inherit from parent */
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
	int		  rdi; /* routing domain identifier? */
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
struct	cert_ip_addr {
	size_t		 sz; /* length of valid bytes */
	char		 addr[16]; /* binary address prefix */
	long		 unused; /* unused bits in last byte */
};

/*
 * An IP address (IPv4 or IPv6) range starting at the minimum and making
 * its way to the maximum.
 */
struct	cert_ip_rng {
	struct cert_ip_addr min; /* minimum ip */
	struct cert_ip_addr max; /* maximum ip */
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
 */
struct	cert {
	struct cert_ip	*ips; /* list of IP address ranges */
	size_t		 ipsz; /* length of "ips" */
	struct cert_as	*as; /* list of AS numbers and ranges */
	size_t		 asz; /* length of "asz" */
	char		*rep; /* CA repository */
	char		*mft; /* manifest (rsync:// uri) */
	char		*ski; /* subject key identifier */
	char		*aki; /* authority key identifier */
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
	uint16_t	    afi; /* AFI value (1 or 2) */
	size_t		    maxlength; /* max length or zero */
	struct cert_ip_addr addr;
};

struct	roa {
	uint32_t	 asid; /* asID of ROA */
	struct roa_ip	*ips;
	size_t		 ipsz;
};

/*
 * Resource types.
 */
enum	rtype {
	RTYPE_EOF = 0,
	RTYPE_TAL,
	RTYPE_MFT,
	RTYPE_ROA,
	RTYPE_CER,
	RTYPE_CRL
};

#define ERR(_fmt, ...) \
	rpki_err(__FILE__, __LINE__, (_fmt), ##__VA_ARGS__)
#define ERRX(_fmt, ...) \
	rpki_errx(__FILE__, __LINE__, (_fmt), ##__VA_ARGS__)
#define CRYPTOX(_v, _fmt, ...) \
	rpki_cryptox((_v), __FILE__, __LINE__, (_fmt), ##__VA_ARGS__)
#define WARN(_fmt, ...) \
	rpki_warn(__FILE__, __LINE__, (_fmt), ##__VA_ARGS__)
#define WARNX(_v, _fmt, ...) \
	rpki_warnx((_v), 0, __FILE__, __LINE__, (_fmt), ##__VA_ARGS__)
#define WARNX1(_v, _fmt, ...) \
	rpki_warnx((_v), 1, __FILE__, __LINE__, (_fmt), ##__VA_ARGS__)
#define LOG(_v, _fmt, ...) \
	rpki_log((_v), __FILE__, __LINE__, (_fmt), ##__VA_ARGS__)

__BEGIN_DECLS

/*
 * Routines for RPKI data files.
 */

void		 tal_buffer(char **, size_t *, size_t *, const struct tal *);
void		 tal_free(struct tal *);
struct tal	*tal_parse(int, const char *);
struct tal	*tal_read(int);

void		 cert_buffer(char **, size_t *, size_t *, const struct cert *);
void		 cert_free(struct cert *);
struct cert	*cert_parse(int, X509 *, const char *, const unsigned char *);
struct cert	*cert_read(int);

void		 mft_buffer(char **, size_t *, size_t *, const struct mft *);
void		 mft_free(struct mft *);
struct mft 	*mft_parse(X509 *, const char *);
struct mft 	*mft_read(int);

void		 roa_buffer(char **, size_t *, size_t *, const struct roa *);
void		 roa_free(struct roa *);
struct roa 	*roa_parse(X509 *, const char *, const unsigned char *);
struct roa	*roa_read(int);

const ASN1_OCTET_STRING
 		*cms_parse_validate(X509 *, const char *,
			const char *, const unsigned char *);
int		 ip_addrfamily(const ASN1_OCTET_STRING *, uint16_t *);
int		 ip_addr(const ASN1_BIT_STRING *, uint16_t, struct cert_ip_addr *);
int	 	 rsync_uri_parse(const char **, size_t *,
			const char **, size_t *, const char **, size_t *,
			enum rtype *, const char *);
void		 rpki_log_open(void);
void		 rpki_log_close(void);
void		 rpki_err(const char *, size_t, const char *, ...)
			__attribute__((format(printf, 3, 4)))
			__attribute__((noreturn));
void		 rpki_errx(const char *, size_t, const char *, ...)
			__attribute__((format(printf, 3, 4)))
			__attribute__((noreturn));
void		 rpki_warn(const char *, size_t, const char *, ...)
			__attribute__((format(printf, 3, 4)));
void		 rpki_warnx(int, int, const char *, size_t, const char *, ...)
			__attribute__((format(printf, 5, 6)));
void		 rpki_log(int, const char *, size_t, const char *, ...)
			__attribute__((format(printf, 4, 5)));
void		 rpki_cryptox(int, const char *, size_t, const char *, ...)
			__attribute__((format(printf, 4, 5)));
void		 cryptowarnx(const char *, ...)
			__attribute__((format(printf, 1, 2)));
void		 cryptoerrx(const char *, ...)
			__attribute__((format(printf, 1, 2)))
			__attribute__((noreturn));
void		 socket_blocking(int);
void		 socket_nonblocking(int);
void		 simple_buffer(char **, size_t *, size_t *, const void *, size_t);
void		 simple_read(int, void *, size_t);
void		 simple_write(int, const void *, size_t);
void		 buf_buffer(char **, size_t *, size_t *, const void *, size_t);
void		 buf_read_alloc(int, void **, size_t *);
void		 buf_write(int, const void *, size_t);
void		 str_buffer(char **, size_t *, size_t *, const char *);
void		 str_read(int, char **);
void		 str_write(int, const char *);

__END_DECLS

#endif /* ! EXTERN_H */
