#ifndef EXTERN_H
#define EXTERN_H

enum	x509_as_type {
	ASN1_AS_ID,
	ASN1_AS_NULL,
	ASN1_AS_RANGE,
};

/*
 * An AS identifier range.
 */
struct	x509_as_range {
	uint32_t	 min; /* minimum non-zero */
	uint32_t	 max; /* maximum */
};

/*
 * An autonomous system (AS) object.
 */
struct	x509_as {
	int		  rdi; /* routing domain identifier? */
	enum x509_as_type type; /* type of AS specification */
	union {
		uint32_t id; /* singleton */
		struct x509_as_range range; /* range */
	};
};

/*
 * An IP address as parsed from a RFC 3779 document.
 * This may either be IPv4 (4-byte size) or IPv6 (16).
 */
struct	x509_ip_addr {
	size_t		 sz; /* 4 (ipv4) or 16 (ipv6) */
	char		 addr[16]; /* binary address prefix */
	long		 unused; /* unused bits */
};

/*
 * An IP address (IPv4 or IPv6) range starting at the minimum and making
 * its way to the maximum.
 */
struct	x509_ip_rng {
	struct x509_ip_addr min; /* minimum ip */
	struct x509_ip_addr max; /* maximum ip */
};

enum	x509_ip_type {
	ASN1_IP_ADDR, /* IP address range w/shared prefix */
	ASN1_IP_INHERIT, /* inherited IP address */
	ASN1_IP_RANGE /* range of IP addresses */
};
/*
 * An IP address range defined by RFC 3779.
 */
struct	x509_ip {
	uint16_t	   afi; /* AFI value */
	uint8_t		   safi; /* SAFI value (if has_safi) */
	int		   has_safi; /* whether safi is set */
	enum x509_ip_type  type; /* type of IP entry */
	struct x509_ip_rng range; /* range */
};

/*
 * Parsed components of a validated X509 certificate stipulated by RFC
 * 6847 and further (within) by RFC 3779.
 */
struct	cert {
	struct x509_ip	*ips; /* list of IP address ranges */
	size_t		 ipsz; /* length of "ips" */
	struct x509_as	*as; /* list of AS numbers and ranges */
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
};

struct	roa {
	uint32_t	 asid; /* asID of ROA */
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

int		 tal_buffer(char **, size_t *, size_t *, int, const struct tal *);
void		 tal_free(struct tal *);
struct tal	*tal_parse(int, const char *);
struct tal	*tal_read(int, int);

int		 cert_buffer(char **, size_t *, size_t *, int, const struct cert *);
void		 cert_free(struct cert *);
struct cert	*cert_parse(int, X509 *, const char *, const unsigned char *);
struct cert	*cert_read(int, int);

int		 mft_buffer(char **, size_t *, size_t *, int, const struct mft *);
void		 mft_free(struct mft *);
struct mft 	*mft_parse(int, X509 *, const char *);
struct mft 	*mft_read(int, int);

int		 roa_buffer(char **, size_t *, size_t *, int, const struct roa *);
void		 roa_free(struct roa *);
struct roa 	*roa_parse(int, X509 *, const char *, const unsigned char *);
struct roa	*roa_read(int, int);

const ASN1_OCTET_STRING
 		*cms_parse_validate(int, X509 *, const char *,
			const char *, const unsigned char *);
int	 	 rsync_uri_parse(int, const char **, size_t *,
			const char **, size_t *, const char **, size_t *,
			enum rtype *, const char *);
int	 	 rsync_uri_check(int, const char *);
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
int		 socket_blocking(int, int);
int		 socket_nonblocking(int, int);
int		 simple_buffer(char **, size_t *, size_t *, const void *, size_t);
int		 simple_read(int, int, void *, size_t);
int		 simple_write(int, const void *, size_t);
int		 buf_buffer(char **, size_t *, size_t *, int, const void *, size_t);
int		 buf_read_alloc(int, int, void **, size_t *);
int		 buf_write(int, int, const void *, size_t);
int		 str_buffer(char **, size_t *, size_t *, int, const char *);
int		 str_read(int, int, char **);
int		 str_write(int, int, const char *);

__END_DECLS

#endif /* ! EXTERN_H */
