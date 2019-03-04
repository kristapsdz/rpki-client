#include <assert.h>
#include <err.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include "extern.h"

/*
 * Parse results and data of the manifest file.
 */
struct	parse {
	const char	*fn; /* manifest file name */
	int		 verbose; /* parse verbosity */
	struct mft	*res; /* result object */
};

/* 
 * Wrap around the existing log macros. 
 * Do this to pass the "verbose" variable into the log.
 */

#define MFT_WARNX(_p, _fmt, ...) \
	WARNX((_p)->verbose, (_fmt), ##__VA_ARGS__)
#define MFT_WARNX1(_p, _fmt, ...) \
	WARNX1((_p)->verbose, (_fmt), ##__VA_ARGS__)
#define MFT_LOG(_p, _fmt, ...) \
	LOG((_p)->verbose, (_fmt), ##__VA_ARGS__)
#define MFT_CRYPTOX(_p, _fmt, ...) \
	CRYPTOX((_p)->verbose, (_fmt), ##__VA_ARGS__)

/*
 * Convert from the ASN.1 generalised time to a time_t.
 * Return the time_t or -1 on failure.
 */
static time_t
gentime2time(struct parse *p, const ASN1_GENERALIZEDTIME *t)
{
	BIO		*mem;
	char		*pp;
	char		 buf[64];
	long		 len;
	struct tm	 tm;

	if ((mem = BIO_new(BIO_s_mem())) == NULL) {
		MFT_WARNX(p, "BIO_new");
		return -1;
	} else if (!ASN1_GENERALIZEDTIME_print(mem, t)) {
		MFT_WARNX(p, "ASN1_GENERALIZEDTIME_print");
		BIO_free(mem);
		return -1;
	}

	/* 
	 * The manpage says nothing about being NUL terminated and
	 * strptime(3) needs a string.
	 * So convert into a static buffer of decent size and NUL
	 * terminate in that way.
	 */

	len = BIO_get_mem_data(mem, &pp);
	if (len < 0 || (size_t)len > sizeof(buf) - 1) {
		MFT_WARNX(p, "ASN1_GENERALIZEDTIME_print: too long");
		BIO_free(mem);
		return -1;
	}

	memcpy(buf, pp, len);
	buf[len] = '\0';
	BIO_free(mem);

	if (strptime(buf, "%b %d %T %Y %Z", &tm) == NULL) {
		MFT_WARNX(p, "%s: strptime", buf);
		return -1;
	}

	return mktime(&tm);
}

/*
 * Parse the "FileAndHash" sequence, RFC 6486, sec. 4.2.
 */
static int
mft_parse_flist(struct parse *p, const ASN1_OCTET_STRING *os)
{
	const ASN1_SEQUENCE_ANY *seq, *sseq = NULL;
	const ASN1_TYPE		*type, *file, *hash;
	const unsigned char     *d;
	size_t		         dsz, sz;
	int		 	 i, rc = 0;
	struct mftfile		*fent;

	d = os->data;
	dsz = os->length;
	seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz);
	if (seq == NULL) {
		MFT_CRYPTOX(p, "%s: want ASN.1 sequence", p->fn);
		goto out;
	} 

	for (i = 0; i < sk_ASN1_TYPE_num(seq); i++) {
		type = sk_ASN1_TYPE_value(seq, i);
		if (type->type != V_ASN1_SEQUENCE) {
			MFT_WARNX(p, "%s: want ASN.1 sequence", p->fn);
			goto out;
		}

		d = type->value.octet_string->data;
		dsz = type->value.octet_string->length;
		sseq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz);
		if (sseq == NULL) {
			MFT_CRYPTOX(p, "%s: want ASN.1 sequence", p->fn);
			goto out;
		} else if (sk_ASN1_TYPE_num(sseq) != 2) {
			MFT_WARNX(p, "%s: want only two elements", p->fn);
			goto out;
		}

		file = sk_ASN1_TYPE_value(sseq, 0);
		hash = sk_ASN1_TYPE_value(sseq, 1);

		/* First is the filename itself. */

		if (file->type != V_ASN1_IA5STRING) {
			MFT_WARNX(p, "%s: want ASN.1 IA5string", p->fn);
			goto out;
		} else if (hash->type != V_ASN1_BIT_STRING) {
			MFT_WARNX(p, "%s: want ASN.1 bitstring", p->fn);
			goto out;
		}

		/* Verify hash length. */
		
		if (hash->value.bit_string->length != SHA256_DIGEST_LENGTH) {
			MFT_WARNX(p, "%s: invalid SHA256 length", p->fn);
			goto out;
		}

		/* Insert the filename and hash value. */

		p->res->files = reallocarray
			(p->res->files, 
			 p->res->filesz + 1,
			 sizeof(struct mftfile));
		if (p->res->files == NULL)
			err(EXIT_FAILURE, NULL);

		fent = &p->res->files[p->res->filesz++];
		memset(fent, 0, sizeof(struct mftfile));

		fent->file = strndup
			(file->value.ia5string->data, 
			 file->value.ia5string->length);
		if (fent->file == NULL)
			err(EXIT_FAILURE, NULL);
		memcpy(fent->hash, hash->value.bit_string->data,
			SHA256_DIGEST_LENGTH);

		sk_ASN1_TYPE_free(sseq);
		sseq = NULL;

		/* 
		 * Make sure we're just a pathname and either a CRL,
		 * ROA, or CER.
		 */

		if (strchr(fent->file, '/') != NULL) {
			MFT_WARNX(p, "%s: has path: %s", p->fn, fent->file);
			goto out;
		} else if ((sz = strlen(fent->file)) <= 4) {
			MFT_WARNX(p, "%s: too short: %s", p->fn, fent->file);
			goto out;
		}

		if (strcasecmp(fent->file + sz - 4, ".roa") &&
		    strcasecmp(fent->file + sz - 4, ".cer") &&
		    strcasecmp(fent->file + sz - 4, ".crl")) {
			MFT_WARNX(p, "%s: bad suffix: %s", p->fn, fent->file);
			goto out;
		}
	}

	rc = 1;
out:
	sk_ASN1_TYPE_free(sseq);
	sk_ASN1_TYPE_free(seq);
	return rc;
}

/*
 * Handle the eContent of the manifest object, RFC 6486 sec. 4.2.
 * Returns <0 on failure, 0 on stale, >0 on success.
 */
static int
mft_parse_econtent(const ASN1_OCTET_STRING *os, struct parse *p)
{
	const ASN1_SEQUENCE_ANY *seq;
	const unsigned char     *d;
	size_t		         dsz;
	const ASN1_TYPE	        *ver, *mftnum, *thisup, *nextup,
			        *falg, *fl;
	int		         i, rc = -1;
	time_t			 this, next, now = time(NULL);

	d = os->data;
	dsz = os->length;

	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		MFT_CRYPTOX(p, "%s: want ASN.1 sequence", p->fn);
		goto out;
	} 

	/* 
	 * We're supposed to have six elements.
	 * But it appears that some manifests don't have the version.
	 */

	if (sk_ASN1_TYPE_num(seq) != 5 &&
	    sk_ASN1_TYPE_num(seq) != 6) {
		MFT_WARNX(p, "%s: want 5 or 6 elements", p->fn);
		goto out;
	}

	/* Start with optional version. */

	i = 0;
	if (sk_ASN1_TYPE_num(seq) == 6) {
		ver = sk_ASN1_TYPE_value(seq, i++);
		if (ver->type != V_ASN1_INTEGER) {
			MFT_WARNX(p, "%s: want ASN.1 integer", p->fn);
			goto out;
		} 
	} else
		ver = NULL;

	/* Now the manifest sequence number. */

	mftnum = sk_ASN1_TYPE_value(seq, i++);
	if (mftnum->type != V_ASN1_INTEGER) {
		MFT_WARNX(p, "%s: want ASN.1 integer", p->fn);
		goto out;
	}

	/* 
	 * Timestamps: this and next update time.
	 * Validate that the current date falls into this interval.
	 * This is required by section 4.4, (3).
	 * If we're after the given date, then the MFT is stale.
	 */

	thisup = sk_ASN1_TYPE_value(seq, i++);
	nextup = sk_ASN1_TYPE_value(seq, i++);
	if (thisup->type != V_ASN1_GENERALIZEDTIME &&
	    nextup->type != V_ASN1_GENERALIZEDTIME) {
		MFT_WARNX(p, "%s: want ASN.1 general time", p->fn);
		goto out;
	}

	this = gentime2time(p, thisup->value.generalizedtime);
	next = gentime2time(p, nextup->value.generalizedtime);

	if (this < 0 || next < 0) {
		MFT_WARNX(p, "%s: bad date", p->fn);
		goto out;
	} else if (this >= next) {
		MFT_WARNX(p, "%s: bad update interval", p->fn);
		goto out;
	} else if (now < this) {
		MFT_WARNX(p, "%s: before date "
			"interval (clock drift?)", p->fn);
		goto out;
	} else if (now >= next) {
		MFT_WARNX(p, "%s: after date interval (stale)", p->fn);
		rc = 0;
		goto out;
	}

	/* File list algorithm. */

	falg = sk_ASN1_TYPE_value(seq, i++);
	if (falg->type != V_ASN1_OBJECT) {
		MFT_WARNX(p, "%s: want ASN.1 OID", p->fn);
		goto out;
	} else if (OBJ_obj2nid(falg->value.object) != NID_sha256) {
		MFT_WARNX(p, "%s: want SHA256 hashing", p->fn);
		goto out;
	}

	/* Now the sequence. */

	fl = sk_ASN1_TYPE_value(seq, i++);
	if (fl->type != V_ASN1_SEQUENCE) {
		MFT_WARNX(p, "%s: want ASN.1 sequence", p->fn);
		goto out;
	} else if (!mft_parse_flist(p, fl->value.octet_string)) {
		MFT_WARNX1(p, "mft_parse_flist");
		goto out;
	}

	rc = 1;
out:
	sk_ASN1_TYPE_free(seq);
	return rc;
}

/*
 * Parse the objects that have been published by the authority whose
 * public key is optionally in "pkey".
 * This conforms to RFC 6486.
 * Returns zero on failure, non-zero on success.
 * Note that if the MFT is stale, all referenced objects are stripped
 * from the parsed content.
 * The MFT content is otherwise returned.
 */
struct mft *
mft_parse(int verb, X509 *cacert, const char *fn)
{
	struct parse		 p;
	const ASN1_OCTET_STRING *os;
	int			 rc;
	size_t			 i;

	memset(&p, 0, sizeof(struct parse));
	p.fn = fn;
	p.verbose = verb;

	os = cms_parse_validate(verb, cacert, 
		fn, "1.2.840.113549.1.9.16.1.26", NULL);

	if (os == NULL) {
		MFT_WARNX1(&p, "cms_parse_validate");
		return NULL;
	}

	if ((p.res = calloc(1, sizeof(struct mft))) == NULL)
		err(EXIT_FAILURE, NULL);
	if ((p.res->file = strdup(fn)) == NULL)
		err(EXIT_FAILURE, NULL);
	
	/* 
	 * If we're stale, then simply remove all of the files that the
	 * MFT references and otherwise accept it.
	 */

	if ((rc = mft_parse_econtent(os, &p)) == 0) {
		if (p.res->files != NULL)
			for (i = 0; i < p.res->filesz; i++)
				free(p.res->files[i].file);
		free(p.res->files);
		p.res->filesz = 0;
		p.res->files = NULL;
	}

	if (rc >= 0)
		return p.res;

	MFT_WARNX1(&p, "mft_parse_econtent");
	mft_free(p.res);
	return NULL;
}

/*
 * Free an MFT pointer.
 * Safe to call with NULL.
 */
void
mft_free(struct mft *p)
{
	size_t	 i;

	if (p == NULL)
		return;

	/* We might get our filesz before our file allocation. */

	if (p->files != NULL)
		for (i = 0; i < p->filesz; i++)
			free(p->files[i].file);

	free(p->file);
	free(p->files);
	free(p);
}

/*
 * Serialise MFT parsed content into the given buffer.
 * See mft_read() for the other side of the pipe.
 */
void
mft_buffer(char **b, size_t *bsz, size_t *bmax,
	int verb, const struct mft *p)
{
	size_t		 i;

	str_buffer(b, bsz, bmax, verb, p->file);
	simple_buffer(b, bsz, bmax, &p->filesz, sizeof(size_t));

	for (i = 0; i < p->filesz; i++) {
		str_buffer(b, bsz, bmax, verb, p->files[i].file);
		simple_buffer(b, bsz, bmax,
			p->files[i].hash, SHA256_DIGEST_LENGTH);
	}
}

/*
 * Read an MFT structure from the file descriptor.
 * Result must be passed to mft_free().
 */
struct mft *
mft_read(int fd, int verb)
{
	struct mft 	*p = NULL;
	size_t		 i;

	if ((p = calloc(1, sizeof(struct mft))) == NULL)
		err(EXIT_FAILURE, NULL);

	str_read(fd, verb, &p->file);
	simple_read(fd, verb, &p->filesz, sizeof(size_t));
	
	if ((p->files = calloc(p->filesz, sizeof(struct mftfile))) == NULL)
		err(EXIT_FAILURE, NULL);

	for (i = 0; i < p->filesz; i++) {
		str_read(fd, verb, &p->files[i].file);
		simple_read(fd, verb, p->files[i].hash, SHA256_DIGEST_LENGTH);
	}

	return p;
}
