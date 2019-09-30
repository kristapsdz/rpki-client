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

#include <assert.h>
#include <err.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include "asn1.h"
#include "extern.h"

/*
 * Parse results and data of the manifest file.
 */
struct	parse {
	const char	*fn; /* manifest file name */
	struct mft	*res; /* result object */
};

/*
 * Parse an individual "FileAndHash", RFC 6486, sec. 4.2.
 * Return zero on failure, non-zero on success.
 */
static int
mft_parse_filehash(struct parse *p, const ASN1_OCTET_STRING *os)
{
	const ASN1_SEQUENCE_ANY *seq;
	const ASN1_TYPE		*file, *hash;
	char			*fn = NULL;
	const unsigned char	*d = os->data;
	size_t			 dsz = os->length, sz;
	int			 rc = 0;
	struct mftfile		*fent;

	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		cryptowarnx("%s: RFC 6486 section 4.2.1: FileAndHash: "
		    "failed ASN.1 sequence parse", p->fn);
		goto out;
	} else if (sk_ASN1_TYPE_num(seq) != 2) {
		warnx("%s: RFC 6486 section 4.2.1: FileAndHash: "
		    "want 2 elements, have %d", p->fn,
		    sk_ASN1_TYPE_num(seq));
		goto out;
	}

	/* First is the filename itself. */

	file = sk_ASN1_TYPE_value(seq, 0);
	if (file->type != V_ASN1_IA5STRING) {
		warnx("%s: RFC 6486 section 4.2.1: FileAndHash: "
		    "want ASN.1 IA5 string, have %s (NID %d)",
		    p->fn, ASN1_tag2str(file->type), file->type);
		goto out;
	}
	fn = strndup((const char *)file->value.ia5string->data,
	    file->value.ia5string->length);
	if (fn == NULL)
		err(EXIT_FAILURE, NULL);

	/*
	 * Make sure we're just a pathname and either an ROA or CER.
	 * I don't think that the RFC specifically mentions this, but
	 * it's in practical use and would really screw things up
	 * (arbitrary filenames) otherwise.
	 */

	if (strchr(fn, '/') != NULL) {
		warnx("%s: path components disallowed in filename: %s",
		    p->fn, fn);
		goto out;
	} else if ((sz = strlen(fn)) <= 4) {
		warnx("%s: filename must be large enough for suffix part: %s",
		    p->fn, fn);
		goto out;
	}

	if (strcasecmp(fn + sz - 4, ".roa") &&
	    strcasecmp(fn + sz - 4, ".crl") &&
	    strcasecmp(fn + sz - 4, ".cer")) {
		free(fn);
		fn = NULL;
		rc = 1;
		goto out;
	}

	/* Now hash value. */

	hash = sk_ASN1_TYPE_value(seq, 1);
	if (hash->type != V_ASN1_BIT_STRING) {
		warnx("%s: RFC 6486 section 4.2.1: FileAndHash: "
		    "want ASN.1 bit string, have %s (NID %d)",
		    p->fn, ASN1_tag2str(hash->type), hash->type);
		goto out;
	}

	if (hash->value.bit_string->length != SHA256_DIGEST_LENGTH) {
		warnx("%s: RFC 6486 section 4.2.1: hash: "
		    "invalid SHA256 length, have %d",
		    p->fn, hash->value.bit_string->length);
		goto out;
	}

	/* Insert the filename and hash value. */

	p->res->files = reallocarray(p->res->files, p->res->filesz + 1,
	    sizeof(struct mftfile));
	if (p->res->files == NULL)
		err(EXIT_FAILURE, NULL);

	fent = &p->res->files[p->res->filesz++];
	memset(fent, 0, sizeof(struct mftfile));

	fent->file = fn;
	fn = NULL;
	memcpy(fent->hash, hash->value.bit_string->data, SHA256_DIGEST_LENGTH);

	rc = 1;
out:
	free(fn);
	sk_ASN1_TYPE_pop_free(seq, ASN1_TYPE_free);
	return rc;
}

/*
 * Parse the "FileAndHash" sequence, RFC 6486, sec. 4.2.
 * Return zero on failure, non-zero on success.
 */
static int
mft_parse_flist(struct parse *p, const ASN1_OCTET_STRING *os)
{
	ASN1_SEQUENCE_ANY	*seq;
	const ASN1_TYPE		*t;
	const unsigned char	*d = os->data;
	size_t			 dsz = os->length;
	int			 i, rc = 0;

	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		cryptowarnx("%s: RFC 6486 section 4.2: fileList: "
		    "failed ASN.1 sequence parse", p->fn);
		goto out;
	}

	for (i = 0; i < sk_ASN1_TYPE_num(seq); i++) {
		t = sk_ASN1_TYPE_value(seq, i);
		if (t->type != V_ASN1_SEQUENCE) {
			warnx("%s: RFC 6486 section 4.2: fileList: "
			    "want ASN.1 sequence, have %s (NID %d)",
			    p->fn, ASN1_tag2str(t->type), t->type);
			goto out;
		} else if (!mft_parse_filehash(p, t->value.octet_string))
			goto out;
	}

	rc = 1;
out:
	sk_ASN1_TYPE_pop_free(seq, ASN1_TYPE_free);
	return rc;
}

/*
 * Handle the eContent of the manifest object, RFC 6486 sec. 4.2.
 * Returns <0 on failure, 0 on stale, >0 on success.
 */
static int
mft_parse_econtent(const unsigned char *d, size_t dsz, struct parse *p, int force)
{
	ASN1_SEQUENCE_ANY	*seq;
	const ASN1_TYPE		*t;
	struct tm			tm;
	int			 i, rc = -1;
	time_t			 this, next, now = time(NULL);
	char			 buf[64];
	char			 caThis[64], caNow[64], caNext[64];

	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		cryptowarnx("%s: RFC 6486 section 4.2: Manifest: "
		    "failed ASN.1 sequence parse", p->fn);
		goto out;
	}

	/* The version is optional. */

	if (sk_ASN1_TYPE_num(seq) != 5 &&
	    sk_ASN1_TYPE_num(seq) != 6) {
		warnx("%s: RFC 6486 section 4.2: Manifest: "
		    "want 5 or 6 elements, have %d", p->fn,
		    sk_ASN1_TYPE_num(seq));
		goto out;
	}

	/* Start with optional version. */

	i = 0;
	if (sk_ASN1_TYPE_num(seq) == 6) {
		t = sk_ASN1_TYPE_value(seq, i++);
		if (t->type != V_ASN1_INTEGER) {
			warnx("%s: RFC 6486 section 4.2.1: version: "
			    "want ASN.1 integer, have %s (NID %d)",
			    p->fn, ASN1_tag2str(t->type), t->type);
			goto out;
		}
	}

	/* Now the manifest sequence number. */

	t = sk_ASN1_TYPE_value(seq, i++);
	if (t->type != V_ASN1_INTEGER) {
		warnx("%s: RFC 6486 section 4.2.1: manifestNumber: "
		    "want ASN.1 integer, have %s (NID %d)",
		    p->fn, ASN1_tag2str(t->type), t->type);
		goto out;
	}
	p->res->manifestNumber = ASN1_INTEGER_get(t->value.integer);

	/*
	 * Timestamps: this and next update time.
	 * Validate that the current date falls into this interval.
	 * This is required by section 4.4, (3).
	 * If we're after the given date, then the MFT is stale.
	 * This is made super complicated because it usees OpenSSL's
	 * ASN1_GENERALIZEDTIME instead of ASN1_TIME, which we could
	 * compare against the current time trivially.
	 */

	t = sk_ASN1_TYPE_value(seq, i++);
	if (t->type != V_ASN1_GENERALIZEDTIME) {
		warnx("%s: RFC 6486 section 4.2.1: thisUpdate: "
		    "want ASN.1 generalised time, have %s (NID %d)",
		    p->fn, ASN1_tag2str(t->type), t->type);
		goto out;
	}

	tm = asn1Time2Time(t->value.generalizedtime);
	this = mktime(&tm);

	t = sk_ASN1_TYPE_value(seq, i++);
	if (t->type != V_ASN1_GENERALIZEDTIME) {
		warnx("%s: RFC 6486 section 4.2.1: nextUpdate: "
		    "want ASN.1 generalised time, have %s (NID %d)",
		    p->fn, ASN1_tag2str(t->type), t->type);
		goto out;
	}
	tm = asn1Time2Time(t->value.generalizedtime);
	next = mktime(&tm);

	strftime(caThis, sizeof(caThis)-1, "%Y-%m-%d %H:%M:%S", localtime(&this));
	strftime(caNext, sizeof(caNext)-1, "%Y-%m-%d %H:%M:%S", localtime(&next));
	strftime(caNow, sizeof(caNow)-1, "%Y-%m-%d %H:%M:%S", localtime(&now));

	memcpy(&p->res->thisUpdate, &this, sizeof (time_t));
	memcpy(&p->res->nextUpdate, &next, sizeof (time_t));

	if (this >= next) {
		warnx("%s: bad update interval [%s] >= [%s]", p->fn, caThis, caNext);
		goto out;
	} else if (now < this) {
		warnx("%s: before date interval (clock drift?) [%s] < [%s]", p->fn, caNow, caThis);
		goto out;
	} else if (now >= next) {
		ctime_r(&next, buf);
		buf[strlen(buf) - 1] = '\0';
		if (!force) {
			if (verbose > 0)
				warnx("%s: stale: expired %s", p->fn, buf);
			rc = 0;
			goto out;
		}
		if (verbose > 0)
			warnx("%s: stale: expired %s (ignoring)", p->fn, buf);
	}

	/* File list algorithm. */

	t = sk_ASN1_TYPE_value(seq, i++);
	if (t->type != V_ASN1_OBJECT) {
		warnx("%s: RFC 6486 section 4.2.1: fileHashAlg: "
		    "want ASN.1 object time, have %s (NID %d)",
		    p->fn, ASN1_tag2str(t->type), t->type);
		goto out;
	} else if (OBJ_obj2nid(t->value.object) != NID_sha256) {
		warnx("%s: RFC 6486 section 4.2.1: fileHashAlg: "
		    "want SHA256 object, have %s (NID %d)", p->fn,
		    ASN1_tag2str(OBJ_obj2nid(t->value.object)),
		    OBJ_obj2nid(t->value.object));
		goto out;
	}

	/* Now the sequence. */

	t = sk_ASN1_TYPE_value(seq, i++);
	if (t->type != V_ASN1_SEQUENCE) {
		warnx("%s: RFC 6486 section 4.2.1: fileList: "
		    "want ASN.1 sequence, have %s (NID %d)",
		    p->fn, ASN1_tag2str(t->type), t->type);
		goto out;
	} else if (!mft_parse_flist(p, t->value.octet_string))
		goto out;

	rc = 1;
out:
	sk_ASN1_TYPE_pop_free(seq, ASN1_TYPE_free);
	return rc;
}

/*
 * Parse the objects that have been published in the manifest.
 * This conforms to RFC 6486.
 * Note that if the MFT is stale, all referenced objects are stripped
 * from the parsed content.
 * The MFT content is otherwise returned.
 */
struct mft *
mft_parse(X509 **x509, const char *fn, int force)
{
	struct parse	 p;
	int		 c, rc = 0;
	size_t		 i, cmsz;
	unsigned char	*cms;
	ASN1_TIME *t;
	struct tm		tm;
	time_t	tt;

	memset(&p, 0, sizeof(struct parse));
	p.fn = fn;

	cms = cms_parse_validate(x509, fn, "1.2.840.113549.1.9.16.1.26",
	    NULL, &cmsz);
	if (cms == NULL)
		return NULL;
	assert(*x509 != NULL);

	if ((p.res = calloc(1, sizeof(struct mft))) == NULL)
		err(EXIT_FAILURE, NULL);
	if ((p.res->file = strdup(fn)) == NULL)
		err(EXIT_FAILURE, NULL);
	if (!x509_get_ski_aki(*x509, fn, &p.res->ski, &p.res->aki))
		goto out;

	/*
	 * If we're stale, then remove all of the files that the MFT
	 * references as well as marking it as stale.
	 */

	if ((c = mft_parse_econtent(cms, cmsz, &p, force)) == 0) {
		/*
		 * FIXME: it should suffice to just mark this as stale
		 * and have the logic around mft_read() simply ignore
		 * the contents of stale entries, just like it does for
		 * invalid ROAs or certificates.
		 */

		p.res->stale = 1;
		if (p.res->files != NULL)
			for (i = 0; i < p.res->filesz; i++)
				free(p.res->files[i].file);
		free(p.res->files);
		p.res->filesz = 0;
		p.res->files = NULL;
	} else if (c == -1)
		goto out;

    t = X509_get_notBefore(*x509);
	tm = asn1Time2Time(t);
	tt = mktime(&tm);
    memcpy(&p.res->notBefore, &tt, sizeof (time_t));

    t = X509_get_notAfter(*x509);
	tm = asn1Time2Time(t);
	tt = mktime(&tm);
    memcpy(&p.res->notAfter, &tt, sizeof (time_t));

	rc = 1;
out:
	if (rc == 0) {
		mft_free(p.res);
		p.res = NULL;
		X509_free(*x509);
		*x509 = NULL;
	}
	free(cms);
	return p.res;
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

	if (p->files != NULL)
		for (i = 0; i < p->filesz; i++)
			free(p->files[i].file);

	free(p->aki);
	free(p->ski);
	free(p->file);
	free(p->files);
	free(p);
}

/*
 * Serialise MFT parsed content into the given buffer.
 * See mft_read() for the other side of the pipe.
 */
void
mft_buffer(char **b, size_t *bsz, size_t *bmax, const struct mft *p)
{
	size_t		 i;

	io_simple_buffer(b, bsz, bmax, &p->stale, sizeof(int));
	io_str_buffer(b, bsz, bmax, p->file);
	io_simple_buffer(b, bsz, bmax, &p->filesz, sizeof(size_t));

	for (i = 0; i < p->filesz; i++) {
		io_str_buffer(b, bsz, bmax, p->files[i].file);
		io_simple_buffer(b, bsz, bmax,
			p->files[i].hash, SHA256_DIGEST_LENGTH);
	}

	io_str_buffer(b, bsz, bmax, p->aki);
	io_str_buffer(b, bsz, bmax, p->ski);
}

/*
 * Read an MFT structure from the file descriptor.
 * Result must be passed to mft_free().
 */
struct mft *
mft_read(int fd)
{
	struct mft	*p = NULL;
	size_t		 i;

	if ((p = calloc(1, sizeof(struct mft))) == NULL)
		err(EXIT_FAILURE, NULL);

	io_simple_read(fd, &p->stale, sizeof(int));
	io_str_read(fd, &p->file);
	io_simple_read(fd, &p->filesz, sizeof(size_t));

	if ((p->files = calloc(p->filesz, sizeof(struct mftfile))) == NULL)
		err(EXIT_FAILURE, NULL);

	for (i = 0; i < p->filesz; i++) {
		io_str_read(fd, &p->files[i].file);
		io_simple_read(fd, p->files[i].hash, SHA256_DIGEST_LENGTH);
	}

	io_str_read(fd, &p->aki);
	io_str_read(fd, &p->ski);
	return p;
}
