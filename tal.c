#include <netinet/in.h>

#include <assert.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/x509.h>

#include "extern.h"

/*
 * Inner function for parsing RFC 7730 from a file stream.
 * Returns a valid pointer on success, NULL otherwise.
 * The pointer must be freed with tal_free().
 */
static struct tal *
tal_parse_stream(int verb, const char *fn, FILE *f)
{
	void		*pp;
	char		*line = NULL, *b64 = NULL;
	size_t		 sz, b64sz = 0, linesize = 0, lineno = 0;
	ssize_t		 linelen, ssz;
	int		 rc = 0;
	struct tal	*tal = NULL;
	enum rtype	 rp;

	if ((tal = calloc(1, sizeof(struct tal))) == NULL) {
		WARN("calloc");
		return NULL;
	}

	/* Begin with the URI section. */

	while ((linelen = getline(&line, &linesize, f)) != -1) {
		lineno++;
		assert(linelen);
		assert(line[linelen - 1] == '\n');
		line[--linelen] = '\0';
		if (linelen && line[linelen - 1] == '\r') 
			line[--linelen] = '\0';

		/* Zero-length line is end of section. */

		if (linelen == 0)
			break;

		/* Append to list of URIs. */

		pp = reallocarray(tal->uri, 
			tal->urisz + 1, sizeof(char *));
		if (pp == NULL) {
			WARN("reallocarray");
			goto out;
		}
		tal->uri = pp;
		tal->uri[tal->urisz] = strdup(line);
		if (tal->uri[tal->urisz] == NULL) {
			WARN("strdup");
			goto out;
		}
		tal->urisz++;

		/* Make sure we're a proper rsync URI. */

		if (!rsync_uri_parse(verb, NULL, NULL, 
		    NULL, NULL, NULL, NULL, &rp, line)) {
			WARNX1(verb, "rsync_uri_parse");
			goto out;
		} else if (rp != RTYPE_CER) {
			WARNX(verb, "%s: not a certificate", line);
			goto out;
		}

		LOG(verb, "%s: parsed certificate: %s", fn, line);
	}

	if (ferror(f)) {
		WARN("%s: getline", fn);
		goto out;
	} else if (tal->urisz == 0) {
		WARNX(verb, "%s: zero URIs", fn);
		goto out;
	}

	/* Now the BASE64-encoded public key. */

	while ((linelen = getline(&line, &linesize, f)) != -1) {
		lineno++;
		assert(linelen);
		assert(line[linelen - 1] == '\n');
		line[--linelen] = '\0';
		if (linelen && line[linelen - 1] == '\r') 
			line[--linelen] = '\0';

		/* Zero-length line can be ignored... ? */

		if (linelen == 0)
			continue;

		/* Do our base64 decoding in-band. */

		sz = ((linelen + 2) / 3) * 4 + 1;
		if ((pp = realloc(b64, b64sz + sz)) == NULL) {
			WARN("realloc");
			goto out;
		}
		b64 = pp;
		ssz = b64_pton(line, b64 + b64sz, sz);
		if (ssz < 0) {
			WARN("b64_pton");
			goto out;
		}

		/* 
		 * This might be different from our allocation size, but
		 * that doesn't matter: the slop here is minimal.
		 */

		b64sz += ssz;
	}
	
	if (ferror(f)) {
		WARN("%s: getline", fn);
		goto out;
	} else if (b64sz == 0) {
		WARNX(verb, "%s: zero-length public key", fn);
		goto out;
	}

	/* Try the convertion into an encoded public key. */

	tal->pkey = b64;
	tal->pkeysz = b64sz;
	b64 = NULL;

	LOG(verb, "%s: parsed %zu URIs", fn, tal->urisz);
	rc = 1;
out:
	free(line);
	free(b64);
	if (rc == 0) {
		tal_free(tal);
		tal = NULL;
	}
	return tal;
}

/*
 * Parse a TAL from a file conformant to RFC 7730.
 * Returns the encoded data or NULL on failure.
 * Failure can be any number of things: failure to open file, allocate
 * memory, bad syntax, etc.
 */
struct tal *
tal_parse(int verb, const char *fn)
{
	FILE		*f;
	struct tal	*p;

	if ((f = fopen(fn, "r")) == NULL) {
		WARN("%s: fopen", fn);
		return NULL;
	}

	LOG(verb, "%s: opened", fn);
	p = tal_parse_stream(verb, fn, f);
	fclose(f);
	return p;
}

/*
 * Free a TAL pointer.
 * Safe to call with NULL.
 */
void
tal_free(struct tal *p)
{
	size_t	 i;

	if (p == NULL)
		return;

	/* We might set "urisz" before allocating "uri". */

	if (p->uri != NULL)
		for (i = 0; i < p->urisz; i++)
			free(p->uri[i]);

	free(p->pkey);
	free(p->uri);
	free(p);
}

/*
 * Buffer TAL parsed contents for writing.
 * See tal_read() for the other side of the pipe.
 * Returns zero on failure, non-zero on success.
 */
int
tal_buffer(char **b, size_t *bsz, size_t *bmax,
	int verb, const struct tal *p)
{
	size_t	 i;
	int	 rc = 0;

	if (!buf_buffer(b, bsz, bmax, verb, p->pkey, p->pkeysz)) {
		WARNX1(verb, "buf_buffer");
		goto out;
	} else if (!simple_buffer(b, bsz, bmax, &p->urisz, sizeof(size_t))) {
		WARNX1(verb, "simple_buffer");
		goto out;
	}

	for (i = 0; i < p->urisz; i++)
		if (!str_buffer(b, bsz, bmax, verb, p->uri[i])) {
			WARNX1(verb, "str_buffer");
			goto out;
		}
	rc = 1;
out:
	return rc;
}

/*
 * Read parsed TAL contents from descriptor.
 * See tal_buffer() for the other side of the pipe.
 * Returns the TAL pointer on success, NULL on failure.
 * A returned pointer must be freed with tal_free().
 */
struct tal *
tal_read(int fd, int verb)
{
	size_t		 i;
	struct tal	*p;

	if ((p = calloc(1, sizeof(struct tal))) == NULL) {
		WARN("calloc");
		goto out;
	}
	if (!buf_read_alloc(fd, verb, (void **)&p->pkey, &p->pkeysz)) {
		WARNX1(verb, "buf_read_alloc");
		goto out;
	}
	assert(p->pkeysz > 0);

	if (!simple_read(fd, verb, &p->urisz, sizeof(size_t))) {
		WARNX1(verb, "simple_read");
		goto out;
	}
	assert(p->urisz > 0);

	if ((p->uri = calloc(p->urisz, sizeof(char *))) == NULL) {
		WARN("calloc");
		goto out;
	}
	for (i = 0; i < p->urisz; i++)
		if (!str_read(fd, verb, &p->uri[i])) {
			WARNX1(verb, "str_read");
			goto out;
		}

	return p;
out:
	tal_free(p);
	return NULL;
}

