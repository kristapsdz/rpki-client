#include <netinet/in.h>

#include <assert.h>
#include <err.h>
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
tal_parse_stream(const char *fn, FILE *f)
{
	char		*line = NULL, *b64 = NULL;
	size_t		 sz, b64sz = 0, linesize = 0, lineno = 0;
	ssize_t		 linelen, ssz;
	int		 rc = 0;
	struct tal	*tal = NULL;
	enum rtype	 rp;

	if ((tal = calloc(1, sizeof(struct tal))) == NULL)
		err(EXIT_FAILURE, NULL);

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

		tal->uri = reallocarray(tal->uri,
			tal->urisz + 1, sizeof(char *));
		if (tal->uri == NULL)
			err(EXIT_FAILURE, NULL);

		tal->uri[tal->urisz] = strdup(line);
		if (tal->uri[tal->urisz] == NULL)
			err(EXIT_FAILURE, NULL);

		tal->urisz++;

		/* Make sure we're a proper rsync URI. */

		if (!rsync_uri_parse(NULL, NULL, 
		    NULL, NULL, NULL, NULL, &rp, line))
			goto out;

		if (rp != RTYPE_CER) {
			warnx("%s: not a certificate", line);
			goto out;
		}
	}

	if (ferror(f))
		err(EXIT_FAILURE, "%s: getline", fn);

	if (tal->urisz == 0) {
		warnx("%s: no URIs in manifest part", fn);
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
		if ((b64 = realloc(b64, b64sz + sz)) == NULL)
			err(EXIT_FAILURE, NULL);
		if ((ssz = b64_pton(line, b64 + b64sz, sz)) < 0)
			errx(EXIT_FAILURE, "b64_pton");

		/* 
		 * This might be different from our allocation size, but
		 * that doesn't matter: the slop here is minimal.
		 */

		b64sz += ssz;
	}
	
	if (ferror(f))
		err(EXIT_FAILURE, "%s: getline", fn);

	if (b64sz == 0) {
		warnx("%s: zero-length public key", fn);
		goto out;
	}

	/* FIXME: try converting into an encoded public key. */

	tal->pkey = b64;
	tal->pkeysz = b64sz;
	b64 = NULL;
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
tal_parse(const char *fn)
{
	FILE		*f;
	struct tal	*p;

	if ((f = fopen(fn, "r")) == NULL)
		err(EXIT_FAILURE, "%s: open", fn);

	p = tal_parse_stream(fn, f);
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
 */
void
tal_buffer(char **b, size_t *bsz, size_t *bmax, const struct tal *p)
{
	size_t	 i;

	buf_buffer(b, bsz, bmax, p->pkey, p->pkeysz);
	simple_buffer(b, bsz, bmax, &p->urisz, sizeof(size_t));

	for (i = 0; i < p->urisz; i++)
		str_buffer(b, bsz, bmax, p->uri[i]);
}

/*
 * Read parsed TAL contents from descriptor.
 * See tal_buffer() for the other side of the pipe.
 * A returned pointer must be freed with tal_free().
 */
struct tal *
tal_read(int fd)
{
	size_t		 i;
	struct tal	*p;

	if ((p = calloc(1, sizeof(struct tal))) == NULL)
		err(EXIT_FAILURE, NULL);

	buf_read_alloc(fd, (void **)&p->pkey, &p->pkeysz);
	assert(p->pkeysz > 0);
	simple_read(fd, &p->urisz, sizeof(size_t));
	assert(p->urisz > 0);

	if ((p->uri = calloc(p->urisz, sizeof(char *))) == NULL)
		err(EXIT_FAILURE, NULL);

	for (i = 0; i < p->urisz; i++)
		str_read(fd, &p->uri[i]);

	return p;
}

