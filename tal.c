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
 * See tal_parse_file() for details.
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
	const unsigned char *sv;

	/* Initial allocation. */

	if (NULL == (tal = calloc(1, sizeof(struct tal)))) {
		WARN("calloc");
		return NULL;
	}

	if ((tal->ident = strdup(fn)) == NULL) {
		WARN("strdup");
		goto out;
	} 

	/* Begin with the URI section. */

	while (-1 != (linelen = getline(&line, &linesize, f))) {
		lineno++;
		assert(linelen);
		assert('\n' == line[linelen - 1]);
		line[--linelen] = '\0';
		if (linelen && '\r' == line[linelen - 1]) 
			line[--linelen] = '\0';

		/* Zero-length line is end of section. */

		if (0 == linelen)
			break;

		/* Append to list of URIs. */

		pp = reallocarray(tal->uri, 
			tal->urisz + 1, sizeof(char *));
		if (NULL == pp) {
			WARN("reallocarray");
			goto out;
		}
		tal->uri = pp;
		tal->uri[tal->urisz] = strdup(line);
		if (NULL == tal->uri[tal->urisz]) {
			WARN("strdup");
			goto out;
		}
		LOG(verb, "%s: parsed URI: %s", 
			fn, tal->uri[tal->urisz]);
		tal->urisz++;
	}

	if (ferror(f)) {
		WARN("%s: getline", fn);
		goto out;
	} else if (0 == tal->urisz) {
		WARNX(verb, "%s: zero URIs", fn);
		goto out;
	}

	/* Now the BASE64-encoded public key. */

	while (-1 != (linelen = getline(&line, &linesize, f))) {
		lineno++;
		assert(linelen);
		assert('\n' == line[linelen - 1]);
		line[--linelen] = '\0';
		if (linelen && '\r' == line[linelen - 1]) 
			line[--linelen] = '\0';

		/* Zero-length line can be ignored... ? */

		if (0 == linelen)
			continue;

		/* Do our base64 decoding in-band. */

		sz = ((linelen + 2) / 3) * 4 + 1;
		if (NULL == (pp = realloc(b64, b64sz + sz))) {
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
	} else if (0 == b64sz) {
		WARNX(verb, "%s: zero-length "
			"public key string", fn);
		goto out;
	}

	/* Try the convertion into an encoded public key. */

	sv = b64;
	tal->pubkey = d2i_PUBKEY(NULL, &sv, b64sz);
	if (NULL == tal->pubkey) {
		CRYPTOX(verb, "%s: bad public key", fn);
		goto out;
	}

	LOG(verb, "%s: parsed %zu URIs", fn, tal->urisz);
	rc = 1;
out:
	free(line);
	free(b64);
	if (0 == rc) {
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
tal_parse_file(int verb, const char *fn)
{
	FILE		*f;
	struct tal	*p;

	if (NULL == (f = fopen(fn, "r"))) {
		WARN("%s: fopen", fn);
		return NULL;
	}

	LOG(verb, "%s: opened", fn);
	p = tal_parse_stream(verb, fn, f);
	fclose(f);
	return p;
}

/*
 * Free a TAL file parsed with tal_parse_file() or the like.
 * Safe to call with a NULL pointer.
 */
void
tal_free(struct tal *p)
{
	size_t	 i;

	if (NULL == p)
		return;

	for (i = 0; i < p->urisz; i++)
		free(p->uri[i]);

	free(p->ident);
	free(p->uri);
	free(p);
}

/*
 * Buffer TAL parsed contents.
 * See tal_read() for the other side of the pipe.
 * Returns zero on failure, non-zero on success.
 */
int
tal_buffer(char **b, size_t *bsz, size_t *bmax,
	int verb, const struct tal *p)
{
	size_t	 	 i;
	unsigned char	*pkey = NULL;
	int		 pkeysz, rc = 0;

	assert(p->ident && '\0' != *p->ident);

	if (!str_buffer(b, bsz, bmax, verb, p->ident)) {
		WARNX1(verb, "str_write");
		goto out;
	} else if ((pkeysz = i2d_PUBKEY(p->pubkey, &pkey)) < 0) {
		CRYPTOX(verb, "i2d_PUBKEY");
		goto out;
	} else if (!buf_buffer(b, bsz, bmax, verb, pkey, pkeysz)) {
		WARNX1(verb, "buf_write");
		goto out;
	} else if (!simple_buffer(b, bsz, bmax, &p->urisz, sizeof(size_t))) {
		WARNX1(verb, "simple_write");
		goto out;
	}

	for (i = 0; i < p->urisz; i++)
		if (!str_buffer(b, bsz, bmax, verb, p->uri[i])) {
			WARNX1(verb, "str_write");
			goto out;
		}

	rc = 1;
out:
	free(pkey);
	return rc;
}

/*
 * Read parsed TAL contents.
 * See tal_write() for the other side of the pipe.
 * Returns the TAL file, which must be freed with tal_free().
 */
struct tal *
tal_read(int fd, int verb)
{
	size_t		  i, urisz = 0, pkeysz;
	unsigned char	 *pkey = NULL, *sv;
	char		**uris = NULL, *ident = NULL;
	struct tal	 *tal = NULL;

	if (!str_read(fd, verb, &ident)) {
		WARNX1(verb, "str_read");
		goto out;
	} else if (!buf_read_alloc(fd, verb, (void **)&pkey, &pkeysz)) {
		WARNX1(verb, "buf_read_alloc");
		goto out;
	}
	assert(pkeysz > 0);

	if (!simple_read(fd, verb, &urisz, sizeof(size_t))) {
		WARNX1(verb, "simple_read");
		goto out;
	}
	assert(urisz > 0);

	if ((uris = calloc(urisz, sizeof(char *))) == NULL) {
		WARN("calloc");
		goto out;
	}
	for (i = 0; i < urisz; i++)
		if (!str_read(fd, verb, &uris[i])) {
			WARNX1(verb, "str_read");
			goto out;
		}

	/* Now copy into an allocated TAL object. */

	if ((tal = calloc(1, sizeof(struct tal))) == NULL)
		ERR("calloc");

	tal->ident = ident;
	tal->urisz = urisz;
	tal->uri = uris;
	sv = pkey;
	tal->pubkey = d2i_PUBKEY(NULL,
		(const unsigned char **)&sv, pkeysz);
	if (tal->pubkey == NULL) {
		CRYPTOX(verb, "d2i_PUBKEY");
		goto out;
	}
	free(pkey);
	return tal;
out:
	if (NULL != uris)
		for (i = 0; i < urisz; i++)
			free(uris[i]);
	free(uris);
	free(ident);
	free(pkey);
	free(uris);
	return NULL;
}

