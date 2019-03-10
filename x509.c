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
 * Wrapper around ASN1_get_object() that preserves the current start
 * state and returns a more meaningful value.
 * FIXME: also appears in cert.c.
 * Return zero on failure, non-zero on success.
 */
static int
ASN1_frame(const char *fn, size_t sz,
	const unsigned char **cnt, long *cntsz, int *tag)
{
	int	 ret, pcls;

	assert(cnt != NULL && *cnt != NULL);
	assert(sz > 0);
	ret = ASN1_get_object(cnt, cntsz, tag, &pcls, sz);
	if ((ret & 0x80)) {
		cryptowarnx("%s: ASN1_get_object", fn);
		return 0;
	} 
	return ASN1_object_size((ret & 0x01) ? 2 : 0, *cntsz, *tag);
}


 /*
 * Parse X509v3 authority key identifier, RFC 6487 sec. 4.8.3.
 * Returns the AKI or NULL if it could not be parsed.
 */
static char *
x509_get_aki(X509_EXTENSION *ext, const char *fn)
{
	unsigned char		*sv = NULL;
	const unsigned char 	*d;
	size_t			 dsz;
	const ASN1_TYPE		*t;
	const ASN1_SEQUENCE_ANY	*seq = NULL, *sseq = NULL;
	int			 ptag;
	long			 i, plen;
	char			 buf[4];
	char			*res = NULL;

	if ((dsz = i2d_X509_EXTENSION(ext, &sv)) < 0) {
		cryptowarnx("%s: RFC 6487 section 4.8.3: AKI: "
			"failed extension parse", fn);
		goto out;
	} 
	d = sv;

	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		cryptowarnx("%s: RFC 6487 section 4.8.3: AKI: "
			"failed ASN.1 sequence parse", fn);
		goto out;
	} else if (sk_ASN1_TYPE_num(seq) != 2) {
		warnx("%s: RFC 6487 section 4.8.3: AKI: "
			"want 2 elements, have %d", fn, 
			sk_ASN1_TYPE_num(seq));
		goto out;
	}

	t = sk_ASN1_TYPE_value(seq, 0);
	if (t->type != V_ASN1_OBJECT) {
		warnx("%s: RFC 6487 section 4.8.3: AKI: "
			"want ASN.1 object, have %s (NID %d)", 
			fn, ASN1_tag2str(t->type), t->type);
		goto out;
	}
	if (OBJ_obj2nid(t->value.object) != NID_authority_key_identifier) {
		warnx("%s: RFC 6487 section 4.8.3: AKI: "
			"incorrect OID, have %s (NID %d)", fn, 
			ASN1_tag2str(OBJ_obj2nid(t->value.object)), 
			OBJ_obj2nid(t->value.object));
		goto out;
	}

	t = sk_ASN1_TYPE_value(seq, 1);
	if (t->type != V_ASN1_OCTET_STRING) {
		warnx("%s: RFC 6487 section 4.8.3: AKI: "
			"want ASN.1 octet string, have %s (NID %d)", 
			fn, ASN1_tag2str(t->type), t->type);
		goto out;
	}

	/* Data is really a sub-sequence...? */

	d = t->value.octet_string->data;
	dsz = t->value.octet_string->length;

	if ((sseq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		cryptowarnx("%s: RFC 6487 section 4.8.2: AKI: "
			"failed ASN.1 sub-sequence parse", fn);
		goto out;
	} else if (sk_ASN1_TYPE_num(sseq) != 1) {
		warnx("%s: RFC 6487 section 4.8.3: AKI: "
			"want 1 element, have %d", fn, 
			sk_ASN1_TYPE_num(seq));
		goto out;
	} 

	t = sk_ASN1_TYPE_value(sseq, 0);
	if (t->type != V_ASN1_OTHER) {
		warnx("%s: RFC 6487 section 4.8.3: AKI: "
			"want ASN.1 external, have %s (NID %d)", 
			fn, ASN1_tag2str(t->type), t->type);
		goto out;
	}

	d = t->value.asn1_string->data;
	dsz = t->value.asn1_string->length;
	if (!ASN1_frame(fn, dsz, &d, &plen, &ptag))
		goto out;

	/* Make room for [hex1, hex2, ":"]*, NUL. */

	if ((res = calloc(plen * 3 + 1, 1)) == NULL)
		err(EXIT_FAILURE, NULL);

	for (i = 0; i < plen; i++) {
		snprintf(buf, sizeof(buf), "%0.2X:", d[i]);
		strlcat(res, buf, plen * 3 + 1);
	}
	res[plen * 3 - 1] = '\0';
out:
	sk_ASN1_TYPE_free(seq);
	sk_ASN1_TYPE_free(sseq);
	free(sv);
	return res;
}

/*
 * Parse X509v3 subject authority key identifier, RFC 6487 sec. 4.8.2.
 * Returns the SKI or NULL if it could not be parsed.
 */
static char *
x509_get_ski(X509_EXTENSION *ext, const char *fn)
{
	size_t			 dsz;
	const unsigned char 	*d;
	const ASN1_SEQUENCE_ANY	*seq = NULL;
	const ASN1_TYPE		*t;
	int			 rc = 0, ptag;
	unsigned char		*sv = NULL;
	char			 buf[4];
	char			*res = NULL;
	long			 j, plen;

	if ((dsz = i2d_X509_EXTENSION(ext, &sv)) < 0) {
		cryptowarnx("%s: RFC 6487 section 4.8.2: SKI: "
			"failed extension parse", fn);
		goto out;
	} 
	d = sv;

	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		cryptowarnx("%s: RFC 6487 section 4.8.2: SKI: "
			"failed ASN.1 sequence parse", fn);
		goto out;
	} else if (sk_ASN1_TYPE_num(seq) != 2) {
		warnx("%s: RFC 6487 section 4.8.2: SKI: "
			"want 2 elements, have %d", fn, 
			sk_ASN1_TYPE_num(seq));
		goto out;
	}

	t = sk_ASN1_TYPE_value(seq, 0);
	if (t->type != V_ASN1_OBJECT) {
		warnx("%s: RFC 6487 section 4.8.2: SKI: "
			"want ASN.1 object, have %s (NID %d)", 
			fn, ASN1_tag2str(t->type), t->type);
		goto out;
	}
	if (OBJ_obj2nid(t->value.object) != NID_subject_key_identifier) {
		warnx("%s: RFC 6487 section 4.8.2: SKI: "
			"incorrect OID, have %s (NID %d)", fn, 
			ASN1_tag2str(OBJ_obj2nid(t->value.object)), 
			OBJ_obj2nid(t->value.object));
		goto out;
	}

	t = sk_ASN1_TYPE_value(seq, 1);
	if (t->type != V_ASN1_OCTET_STRING) {
		warnx("%s: RFC 6487 section 4.8.2: SKI: "
			"want ASN.1 octet string, have %s (NID %d)", 
			fn, ASN1_tag2str(t->type), t->type);
		goto out;
	}

	/* 
	 * Parse the frame out of the ASN.1 octet string.
	 * The content is always a 20 B (160 bit) hash.
	 */

	d = t->value.octet_string->data;
	dsz = t->value.octet_string->length;

	if (!ASN1_frame(fn, dsz, &d, &plen, &ptag))
		goto out;

	if (plen != 20) {
		warnx("%s: RFC 6487 section 4.8.2: SKI: want 20 B "
			"SHA1 hash, have %ld B", fn, plen);
		goto out;
	} 
	assert(V_ASN1_OCTET_STRING == ptag);

	/* Make room for [hex1, hex2, ":"]*, NUL. */

	if ((res = calloc(plen * 3 + 1, 1)) == NULL)
		err(EXIT_FAILURE, NULL);

	for (j = 0; j < plen; j++) {
		snprintf(buf, sizeof(buf), "%0.2X:", d[j]);
		strlcat(res, buf, dsz * 3 + 1);
	}
	res[plen * 3 - 1] = '\0';
	rc = 1;
out:
	sk_ASN1_TYPE_free(seq);
	free(sv);
	return res;
}

/*
 * Authenticate a self-signed certificate with the given public key.
 * This conforms to RFC 6487 in the case where the public key is given
 * in the TAL file and is self-signed---that is, it does not specify a
 * different authority key identifier.
 * Returns zero on failure, non-zero on success.
 */
int
x509_authorise_selfsigned(X509 *x, const char *fn,
	struct auth **auths, size_t *authsz,
	const unsigned char *pkey, size_t pkeysz)
{
	EVP_PKEY	*pk = NULL, *opk = NULL;
	int		 rc = 0, extsz, i;
	char		*ski = NULL, *aki = NULL;
	size_t		 j;
	X509_EXTENSION	*ext;
	ASN1_OBJECT	*obj;

	assert(pkeysz);
	assert(pkey != NULL);
	pk = d2i_PUBKEY(NULL, &pkey, pkeysz);
	assert(pk != NULL);

	/* Public keys should match and verify. */

	if ((opk = X509_get_pubkey(x)) == NULL) {
		cryptowarnx("%s: RFC 6487: no public key", fn);
		goto out;
	} else if (!EVP_PKEY_cmp(pk, opk)) {
		cryptowarnx("%s: given and self-signing "
			"public keys are different", fn);
		goto out;
	} else if (!X509_verify(x, pk)) {
		cryptowarnx("%s: RFC 6487: self-signed key does "
			"not match TAL-specified key", fn);
		goto out;
	}

	/* Get the SKI and (optionally) AKI. */

	if ((extsz = X509_get_ext_count(x)) < 0)
		cryptoerrx("X509_get_ext_count");

	for (i = 0; i < extsz; i++) {
		ext = X509_get_ext(x, i);
		assert(ext != NULL);
		obj = X509_EXTENSION_get_object(ext);
		assert(obj != NULL);
		switch (OBJ_obj2nid(obj)) {
		case NID_authority_key_identifier:
			aki = x509_get_aki(X509_get_ext(x, i), fn);
			if (aki == NULL)
				goto out;
			break;
		return 0;
		case NID_subject_key_identifier:
			ski = x509_get_ski(X509_get_ext(x, i), fn);
			if (ski == NULL)
				goto out;
			break;
		default:
			break;
		}
	}

	/* The AKI, if provided, should match the SKI. */

	if (ski == NULL) {
		warnx("%s: RFC 6487: no subject key identifier", fn);
		goto out;
	} else if (aki != NULL && strcmp(aki, ski)) {
		warnx("%s: RFC 6487: non-matching subject and "
			"authoritative key identifiers", fn);
		goto out;
	}

	/* Don't allow the SKI to already exist. */

	for (j = 0; j < *authsz; j++)
		if (strcmp((*auths)[j].ski, ski) == 0) {
			warnx("%s: RFC 6487: duplicate certificate", fn);
			goto out;
		}

	/* Append our own public key to the key cache. */

	*auths = reallocarray(*auths,
		*authsz + 1, sizeof(struct auth));
	if (*auths == NULL)
		err(EXIT_FAILURE, NULL);
	(*auths)[*authsz].ski = ski;
	(*auths)[*authsz].cert = opk;
	(*authsz)++;

	opk = NULL;
	ski = NULL;
	rc = 1;
out:
	free(ski);
	free(aki);
	EVP_PKEY_free(pk);
	EVP_PKEY_free(opk);
	return rc;
}

/*
 * Take a signed certificate as specified in RFC 6487, look up the
 * referenced certificate (AKI) in the key cache, and verify the
 * signature.
 * If append is non-zero, augment the key cache with the cert's SKI.
 * Returns zero on failure, non-zero on success.
 */
int
x509_authorise_signed(X509 *x, const char *fn,
	struct auth **auths, size_t *authsz, int append)
{
	int	 	 i, extsz, rc = 0;
	size_t		 j;
	char		*ski = NULL, *aki = NULL;
	X509_EXTENSION	*ext;
	ASN1_OBJECT	*obj;
	EVP_PKEY	*pk;

	/* Get the public key, SKI, and AKI. */

	if ((pk = X509_get_pubkey(x)) == NULL) {
		cryptowarnx("%s: no public key", fn);
		return 0;
	} else if ((extsz = X509_get_ext_count(x)) < 0)
		cryptoerrx("X509_get_ext_count");

	for (i = 0; i < extsz; i++) {
		ext = X509_get_ext(x, i);
		assert(ext != NULL);
		obj = X509_EXTENSION_get_object(ext);
		assert(obj != NULL);
		switch (OBJ_obj2nid(obj)) {
		case NID_authority_key_identifier:
			free(aki);
			aki = x509_get_aki(X509_get_ext(x, i), fn);
			if (aki == NULL)
				goto out;
			break;
		return 0;
		case NID_subject_key_identifier:
			free(ski);
			ski = x509_get_ski(X509_get_ext(x, i), fn);
			if (ski == NULL)
				goto out;
			break;
		default:
			break;
		}
	}

	if (aki == NULL) {
		warnx("%s: RFC 6487: no authority key identifier", fn);
		goto out;
	} else if (ski == NULL) {
		warnx("%s: RFC 6487: no subject key identifier", fn);
		goto out;
	} else if (strcmp(aki, ski) == 0) {
		warnx("%s: RFC 6487: self-signing key not allowed", fn);
		goto out;
	}	

	/* SKI shouldn't already be specified. */

	for (j = 0; j < *authsz; j++)
		if (strcmp((*auths)[j].ski, ski) == 0) {
			warnx("%s: RFC 6487: duplicate certificate", fn);
			goto out;
		}

	/* Look for a certificate matching the AKI. */

	for (j = 0; j < *authsz; j++)
		if (strcmp((*auths)[j].ski, aki) == 0)
			break;

	if (j == *authsz) {
		warnx("%s: RFC 6487: authority key "
			"identifier not found", fn);
		goto out;
	} else if (!X509_verify(x, (*auths)[j].cert)) {
		cryptowarnx("%s: RFC 6487: key verification failed", fn);
		goto out;
	}

	/* Append our own public key to the key cache. */

	if (append) {
		*auths = reallocarray(*auths,
			*authsz + 1, sizeof(struct auth));
		if (*auths == NULL)
			err(EXIT_FAILURE, NULL);
		(*auths)[*authsz].ski = ski;
		(*auths)[*authsz].cert = pk;
		(*authsz)++;
		ski = NULL;
		pk = NULL;
	}

	rc = 1;
out:
	free(ski);
	free(aki);
	EVP_PKEY_free(pk);
	return 1;
}
