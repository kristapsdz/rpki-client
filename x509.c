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

static void
tracewarn(size_t idx, const struct auth *auths, size_t authsz)
{

	for (;; idx = auths[idx].parent) {
		warnx(" ...inheriting from: %s", auths[idx].fn);
		if (auths[idx].parent == (size_t)idx)
			break;
	}
}

/*
 * Walk up the chain of certificates trying to match our AS number to
 * one of the allocations in that chain.
 * Returns the index of the certificate in auths or -1 on error.
 */
static ssize_t
x509_auth_as(uint32_t min, uint32_t max,
	size_t idx, const struct auth *as, size_t asz)
{
	int	 c;

	assert(idx < asz);

	/* Does this certificate cover our AS number? */

	if (as[idx].cert->asz) {
		c = as_check_covered(min, max, 
			as[idx].cert->as, as[idx].cert->asz);
		if (c > 0)
			return idx;
		else if (c < 0)
			return -1;
	}

	/* If it doesn't, walk up the chain. */

	if (as[idx].parent == as[idx].id)
		return -1;
	return x509_auth_as(min, max, as[idx].parent, as, asz);
}

/*
 * Walk up the chain of certificates (really just the last one, but in
 * the case of inheritence, the ones before) making sure that our IP
 * prefix is covered in the first non-inheriting specification.
 * Returns the index of the certificate in auths or -1 on error.
 */
static ssize_t
x509_auth_ip_addr(size_t idx, enum afi afi, 
	const unsigned char *min, const unsigned char *max, 
	const struct auth *as, size_t asz)
{
	int	 c;

	assert(idx < asz);

	/* Does this certificate cover our IP prefix? */

	c = ip_addr_check_covered(afi, min, max,
		as[idx].cert->ips, as[idx].cert->ipsz);
	if (c > 0)
		return idx;
	else if (c < 0)
		return -1;

	/* If it doesn't, walk up the chain. */

	if (as[idx].parent == as[idx].id)
		return -1;
	return x509_auth_ip_addr
		(as[idx].parent, afi, min, max, as, asz);
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
	const ASN1_TYPE		*t;
	const ASN1_SEQUENCE_ANY	*seq = NULL, *sseq = NULL;
	int			 dsz, ptag;
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
	const unsigned char 	*d;
	const ASN1_SEQUENCE_ANY	*seq = NULL;
	const ASN1_TYPE		*t;
	int			 dsz, ptag;
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
 * Augments the key cache with the certificate's SKI, public key, and
 * parsed data.
 * Returns zero on failure, non-zero on success.
 */
int
x509_auth_selfsigned_cert(X509 *x, const char *fn,
	struct auth **auths, size_t *authsz,
	const unsigned char *pkey, size_t pkeysz, struct cert *cert)
{
	EVP_PKEY	*pk = NULL, *opk = NULL;
	int		 rc = 0, extsz, i;
	char		*ski = NULL, *aki = NULL;
	size_t		 j;
	X509_EXTENSION	*ext;
	ASN1_OBJECT	*obj;

	assert(cert != NULL);
	assert(pkeysz);
	assert(pkey != NULL);
	pk = d2i_PUBKEY(NULL, &pkey, pkeysz);
	assert(pk != NULL);

	/* 
	 * Pre-validation: AS and IP resources must not inherit.  The
	 * CRL must not be specified.  The pubkey must exist and must
	 * match the given pubkey.
	 */

	if (cert->asz && cert->as[0].type == CERT_AS_INHERIT) {
		warnx("%s: RFC 6487 (trust anchor): "
			"inheriting AS resources", fn);
		goto out;
	}

	for (j = 0; j < cert->ipsz; j++) 
		if (cert->ips[j].type == CERT_IP_INHERIT) {
			warnx("%s: RFC 6487 (trust anchor): "
				"inheriting IP resources", fn);
			goto out;
		}

	if (cert->crl != NULL) {
		warnx("%s: RFC 6487 (trust anchor): "
			"CRL location not allowed", fn);
		goto out;
	}

	if ((opk = X509_get_pubkey(x)) == NULL) {
		cryptowarnx("%s: RFC 6487 (trust anchor): "
			"missing pubkey", fn);
		goto out;
	} else if (!EVP_PKEY_cmp(pk, opk)) {
		cryptowarnx("%s: RFC 6487 (trust anchor): "
			"pubkey does not match TAL pubkey", fn);
		goto out;
	} else if (!X509_verify(x, pk)) {
		cryptowarnx("%s: RFC 6487 (trust anchor): "
			"bad pubkey signature", fn);
		goto out;
	}

	/* Extract SKI and AKI from X509. */

	if ((extsz = X509_get_ext_count(x)) < 0)
		cryptoerrx("X509_get_ext_count");

	for (i = 0; i < extsz; i++) {
		ext = X509_get_ext(x, i);
		assert(ext != NULL);
		obj = X509_EXTENSION_get_object(ext);
		assert(obj != NULL);
		switch (OBJ_obj2nid(obj)) {
		case NID_authority_key_identifier:
			if (aki != NULL) {
				warnx("%s: RFC 6487 (trust anchor): "
					"repeat AKI", fn);
				goto out;
			}
			if ((aki = x509_get_aki(ext, fn)) == NULL)
				goto out;
			break;
		return 0;
		case NID_subject_key_identifier:
			if (ski != NULL) {
				warnx("%s: RFC 6487 (trust anchor): "
					"repeat SKI", fn);
				goto out;
			}
			if ((ski = x509_get_ski(ext, fn)) == NULL)
				goto out;
			break;
		default:
			break;
		}
	}

	/* 
	 * Post-validation: the AKI, if provided, should match the SKI.
	 * The SKI must not exist.
	 */

	if (ski == NULL) {
		warnx("%s: RFC 6487 (trust anchor): missing SKI", fn);
		goto out;
	} else if (aki != NULL && strcmp(aki, ski)) {
		warnx("%s: RFC 6487 (trust anchor): "
			"non-matching SKI and AKI", fn);
		goto out;
	}
	for (j = 0; j < *authsz; j++)
		if (strcmp((*auths)[j].ski, ski) == 0) {
			warnx("%s: RFC 6487 (trust anchor): "
				"re-registering SKI", fn);
			goto out;
		}

	/* Success: append to the certificate cache. */

	*auths = reallocarray(*auths,
		*authsz + 1, sizeof(struct auth));
	if (*auths == NULL)
		err(EXIT_FAILURE, NULL);
	(*auths)[*authsz].id = *authsz;
	(*auths)[*authsz].parent = *authsz;
	(*auths)[*authsz].ski = ski;
	(*auths)[*authsz].pkey = opk;
	(*auths)[*authsz].cert = cert;
	(*auths)[*authsz].fn = strdup(fn);
	if ((*auths)[*authsz].fn == NULL)
		err(EXIT_FAILURE, NULL);
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
 * Returns zero on failure, non-zero on success.
 */
static ssize_t
x509_auth_cert(X509 *x, const char *fn,
	const struct auth *auths, size_t authsz, char **skip)
{
	int	 	 i, extsz;
	ssize_t		 rc = -1;
	size_t		 j;
	char		*ski = NULL, *aki = NULL;
	X509_EXTENSION	*ext;
	ASN1_OBJECT	*obj;

	if (skip != NULL)
		*skip = NULL;

	/* Extract SKI and AKI from X509. */

	if ((extsz = X509_get_ext_count(x)) < 0)
		cryptoerrx("X509_get_ext_count");

	for (i = 0; i < extsz; i++) {
		ext = X509_get_ext(x, i);
		assert(ext != NULL);
		obj = X509_EXTENSION_get_object(ext);
		assert(obj != NULL);

		switch (OBJ_obj2nid(obj)) {
		case NID_authority_key_identifier:
			if (aki != NULL) {
				warnx("%s: RFC 6487: repeat AKI", fn);
				goto out;
			}
			if ((aki = x509_get_aki(ext, fn)) == NULL)
				goto out;
			break;
		return 0;
		case NID_subject_key_identifier:
			if (ski != NULL) {
				warnx("%s: RFC 6487: repeat SKI", fn);
				goto out;
			}
			if ((ski = x509_get_ski(ext, fn)) == NULL)
				goto out;
			break;
		default:
			break;
		}
	}

	/*
	 * Validation: AKI and SKI must exist and match, SKI must not
	 * aleady be registered, AKI must be registered, key
	 * verification with AKI key must succeed.
	 */

	if (aki == NULL) {
		warnx("%s: RFC 6487: missing AKI", fn);
		goto out;
	} else if (ski == NULL) {
		warnx("%s: RFC 6487: missing SKI", fn);
		goto out;
	} else if (strcmp(aki, ski) == 0) {
		warnx("%s: RFC 6487: matching SKI and AKI", fn);
		goto out;
	}	

	for (j = 0; j < authsz; j++)
		if (strcmp(auths[j].ski, ski) == 0) {
			warnx("%s: RFC 6487: re-registering SKI", fn);
			goto out;
		}

	for (j = 0; j < authsz; j++)
		if (strcmp(auths[j].ski, aki) == 0)
			break;
	if (j == authsz) {
		warnx("%s: RFC 6487: unknown AKI", fn);
		goto out;
	}

	if (!X509_verify(x, auths[j].pkey)) {
		cryptowarnx("%s: RFC 6487: key verify failed", fn);
		goto out;
	}

	/* Success: assign SKI and AKI index. */

	if (skip != NULL) {
		*skip = ski;
		ski = NULL;
	}
	rc = j;
out:
	free(ski);
	free(aki);
	return rc;
}

/*
 * Validate a signed (non-TA) certificate.
 * Returns zero on failure, non-zero on success.
 * On success, adds the certificate to the cache.
 */
int
x509_auth_signed_cert(X509 *x, const char *fn,
	struct auth **auths, size_t *authsz, struct cert *cert)
{
	ssize_t	 	 c, pp;
	size_t		 i;
	uint32_t	 min, max;
	char		*ski;
	char		 buf1[64], buf2[64];
	EVP_PKEY	*pkey;

	if (cert->crl == NULL) {
		warnx("%s: RFC 6487: missing CRL", fn);
		return 0;
	} else if ((pkey = X509_get_pubkey(x)) == NULL) {
		warnx("%s: RFC 6487: missing pubkey", fn);
		return 0;
	}

	/* 
	 * Use "err" now to decrement pkey refcount. 
	 * Validate the certificate, then validate that our AS and IP
	 * allocations are properly inheriting.
	 */

	c = x509_auth_cert(x, fn, *auths, *authsz, &ski);
	if (c < 0)
		goto err;

	for (i = 0; i < cert->asz; i++) {
		if (cert->as[i].type == CERT_AS_INHERIT)
			continue;
		min = cert->as[i].type == CERT_AS_ID ?
			cert->as[i].id : cert->as[i].range.min;
		max = cert->as[i].type == CERT_AS_ID ?
			cert->as[i].id : cert->as[i].range.max;
		pp = x509_auth_as(min, max, c, *auths, *authsz);
		if (pp >= 0)
			continue;
		warnx("%s: RFC 6487: uncovered AS: %" 
			PRIu32 "--%" PRIu32, fn, min, max);
		tracewarn(c, *auths, *authsz);
		goto err;
	}

	for (i = 0; i < cert->ipsz; i++) {
		pp = x509_auth_ip_addr
			(c, cert->ips[i].afi, cert->ips[i].min, 
			 cert->ips[i].max, *auths, *authsz);
		if (pp >= 0)
			continue;
		switch (cert->ips[i].type) {
		case CERT_IP_RANGE:
			ip_addr_print(&cert->ips[i].range.min, 
				cert->ips[i].afi, buf1, sizeof(buf1));
			ip_addr_print(&cert->ips[i].range.max, 
				cert->ips[i].afi, buf2, sizeof(buf2));
			warnx("%s: RFC 6487: uncovered IP: "
				"%s--%s", fn, buf1, buf2);
			break;
		case CERT_IP_ADDR:
			ip_addr_print(&cert->ips[i].ip, 
				cert->ips[i].afi, buf1, sizeof(buf1));
			warnx("%s: RFC 6487: uncovered IP: "
				"%s", fn, buf1);
		case CERT_IP_INHERIT:
			warnx("%s: RFC 6487: uncovered IP: "
				"(inherit)", fn);
			break;
		}
		tracewarn(c, *auths, *authsz);
		goto err;
	}

	*auths = reallocarray(*auths,
		*authsz + 1, sizeof(struct auth));
	if (*auths == NULL)
		err(EXIT_FAILURE, NULL);

	(*auths)[*authsz].id = *authsz;
	(*auths)[*authsz].parent = c;
	(*auths)[*authsz].ski = ski;
	(*auths)[*authsz].pkey = X509_get_pubkey(x);
	assert((*auths)[*authsz].pkey != NULL);
	(*auths)[*authsz].cert = cert;
	(*auths)[*authsz].fn = strdup(fn);
	if ((*auths)[*authsz].fn == NULL)
		err(EXIT_FAILURE, NULL);
	(*authsz)++;
	return 1;

err:
	EVP_PKEY_free(pkey);
	return 0;
}

/*
 * Validate our MFT.
 * At this time, this simply means validating the signing key.
 * Returns zero on failure, non-zero on success.
 */
int
x509_auth_signed_mft(X509 *x, const char *fn,
	const struct auth *auths, size_t authsz, struct mft *mft)
{

	return x509_auth_cert(x, fn, auths, authsz, NULL) >= 0;
}

/*
 * Validate our ROA.
 * Beyond the usual, this means checking that the AS number is covered
 * by one of the parent certificates and the IP prefix is also
 * contained.
 * Sets the "invalid" field if any of these fail.
 */
void
x509_auth_signed_roa(X509 *x, const char *fn,
	const struct auth *auths, size_t authsz, struct roa *roa)
{
	ssize_t	 c, pp;
	size_t	 i;
	char	 buf[64];

	roa->invalid = 1;

	if ((c = x509_auth_cert(x, fn, auths, authsz, NULL)) < 0)
		return;

	/*
	 * According to RFC 6483 section 4, AS 0 in an ROA means that
	 * the prefix is specifically disallowed from being routed.
	 */

	if (roa->asid > 0) {
		pp = x509_auth_as(roa->asid, 
			roa->asid, c, auths, authsz);
		if (pp < 0) {
			warnx("%s: RFC 6482: uncovered AS: "
				"%" PRIu32, fn, roa->asid);
			tracewarn(c, auths, authsz);
			return;
		}
	}

	for (i = 0; i < roa->ipsz; i++) {
		pp = x509_auth_ip_addr
			(c, roa->ips[i].afi, roa->ips[i].min, 
			 roa->ips[i].max, auths, authsz);
		if (pp >= 0)
			continue;
		ip_addr_print(&roa->ips[i].addr, 
			roa->ips[i].afi, buf, sizeof(buf));
		warnx("%s: RFC 6482: uncovered IP: %s", fn, buf);
		tracewarn(c, auths, authsz);
		return;
	}

	roa->invalid = 0;
}
