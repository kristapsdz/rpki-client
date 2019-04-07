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

/*
 * Walk up the chain of certificates trying to match our AS number to
 * one of the allocations in that chain.
 * Returns the index of the certificate in auths or -1 on error.
 */
static ssize_t
x509_auth_as(uint32_t asid, size_t idx,
	const struct auth *as, size_t asz)
{

	assert(idx < asz);

	/* Does this certificate cover our AS number? */

	if (as_check_covered(asid, as[idx].cert->as, as[idx].cert->asz))
		return idx;

	/* If it doesn't, walk up the chain. */

	if (as[idx].parent == as[idx].id)
		return -1;
	return x509_auth_as(asid, as[idx].parent, as, asz);
}

/*
 * Walk up the chain of certificates (really just the last one, but in
 * the case of inheritence, the ones before) making sure that our IP
 * prefix is covered in the first non-inheriting specification.
 * Returns the index of the certificate in auths or -1 on error.
 */
static ssize_t
x509_auth_ip_addr(const struct roa_ip *ip, size_t idx,
	const struct auth *as, size_t asz)
{

	assert(idx < asz);

	/* Does this certificate cover our IP prefix? */

	if (ip_addr_check_covered
	    (ip, as[idx].cert->ips, as[idx].cert->ipsz))
		return idx;

	/* If it doesn't, walk up the chain. */

	if (as[idx].parent == as[idx].id)
		return -1;
	return x509_auth_ip_addr(ip, as[idx].parent, as, asz);
}

/*
 * Check the AS identifiers, if any, on a self-signed "root"
 * certificate.
 * Returns zero on failure, non-zero on success.
 */
static int
x509_auth_as_selfsigned(const struct cert *cert, const char *fn)
{

	/* The identifier cannot inherit from nothing. */

	if (cert->asz == 0 || cert->as[0].type != CERT_AS_INHERIT)
		return 1;

	warnx("%s: self-signed AS identifier cannot inherit", fn);
	return 0;
}

/*
 * Check to make sure that the AS identifiers specified in a certificate
 * are valid in view of the parent identifiers.
 * We can only narrow or inherit, not expand.
 * Return zero on failure, non-zero on success.
 */
static int
x509_auth_as_signed(const struct cert *cert, const char *fn,
	size_t parent, const struct auth *auths, size_t authsz)
{
	const struct cert	*pcert;
	const struct cert_as	*as, *pas;
	size_t			 i, j;
	int			 found;

	assert(parent < authsz);
	pcert = auths[parent].cert;

	/* 
	 * Allow us to narrow to nothingness the possible identifiers or
	 * to inherit fully.
	 */

	if (cert->asz == 0)
		return 1;
	if (cert->asz && cert->as[0].type == CERT_AS_INHERIT)
		return 1;

	assert(cert->asz);

	if (pcert->asz == 0) {
		warnx("%s: expanding parent AS identifiers", fn);
		return 0;
	}

	assert(cert->asz && pcert->asz);

	/*
	 * We want to examine the first parent that has non-inheritable
	 * entries, so climb from here.
	 */

	if (pcert->as[0].type == CERT_AS_INHERIT) {
		assert(auths[parent].parent != auths[parent].id);
		return x509_auth_as_signed(cert, fn,
			auths[parent].parent, auths, authsz);
	}

	/*
	 * Now our parent is either an identifier or a range, so we can
	 * make sure that all of our identifiers fall into the
	 * parent's ranges or singular identifiers.
	 */

	for (i = 0; i < cert->asz; i++) {
		found = 0;
		as = &cert->as[i];
		switch (as->type) {
		case CERT_AS_ID:
			for (j = 0; !found && j < pcert->asz; j++) {
				pas = &pcert->as[j];
				switch (pas->type) {
				case CERT_AS_ID:
					if (as->id == pas->id)
						found = 1;
					break;
				case CERT_AS_RANGE:
					if (as->id >= pas->range.min &&
					    as->id <= pas->range.max)
						found = 1;
					break;
				default:
					abort();
				}
			}
			break;
		case CERT_AS_RANGE:
			for (j = 0; !found && j < pcert->asz; j++) {
				pas = &pcert->as[j];
				switch (pas->type) {
				case CERT_AS_ID:
					/*
					 * A range must have at least
					 * two elements, and sequential
					 * identifiers must be collapsed
					 * into a range, so this will
					 * never happen.
					 */
					break;
				case CERT_AS_RANGE:
					if (as->range.min >= 
					     pas->range.min &&
					    as->range.max <= 
					     pas->range.max)
						found = 1;
					break;
				default:
					abort();
				}
			}
			break;
		default:
			abort();
		}
		if (found == 0) {
			warnx("%s: AS identifiers don't fall "
				"into parent allocations", fn);
			return 0;
		}
	}

	return 1;
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

	/* Must not have a CRL. */

	if (cert->crl != NULL) {
		warnx("%s: RFC 6487: self-signed certificate "
			"must not have a CRL distribution point", fn);
		goto out;
	}

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

	/* Verify and append our own public key to the key cache. */

	if (!x509_auth_as_selfsigned(cert, fn))
		goto out;

	/* FIXME: same as x509_auth_as_selfsigned() but for the IPs. */

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
 * If cert is non-NULL, augments the key cache with the certificate's
 * SKI, public key, and parsed data.
 * Returns zero on failure, non-zero on success.
 */
static ssize_t
x509_auth_signed(X509 *x, const char *fn,
	struct auth **auths, size_t *authsz, struct cert *cert)
{
	int	 	 i, extsz;
	ssize_t		 rc = -1;
	size_t		 j;
	char		*ski = NULL, *aki = NULL;
	X509_EXTENSION	*ext;
	ASN1_OBJECT	*obj;
	EVP_PKEY	*pk;

	/* Get the public key, SKI, and AKI. */

	if ((pk = X509_get_pubkey(x)) == NULL) {
		cryptowarnx("%s: no public key", fn);
		return -1;
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
	} else if (!X509_verify(x, (*auths)[j].pkey)) {
		cryptowarnx("%s: RFC 6487: key verification failed", fn);
		goto out;
	}

	/* 
	 * FIXME: make sure that the AS inherits (I actually don't think
	 * this is a thing, and that inheriting certificates can do
	 * whatever they want with the AS numbers) but for sure make
	 * sure that our IP ranges are fully covered by the parent.
	 */

	/* Verify and append our own public key to the key cache. */

	if (cert != NULL) {
		if (!x509_auth_as_signed(cert, fn, j, *auths, *authsz))
			goto out;
		*auths = reallocarray(*auths,
			*authsz + 1, sizeof(struct auth));
		if (*auths == NULL)
			err(EXIT_FAILURE, NULL);
		(*auths)[*authsz].id = *authsz;
		(*auths)[*authsz].parent = j;
		(*auths)[*authsz].ski = ski;
		(*auths)[*authsz].pkey = pk;
		(*auths)[*authsz].cert = cert;
		(*auths)[*authsz].fn = strdup(fn);
		if ((*auths)[*authsz].fn == NULL)
			err(EXIT_FAILURE, NULL);
		(*authsz)++;
		ski = NULL;
		pk = NULL;
	}

	rc = j;
out:
	free(ski);
	free(aki);
	EVP_PKEY_free(pk);
	return rc;
}

int
x509_auth_signed_cert(X509 *x, const char *fn,
	struct auth **auths, size_t *authsz, struct cert *cert)
{

	/* Must have a CRL. */

	if (cert->crl == NULL) {
		warnx("%s: RFC 6487: signed certificate "
			"must have a CRL distribution point", fn);
		return 0;
	}

	return x509_auth_signed(x, fn, auths, authsz, cert) >= 0;
}

int
x509_auth_signed_mft(X509 *x, const char *fn,
	struct auth **auths, size_t *authsz, struct mft *mft)
{

	return x509_auth_signed(x, fn, auths, authsz, NULL) >= 0;
}

/*
 * Check our ROA.
 * Beyond the usual, this means checking that the AS number is covered
 * by one of the parent certificates and the IP prefix is also
 * contained.
 * Sets the "invalid" field if any of these fail.
 */
void
x509_auth_signed_roa(X509 *x, const char *fn,
	struct auth **auths, size_t *authsz, struct roa *roa)
{
	ssize_t		 c;
	size_t		 asz, i, level;
	struct cert_as	*as;

	roa->invalid = 1;

	if ((c = x509_auth_signed(x, fn, auths, authsz, NULL)) < 0)
		return;

	/*
	 * According to RFC 6483 section 4, AS 0 in an ROA means that
	 * the prefix is specifically disallowed from being routed.
	 */

	if (roa->asid > 0 &&
	    x509_auth_as(roa->asid, c, *auths, *authsz) < 0) {
		warnx("%s: uncovered AS "
			"identifier: %" PRIu32, fn, roa->asid);
		
		/* Trace coverage. */

		for (level = 0; ; level++, c = (*auths)[c].parent) {
			as = (*auths)[c].cert->as;
			asz = (*auths)[c].cert->asz;
			for (i = 0; i < asz; i++) 
				switch (as[i].type) {
				case CERT_AS_ID:
					warnx(" ...parent[%zu]: %" 
						PRIu32, level, as[i].id);
					break;
				case CERT_AS_RANGE:
					warnx(" ...parent[%zu]: %" 
						PRIu32 "--%" PRIu32, 
						level, as[i].range.min, 
						as[i].range.max);
					break;
				default:
					break;
				}
			if ((*auths)[c].parent == (size_t)c)
				break;
		}
		return;
	}

	for (i = 0; i < roa->ipsz; i++) 
		if (x509_auth_ip_addr(&roa->ips[i], c, *auths, *authsz) < 0) {
			warnx("%s: uncovered IP address", fn);
			return;
		}

	roa->invalid = 0;
}
