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

#include <sys/socket.h>

#include <assert.h>
#include <err.h>
#include <stdarg.h>
#include <stdint.h>
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
 * Parse X509v3 authority key identifier (AKI), RFC 6487 sec. 4.8.3.
 * Returns the AKI or NULL if it could not be parsed.
 * The AKI is formatted as aa:bb:cc:dd, with each being a hex value.
 */
char *
x509_get_aki_ext(X509_EXTENSION *ext, const char *fn)
{
	const unsigned char	*d;
	const ASN1_TYPE		*t;
	const ASN1_OCTET_STRING	*os = NULL;
	ASN1_SEQUENCE_ANY	*seq = NULL;
	int			 dsz, ptag;
	long			 i, plen;
	char			 buf[4];
	char			*res = NULL;

	assert(NID_authority_key_identifier ==
	    OBJ_obj2nid(X509_EXTENSION_get_object(ext)));
	os = X509_EXTENSION_get_data(ext);
	assert(os != NULL);

	d = os->data;
	dsz = os->length;

	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		cryptowarnx("%s: RFC 6487 section 4.8.3: AKI: "
		    "failed ASN.1 sub-sequence parse", fn);
		goto out;
	}
	if (sk_ASN1_TYPE_num(seq) != 1) {
		warnx("%s: RFC 6487 section 4.8.3: AKI: "
		    "want 1 element, have %d", fn, sk_ASN1_TYPE_num(seq));
		goto out;
	}

	t = sk_ASN1_TYPE_value(seq, 0);
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
		snprintf(buf, sizeof(buf), "%02X:", d[i]);
		strlcat(res, buf, plen * 3 + 1);
	}
	res[plen * 3 - 1] = '\0';
out:
	sk_ASN1_TYPE_pop_free(seq, ASN1_TYPE_free);
	return res;
}

/*
 * Parse X509v3 subject key identifier (SKI), RFC 6487 sec. 4.8.2.
 * Returns the SKI or NULL if it could not be parsed.
 * The SKI is formatted as aa:bb:cc:dd, with each being a hex value.
 */
char *
x509_get_ski_ext(X509_EXTENSION *ext, const char *fn)
{
	const unsigned char	*d;
	const ASN1_OCTET_STRING	*os;
	ASN1_OCTET_STRING	*oss = NULL;
	int			 i, dsz;
	char			 buf[4];
	char			*res = NULL;

	assert(NID_subject_key_identifier ==
	    OBJ_obj2nid(X509_EXTENSION_get_object(ext)));

	os = X509_EXTENSION_get_data(ext);
	assert(os != NULL);
	d = os->data;
	dsz = os->length;

	if ((oss = d2i_ASN1_OCTET_STRING(NULL, &d, dsz)) == NULL) {
		cryptowarnx("%s: RFC 6487 section 4.8.2: SKI: "
		    "failed ASN.1 octet string parse", fn);
		goto out;
	}

	d = oss->data;
	dsz = oss->length;

	if (dsz != 20) {
		warnx("%s: RFC 6487 section 4.8.2: SKI: "
		    "want 20 B SHA1 hash, have %d B", fn, dsz);
		goto out;
	}

	/* Make room for [hex1, hex2, ":"]*, NUL. */

	if ((res = calloc(dsz * 3 + 1, 1)) == NULL)
		err(EXIT_FAILURE, NULL);

	for (i = 0; i < dsz; i++) {
		snprintf(buf, sizeof(buf), "%02X:", d[i]);
		strlcat(res, buf, dsz * 3 + 1);
	}
	res[dsz * 3 - 1] = '\0';
out:
	ASN1_OCTET_STRING_free(oss);
	return res;
}

/*
 * Parse the SIA url, 4.8.8.2.
 * There may be multiple different resources at this location, so throw
 * out all but the matching resource type.
 * Returns zero on failure, non-zero on success.
 */
static int
x509_sia_resource_mft(const char *fn, struct basicCertificate *cert,
	const unsigned char *d, size_t dsz)
{
	ASN1_SEQUENCE_ANY	*seq;
	const ASN1_TYPE		*t;
	int			 rc = 0, ptag;
	char			buf[128];
	long			 plen;
	enum rtype		 rt;

	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		cryptowarnx("%s: RFC 6487 section 4.8.8: SIA: "
		    "failed ASN.1 sequence parse", fn);
		goto out;
	}
	if (sk_ASN1_TYPE_num(seq) != 2) {
		warnx("%s: RFC 6487 section 4.8.8: SIA: "
		    "want 2 elements, have %d",
		    fn, sk_ASN1_TYPE_num(seq));
		goto out;
	}
	/* Composed of an OID and its continuation. */

	t = sk_ASN1_TYPE_value(seq, 0);
	if (t->type != V_ASN1_OBJECT) {
		warnx("%s: RFC 6487 section 4.8.8: SIA: "
		    "want ASN.1 object, have %s (NID %d)",
		    fn, ASN1_tag2str(t->type), t->type);
		goto out;
	}
	OBJ_obj2txt(buf, sizeof(buf), t->value.object, 1);

	/*
	 * Ignore all but id-ad-signedObject.
	 */
	if (strcmp(buf, "1.3.6.1.5.5.7.48.11")) { // id-ad-signedObject
		rc = 1;
		goto out;
	}
	if (cert->eeLocation != NULL) {
		warnx("%s: RFC 6487 section 4.8.8: SIA: "
			"MFT location already specified", fn);
		goto out;
	}

	t = sk_ASN1_TYPE_value(seq, 1);
	if (t->type != V_ASN1_OTHER) {
		warnx("%s: RFC 6487 section 4.8.8: SIA: "
			"want ASN.1 external, have %s (NID %d)",
			fn, ASN1_tag2str(t->type), t->type);
		goto out;
	}

	/* FIXME: there must be a way to do this without ASN1_frame. */

	d = t->value.asn1_string->data;
	dsz = t->value.asn1_string->length;
	if (!ASN1_frame(fn, dsz, &d, &plen, &ptag))
		goto out;

	if ((cert->eeLocation = strndup((const char *)d, plen)) == NULL)
		err(EXIT_FAILURE, NULL);

	/* Make sure it's an rsync address. */

	if (!rsync_uri_parse(NULL, NULL, NULL,
		NULL, NULL, NULL, &rt, cert->eeLocation)) {
		warnx("%s: RFC 6487 section 4.8.8: SIA: "
			"failed to parse rsync URI", fn);
		free(cert->eeLocation);
		cert->eeLocation = NULL;
		goto out;
	}

	// ToDo: Should validate the extension?
	/*
	if (rt != RTYPE_MFT && rt != RTYPE_ROA) {
		warnx("%s: RFC 6487 section 4.8.8: SIA: "
			"invalid rsync URI suffix [%s]", fn, cert->eeLocation);
		free(cert->eeLocation);
		cert->eeLocation = NULL;
		goto out;
	}
	*/

	rc = 1;
out:
	sk_ASN1_TYPE_pop_free(seq, ASN1_TYPE_free);
	return rc;
}

/*
 * Multiple locations as defined in RFC 6487, 4.8.8.1.
 * Returns zero on failure, non-zero on success.
 */
static int
x509_sia_resource(const char *fn, struct basicCertificate *cert, const unsigned char *d, size_t dsz)
{
	ASN1_SEQUENCE_ANY	*seq;
	const ASN1_TYPE		*t;
	int			 rc = 0, i;

	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		cryptowarnx("%s: RFC 6487 section 4.8.8: SIA: "
		    "failed ASN.1 sequence parse", fn);
		goto out;
	}

	for (i = 0; i < sk_ASN1_TYPE_num(seq); i++) {
		t = sk_ASN1_TYPE_value(seq, i);
		if (t->type != V_ASN1_SEQUENCE) {
			warnx("%s: RFC 6487 section 4.8.8: SIA: "
			    "want ASN.1 sequence, have %s (NID %d)",
			    fn, ASN1_tag2str(t->type), t->type);
			goto out;
		}
		d = t->value.asn1_string->data;
		dsz = t->value.asn1_string->length;
		if (!x509_sia_resource_mft(fn, cert, d, dsz))
			goto out;
	}

	rc = 1;
out:
	sk_ASN1_TYPE_pop_free(seq, ASN1_TYPE_free);
	return rc;
}

/*
 * Parse "Subject Information Access" extension, RFC 6487 4.8.8.
 * Returns zero on failure, non-zero on success.
 */
static int
x509_get_sia_ext(X509_EXTENSION *ext, const char *fn, struct basicCertificate *cert)
{
	unsigned char		*sv = NULL;
	const unsigned char	*d;
	ASN1_SEQUENCE_ANY	*seq = NULL;
	const ASN1_TYPE		*t;
	int numElem;
	int			 dsz, rc = 0;

	if ((dsz = i2d_X509_EXTENSION(ext, &sv)) < 0) {
		cryptowarnx("%s: RFC 6487 section 4.8.8: SIA: "
		    "failed extension parse", fn);
		goto out;
	}
	d = sv;

	if ((seq = d2i_ASN1_SEQUENCE_ANY(NULL, &d, dsz)) == NULL) {
		cryptowarnx("%s: RFC 6487 section 4.8.8: SIA: "
		    "failed ASN.1 sequence parse", fn);
		goto out;
	}

    numElem = sk_ASN1_TYPE_num(seq);
    // Optionally may have a BOOL at position 1 (0-based)
	if (numElem != 2 && numElem != 3) {
		warnx("%s: RFC 6487 section 4.8.8: SIA: "
		    "want 2 elements, have %d", fn,
		    sk_ASN1_TYPE_num(seq));
		goto out;
	}
	t = sk_ASN1_TYPE_value(seq, 0);
	if (t->type != V_ASN1_OBJECT) {
		warnx("%s: RFC 6487 section 4.8.8: SIA: "
		    "want ASN.1 object, have %s (NID %d)",
		    fn, ASN1_tag2str(t->type), t->type);
		goto out;
	}
	if (OBJ_obj2nid(t->value.object) != NID_sinfo_access) {
		warnx("%s: RFC 6487 section A.1 Extension: "
			"want BOOL, have %s (NID %d)",
			fn, ASN1_tag2str(t->type), t->type);
		goto out;
	}

    if (numElem == 3) {
		t = sk_ASN1_TYPE_value(seq, 1);
		if (t->type != V_ASN1_BOOLEAN) {
			warnx("%s: RFC 5280 section 4.8.8: SIA: "
				"want ASN.1 object, have %s (NID %d)",
				fn, ASN1_tag2str(t->type), t->type);
			goto out;
		}
	}

	t = sk_ASN1_TYPE_value(seq, numElem - 1);
	if (t->type != V_ASN1_OCTET_STRING) {
		warnx("%s: RFC 6487 section 4.8.8: SIA: "
		    "want ASN.1 octet string, have %s (NID %d)",
		    fn, ASN1_tag2str(t->type), t->type);
		goto out;
	}

	d = t->value.octet_string->data;
	dsz = t->value.octet_string->length;
	if (!x509_sia_resource(fn, cert, d, dsz))
		goto out;

	rc = 1;
out:
	sk_ASN1_TYPE_pop_free(seq, ASN1_TYPE_free);
	free(sv);
	return rc;
}

/*
 * Wraps around x509_get_ski_ext and x509_get_aki_ext.
 * Returns zero on failure (out pointers are NULL) or non-zero on
 * success (out pointers must be freed).
 */
static int x509_get_extensions(X509 *x, const char *fn, struct basicCertificate *cert)
{
	X509_EXTENSION		*ext = NULL;
	const ASN1_OBJECT	*obj;
	int			 extsz, i;

	cert->ski = cert->aki = NULL;

	if ((extsz = X509_get_ext_count(x)) < 0)
		cryptoerrx("X509_get_ext_count");

	for (i = 0; i < extsz; i++) {
		ext = X509_get_ext(x, i);
		assert(ext != NULL);
		obj = X509_EXTENSION_get_object(ext);
		assert(obj != NULL);
		switch (OBJ_obj2nid(obj)) {

		case NID_sinfo_access:
			if (cert->eeLocation != NULL) {
				free(cert->eeLocation);
			}
			x509_get_sia_ext(ext, fn, cert);
			break;
		case NID_subject_key_identifier:
			if (cert->ski != NULL) {
				free(cert->ski);
			}
			cert->ski = x509_get_ski_ext(ext, fn);
			break;
		case NID_authority_key_identifier:
			if (cert->aki != NULL) {
				free(cert->aki);
			}
			cert->aki = x509_get_aki_ext(ext, fn);
			break;
		}
	}
	return 1;
}

int x509Basic_parse(X509 *x509, const char *fn, struct basicCertificate *cert, int isResourceCertificate) {
	ASN1_INTEGER *srl;
	ASN1_TIME *t;
	struct tm tm;
	time_t tt;

	x509_get_extensions(x509, fn, cert);
	if (isResourceCertificate) {
		// Resource Certificate must have aki and ski extensions
		if (cert->aki == NULL) {
			cryptowarnx("%s: RFC 6487 section 4.8.3: AKI: "
				"missing AKI X509 extension", fn);
			if (cert->ski != NULL) {
				free(cert->ski);
				cert->ski = NULL;
			}
			return 0;
		}
		if (cert->ski == NULL) {
			cryptowarnx("%s: RFC 6487 section 4.8.2: AKI: "
				"missing SKI X509 extension", fn);
			if (cert->aki != NULL) {
				free(cert->aki);
				cert->aki = NULL;
			}
			return 0;
		}
	}
    t = X509_get_notBefore(x509);
	tm = asn1Time2Time(t);
	tt = mktime(&tm);
    memcpy(&cert->notBefore, &tt, sizeof (time_t));

    t = X509_get_notAfter(x509);
	tm = asn1Time2Time(t);
	tt = mktime(&tm);
    memcpy(&cert->notAfter, &tt, sizeof (time_t));

	srl = X509_get_serialNumber(x509);
	if (srl != NULL) {
		BIGNUM *bnSrl = ASN1_INTEGER_to_BN(srl, NULL);
		if (bnSrl != NULL) {
			cert->serial = BN_bn2hex(bnSrl);
			BN_free(bnSrl);
		}
	}
    cert->subject = X509_NAME_oneline(X509_get_subject_name(x509), NULL, 0);
	cert->version = X509_get_version(x509) + 1; // 0-based -> 1-based
	cert->issuerName = X509_NAME_oneline(X509_get_issuer_name(x509), NULL, 0);
	return 1;
}

void x509Basic_free(struct basicCertificate *cert) {
    if (cert != NULL) {
        if (cert->serial != NULL) {
	        OPENSSL_free(cert->serial);
        }
        if (cert->issuerName != NULL) {
	        OPENSSL_free(cert->issuerName);
        }
        if (cert->subject != NULL) {
	        OPENSSL_free(cert->subject);
        }
        if (cert->aki != NULL) {
	        free(cert->aki);
        }
        if (cert->ski != NULL) {
	        free(cert->ski);
        }
		if (cert->eeLocation != NULL) {
			free(cert->eeLocation);
		}
    }
}
