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
#include <assert.h>
#include <err.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/cms.h>

#include "extern.h"

/*
 * Parse and validate a self-signed CMS message, where the signing X509
 * certificate has been hashed to dgst (optional).
 * Conforms to RFC 6488.
 * The eContentType of the message must be an oid object.
 * Return the eContent as an octet string or NULL on "soft" failure.
 */
const ASN1_OCTET_STRING *
cms_parse_validate(X509 **xp, const char *fn,
	const char *oid, const unsigned char *dgst)
{
	const ASN1_OBJECT  *obj;
	ASN1_OCTET_STRING **os = NULL;
	BIO 		   *bio = NULL, *shamd;
	CMS_ContentInfo    *cms;
	char 		    buf[128];
	int		    rc = 0, sz;
	STACK_OF(X509)	   *certs = NULL;
	EVP_MD		   *md;
	unsigned char	    mdbuf[EVP_MAX_MD_SIZE];

	*xp = NULL;

	if ((bio = BIO_new_file(fn, "rb")) == NULL)
		cryptoerrx("%s: BIO_new_file", fn);

	/*
	 * If we have a digest specified, create an MD chain that will
	 * automatically compute a digest during the CMS creation.
	 */

	if (dgst != NULL) {
		if ((shamd = BIO_new(BIO_f_md())) == NULL)
			cryptoerrx("BIO_new");
		if (!BIO_set_md(shamd, EVP_sha256()))
			cryptoerrx("BIO_set_md");
		if ((bio = BIO_push(shamd, bio)) == NULL)
			cryptoerrx("BIO_push");
	}

	if ((cms = d2i_CMS_bio(bio, NULL)) == NULL) {
		cryptowarnx("%s: d2i_CMS_bio", fn);
		goto out;
	}

	/*
	 * If we have a digest, find it in the chain (we'll already have
	 * made it, so assert otherwise) and verify it.
	 */

	if (dgst != NULL) {
		shamd = BIO_find_type(bio, BIO_TYPE_MD);
		assert(shamd != NULL);

		if (!BIO_get_md(shamd, &md))
			cryptoerrx("BIO_get_md");
		assert(EVP_MD_type(md) == NID_sha256);

		if ((sz = BIO_gets(shamd, mdbuf, EVP_MAX_MD_SIZE)) < 0)
			cryptoerrx("BIO_gets");
		assert(sz == SHA256_DIGEST_LENGTH);

		if (memcmp(mdbuf, dgst, SHA256_DIGEST_LENGTH)) {
			warnx("%s: bad message digest", fn);
			goto out;
		}
	}

	/* RFC 6488 section 2.1.3.1: check the object's eContentType. */

	obj = CMS_get0_eContentType(cms);
	if ((sz = OBJ_obj2txt(buf, sizeof(buf), obj, 1)) < 0)
		cryptoerrx("OBJ_obj2txt");

	if ((size_t)sz >= sizeof(buf)) {
		warnx("%s: OID too long", fn);
		goto out;
	} else if (strcmp(buf, oid)) {
		warnx("%s: bad content type: %s, want %s", fn, buf, oid);
		goto out;
	}

	/*
	 * The CMS is self-signed with a signing certifiate.
	 * Verify that the self-signage is correct.
	 */

	if (!CMS_verify(cms, NULL, NULL, 
	    NULL, NULL, CMS_NO_SIGNER_CERT_VERIFY)) {
		cryptowarnx("%s: CMS_verify", fn);
		goto out;
	}

	/*
	 * The self-signing certificate is further signed by the input
	 * signing authority according to RFC 6488, 2.1.4.
	 * We extract that certificate now for later verification.
	 */

	certs = CMS_get0_signers(cms);
	if (certs == NULL || sk_X509_num(certs) != 1) {
		warnx("%s: multiple signers", fn);
		goto out;
	}
	*xp = X509_dup(sk_X509_value(certs, 0));

	/* Extract eContent and pass to output function. */

	if ((os = CMS_get0_content(cms)) == NULL || *os == NULL) {
		warnx("%s: empty content", fn);
		goto out;
	}

	rc = 1;
out:
	BIO_free_all(bio);
	sk_X509_free(certs);

	if (rc == 0) {
		X509_free(*xp);
		*xp = NULL;
	}

	return (rc == 0) ? NULL : *os;
}
