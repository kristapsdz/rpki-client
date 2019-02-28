#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/cms.h>

#include "extern.h"

/*
 * Parse and validate a self-signed CMS message, where the signing X509
 * certificate has been signed by cacert.
 * The eContentType of the message must be an oid object.
 * Return the eContent as an octet string or NULL on failure.
 */
const ASN1_OCTET_STRING *
cms_parse_validate(int verb, 
	X509 *cacert, const char *fn, const char *oid)
{
	const ASN1_OBJECT  *obj;
	ASN1_OCTET_STRING **os = NULL;
	BIO 		   *bio = NULL;
	CMS_ContentInfo    *cms;
	char 		    buf[128];
	int		    rc = 0;
	STACK_OF(X509)	   *certs = NULL;
	X509		   *cert;

	/* Parse CMS file from input. */

	if (NULL == (bio = BIO_new_file(fn, "rb"))) {
		CRYPTOX(verb, "%s: BIO_new_file", fn);
		goto out;
	} else if (NULL == (cms = d2i_CMS_bio(bio, NULL))) {
		CRYPTOX(verb, "%s: d2i_CMS_bio", fn);
		goto out;
	}

	/* Check the CMS object's eContentType. */

	obj = CMS_get0_eContentType(cms);
	OBJ_obj2txt(buf, sizeof(buf), obj, 1);
	if (strcmp(buf, oid)) {
		WARNX(verb, "%s: incorrect OID value", fn);
		goto out;
	}

	/*
	 * The CMS is self-signed with a signing certifiate which must
	 * be signed by the public key.
	 */

	if (NULL != cacert) {
		if ( ! CMS_verify(cms, NULL, NULL, 
		     NULL, NULL, CMS_NO_SIGNER_CERT_VERIFY)) {
			CRYPTOX(verb, "%s: CMS_verify", fn);
			goto out;
		}
		LOG(verb, "%s: verified CMS", fn);

		certs = CMS_get0_signers(cms);
		if (NULL == certs ||
		    1 != sk_X509_num(certs)) {
			WARNX(verb, "%s: need single signer", fn);
			goto out;
		}

		cert = sk_X509_value(certs, 0);
		if (X509_verify(cert, X509_get_pubkey(cacert)) <= 0) {
			CRYPTOX(verb, "%s: X509_verify", fn);
			goto out;
		} 

		LOG(verb, "%s: verified signer", fn);
	}

	/* Extract eContents and pass to output function. */

	if (NULL == (os = CMS_get0_content(cms)) || NULL == *os)
		WARNX(verb, "%s: empty CMS content", fn);
	else
		rc = 1;
out:
	BIO_free(bio);
	sk_X509_free(certs);
	return rc ? *os : NULL;
}
