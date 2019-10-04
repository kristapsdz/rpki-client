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

#include <arpa/inet.h>
#include <sys/socket.h>

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <memory.h>
#include <openssl/ssl.h>

#include "extern.h"
#include "test-core.h"

static unsigned char ToAsc (unsigned char c)
{
	unsigned char nib = c & 0x0f;
  	if (nib <= 9)
    	return (nib + '0');
	return (nib - 10 + 'a');
}

void hex_encode (unsigned char *lpcAsc, unsigned char *lpcBcd, size_t szBcd)
{
	size_t i;
	for (i = 0; i < szBcd; i++) {
		*lpcAsc++ = ToAsc (lpcBcd[i] >> 4);
		*lpcAsc++ = ToAsc (lpcBcd[i]);
	}
}

void print_sep_line (const char *title, size_t count)
{
	size_t i;

	if (title && *title) {
		printf ("%s ", title);
		count -= strlen(title) + 1;
	}
	for (i = 0; i < count; i++) {
		printf("=");
	}
	printf("\n");
}

void print_cert(const struct cert *p)
{
	size_t	 i;
	char	 buf1[64], buf2[64];
	int	 sockt;
	char caNotAfter[64], caNotBefore[64], caNow[64];
	time_t now;
	struct tm *tm;

	assert(p != NULL);

    now = time(NULL);
	tm = gmtime(&now);
	strftime(caNow, sizeof(caNow)-1, "%Y-%m-%d %H:%M:%S GMT", tm);

	tm = gmtime(&p->basic.notBefore);
	strftime(caNotBefore, sizeof(caNotBefore)-1, "%Y-%m-%d %H:%M:%S GMT", tm);

	tm = gmtime(&p->basic.notAfter);
	strftime(caNotAfter, sizeof(caNotAfter)-1, "%Y-%m-%d %H:%M:%S GMT", tm);

	printf("%*.*s: %s\n", TAB, TAB, "Now", caNow);
	print_sep_line("Certificate", 110);
	printf("%*.*s: %ld\n", TAB, TAB, "Version", p->basic.version);
	printf("%*.*s: %s\n", TAB, TAB, "Serial", p->basic.serial);
	printf("%*.*s: %s\n", TAB, TAB, "Issuer", p->basic.issuerName);
	printf("%*.*s: %s\n", TAB, TAB, "Subject", p->basic.subject);
	printf("%*.*s: %s\n", TAB, TAB, "Not Before", caNotBefore);
	printf("%*.*s: %s\n", TAB, TAB, "Not After", caNotAfter);
	printf("%*.*s: %s\n", TAB, TAB, "Subject key identifier", p->basic.ski);
	if (p->basic.aki != NULL) {
		printf("%*.*s: %s\n", TAB, TAB, "Authority key identifier", p->basic.aki);
	}

	printf("%*.*s: %s\n", TAB, TAB, "Manifest", p->mft);
	if (p->rep != NULL) {
		printf("%*.*s: %s\n", TAB, TAB, "Repository", p->rep);
	}
	if (p->crl != NULL) {
		printf("%*.*s: %s\n", TAB, TAB, "Revocation list", p->crl);
	}
	for (i = 0; i < p->asz; i++)
		switch (p->as[i].type) {
		case CERT_AS_ID:
			printf("%*zu: AS: %"
				PRIu32 "\n", TAB, i + 1, p->as[i].id);
			break;
		case CERT_AS_INHERIT:
			printf("%*zu: AS: inherit\n", TAB, i + 1);
			break;
		case CERT_AS_RANGE:
			printf("%*zu: AS: %"
				PRIu32 "-%" PRIu32 "\n", TAB, i + 1,
				p->as[i].range.min, p->as[i].range.max);
			break;
		}

	for (i = 0; i < p->ipsz; i++)
		switch (p->ips[i].type) {
		case CERT_IP_INHERIT:
			printf("%*zu: IP: inherit\n", TAB, i + 1);
			break;
		case CERT_IP_ADDR:
			ip_addr_print(&p->ips[i].ip,
				p->ips[i].afi, buf1, sizeof(buf1));
			printf("%*zu: IP: %s\n",TAB,  i + 1, buf1);
			break;
		case CERT_IP_RANGE:
			sockt = (p->ips[i].afi == AFI_IPV4) ?
				AF_INET : AF_INET6;
			inet_ntop(sockt, p->ips[i].min, buf1, sizeof(buf1));
			inet_ntop(sockt, p->ips[i].max, buf2, sizeof(buf2));
			printf("%*zu: IP: %s-%s\n", TAB, i + 1, buf1, buf2);
			break;
		}
}

// http://www.geo-complex.com/shares/soft/unix/CentOS/OpenVPN/openssl-1.1.0c/crypto/x509/x_crl.c
void print_crl (const X509_CRL *p)
{
	int i, numRevoked;
	char caRevocationDate[64];
	char caLast[64], caNext[64], caNow[64];
	char *issuerName;
	time_t now;
	struct tm tm;
	STACK_OF(X509_REVOKED) *revoked;

	assert(p != NULL);

    now = time(NULL);
	strftime(caNow, sizeof(caNow)-1, "%Y-%m-%d %H:%M:%S GMT", gmtime(&now));

	revoked = X509_CRL_get_REVOKED(p);

	tm = asn1Time2Time(p->crl->lastUpdate);
	strftime(caLast, sizeof(caLast)-1, "%Y-%m-%d %H:%M:%S GMT", &tm);

	tm = asn1Time2Time(p->crl->nextUpdate);
	strftime(caNext, sizeof(caNext)-1, "%Y-%m-%d %H:%M:%S GMT", &tm);

	printf("%*.*s: %s\n", TAB, TAB, "Now", caNow);
	print_sep_line("Certificate Revocation List", 110);
	printf("%*.*s: %ld\n", TAB, TAB, "Version", ASN1_INTEGER_get(p->crl->version) + 1);
	printf("%*.*s: %ld\n", TAB, TAB, "CRL Number", ASN1_INTEGER_get(p->crl_number));

	issuerName = X509_NAME_oneline(p->crl->issuer, NULL, 0);
	if (issuerName != NULL) {
		printf("%*.*s: %s\n", TAB, TAB, "Issuer", issuerName);
		OPENSSL_free(issuerName);
	}

	printf("%*.*s: %s\n", TAB, TAB, "Last Update", caLast);
	printf("%*.*s: %s\n", TAB, TAB, "Next Update", caNext);

	numRevoked = sk_X509_REVOKED_num(revoked);
	if (numRevoked > 0) {
		print_sep_line("Revoked Certificates", 110);
		for (i = 0; i < numRevoked; i++) {
			X509_REVOKED *rev = sk_X509_REVOKED_value(revoked, i);
			if (rev != NULL) {
				BIGNUM *bnSrl = ASN1_INTEGER_to_BN(rev->serialNumber, NULL);
				if (bnSrl != NULL) {
					char *lpcSrl = BN_bn2hex(bnSrl);
					if (lpcSrl != NULL) {
						printf("%*.*s: %s\n", TAB, TAB, "Serial Number", lpcSrl);
						OPENSSL_free(lpcSrl);
					}
					BN_free(bnSrl);
				}
			}
			tm = asn1Time2Time(rev->revocationDate);
			strftime(caRevocationDate, sizeof(caRevocationDate)-1, "%Y-%m-%d %H:%M:%S GMT", &tm);
			printf("%*.*s:    %s\n", TAB, TAB, "Revokation Date", caRevocationDate);
		}
	}
}

void print_mft(const struct mft *p)
{
	size_t	 i;
	unsigned char caSHA256[64 + 1];
	char caNotAfter[64], caNotBefore[64], caThis[64], caNext[64], caNow[64];
	time_t now;
	struct tm *tm;

	assert(p != NULL);

    now = time(NULL);
	tm = gmtime(&now);
	strftime(caNow, sizeof(caNow)-1, "%Y-%m-%d %H:%M:%S GMT", tm);

	tm = gmtime(&p->thisUpdate);
	strftime(caThis, sizeof(caThis)-1, "%Y-%m-%d %H:%M:%S GMT", tm);

	tm = gmtime(&p->nextUpdate);
	strftime(caNext, sizeof(caNext)-1, "%Y-%m-%d %H:%M:%S GMT", tm);

	tm = gmtime(&p->eeCert.notBefore);
	strftime(caNotBefore, sizeof(caNotBefore)-1, "%Y-%m-%d %H:%M:%S GMT", tm);

	tm = gmtime(&p->eeCert.notAfter);
	strftime(caNotAfter, sizeof(caNotAfter)-1, "%Y-%m-%d %H:%M:%S GMT", tm);

	printf("%*.*s: %s\n", TAB, TAB, "Now", caNow);
	print_sep_line("EE Certificate", 110);
	printf("%*.*s: %ld\n", TAB, TAB, "Version", p->eeCert.version);
	printf("%*.*s: %s\n", TAB, TAB, "Serial", p->eeCert.serial);
	printf("%*.*s: %s\n", TAB, TAB, "Issuer", p->eeCert.issuerName);
	printf("%*.*s: %s\n", TAB, TAB, "Subject", p->eeCert.subject);
	printf("%*.*s: %s\n", TAB, TAB, "Not Before", caNotBefore);
	printf("%*.*s: %s\n", TAB, TAB, "Not After", caNotAfter);
	printf("%*.*s: %s\n", TAB, TAB, "Subject Info Access", p->eeCert.eeLocation);
	printf("%*.*s: %s\n", TAB, TAB, "Subject key identifier", p->eeCert.ski);
	printf("%*.*s: %s\n", TAB, TAB, "Authority key identifier", p->eeCert.aki);
	print_sep_line("Manifest", 110);

	printf("%*.*s: %ld\n", TAB, TAB, "Manifest Number", p->manifestNumber);
	printf("%*.*s: %s\n", TAB, TAB, "This Update", caThis);
	printf("%*.*s: %s\n", TAB, TAB, "Next Update", caNext);
	for (i = 0; i < p->filesz; i++) {
		memset (caSHA256, 0, sizeof (caSHA256));
		hex_encode(caSHA256, p->files[i].hash, 32);
		printf("%s  %s\n", caSHA256, p->files[i].file);
	}
}

// ROA
void print_roa(const struct roa *p)
{
	char	 buf[128];
	size_t	 i;
	char caNotAfter[64], caNotBefore[64], caNow[64];
	time_t now;
	struct tm *tm;

	assert(p != NULL);

    now = time(NULL);
	tm = gmtime(&now);
	strftime(caNow, sizeof(caNow)-1, "%Y-%m-%d %H:%M:%S GMT", tm);

	tm = gmtime(&p->eeCert.notBefore);
	strftime(caNotBefore, sizeof(caNotBefore)-1, "%Y-%m-%d %H:%M:%S GMT", tm);

	tm = gmtime(&p->eeCert.notAfter);
	strftime(caNotAfter, sizeof(caNotAfter)-1, "%Y-%m-%d %H:%M:%S GMT", tm);

	printf("%*.*s: %s\n", TAB, TAB, "Now", caNow);
	print_sep_line("EE Certificate", 110);
	printf("%*.*s: %ld\n", TAB, TAB, "Version", p->eeCert.version);
	printf("%*.*s: %s\n", TAB, TAB, "Serial", p->eeCert.serial);
	printf("%*.*s: %s\n", TAB, TAB, "Issuer", p->eeCert.issuerName);
	printf("%*.*s: %s\n", TAB, TAB, "Subject", p->eeCert.subject);
	printf("%*.*s: %s\n", TAB, TAB, "Not Before", caNotBefore);
	printf("%*.*s: %s\n", TAB, TAB, "Not After", caNotAfter);
	printf("%*.*s: %s\n", TAB, TAB, "Subject Info Access", p->eeCert.eeLocation);
	printf("%*.*s: %s\n", TAB, TAB, "Subject key identifier", p->eeCert.ski);
	printf("%*.*s: %s\n", TAB, TAB, "Authority key identifier", p->eeCert.aki);
	print_sep_line("ROA", 110);
	printf("%*.*s: %" PRIu32 "\n", TAB, TAB, "asID", p->asid);
	for (i = 0; i < p->ipsz; i++) {
		ip_addr_print(&p->ips[i].addr,
			p->ips[i].afi, buf, sizeof(buf));
		printf("%*zu: %s (max: %zu)\n", TAB, i + 1,
			buf, p->ips[i].maxlength);
	}
}

// TAL
void print_tal(const struct tal *p)
{
	size_t	 i;

	assert(p != NULL);

	for (i = 0; i < p->urisz; i++)
		printf("%5zu: URI: %s\n", i + 1, p->uri[i]);
}
