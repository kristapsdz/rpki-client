#ifndef ASN1_H
#define ASN1_H

#include <stdlib.h>
#include <openssl/ssl.h>

struct tm asn1Time2Time(ASN1_TIME* time);

#endif

