#ifndef __OPENSSL_COMPAT_H
#define __OPENSSL_COMPAT_H

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x10101000L
#define EVP_PKEY_get0_RSA(_pkey) ((_pkey)->pkey.rsa)
#define RSA_get0_n(_rsa) ((_rsa)->n)
#define RSA_get0_e(_rsa) ((_rsa)->e)
#define EVP_PKEY_get0_EC_KEY(_pkey) ((_pkey)->pkey.ec)
#define ECDSA_SIG_get0_r(_sig) ((_sig)->r)
#define ECDSA_SIG_get0_s(_sig) ((_sig)->s)
#define X509_get0_serialNumber X509_get_serialNumber
#endif

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#define OSSL_UNCONST(_type, _expr) (const_cast <_type *>(_expr))
#else
#define OSSL_UNCONST(_type, _expr) (_expr)
#endif

#endif /* __OPENSSL_COMPAT_H */
