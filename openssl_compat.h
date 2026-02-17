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

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/crypto.h>

// This class replaces the current default OpenSSL context with a clean one, putting things back in the destructor.
// Call Init() once at startup and Fini() once at shutdown.
class OsslDefaultCtxGuard {
public:
    static void Init() { ctx_ = OSSL_LIB_CTX_new(); }
    static void Fini() { OSSL_LIB_CTX_free(ctx_); ctx_ = nullptr; }

    OsslDefaultCtxGuard() {
        if (ctx_) {
            ossl_old_ctx = OSSL_LIB_CTX_set0_default(ctx_);
        }
    }
    ~OsslDefaultCtxGuard() {
        if (ossl_old_ctx) {
            OSSL_LIB_CTX_set0_default(ossl_old_ctx);
            ossl_old_ctx = nullptr;
        }
    }
    OsslDefaultCtxGuard(const OsslDefaultCtxGuard&) = delete;
    OsslDefaultCtxGuard& operator=(const OsslDefaultCtxGuard&) = delete;
private:
    inline static OSSL_LIB_CTX *ctx_ = nullptr;
    OSSL_LIB_CTX *ossl_old_ctx = nullptr;
};

#else
// OpenSSL < 3.0 does not have any global context that needs to be reset
class OsslDefaultCtxGuard {
public:
    static void Init() {}
    static void Fini() {}

    OsslDefaultCtxGuard() = default;
    ~OsslDefaultCtxGuard() = default;
    OsslDefaultCtxGuard(const OsslDefaultCtxGuard&) = delete;
    OsslDefaultCtxGuard& operator=(const OsslDefaultCtxGuard&) = delete;
};
#endif

#endif /* __OPENSSL_COMPAT_H */
