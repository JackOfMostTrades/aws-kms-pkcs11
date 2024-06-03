#include <stdio.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <aws/core/Aws.h>
#include <aws/acm-pca/ACMPCAClient.h>
#include <aws/acm-pca/model/GetCertificateRequest.h>
#include <aws/acm-pca/model/GetCertificateResult.h>

#include "debug.h"
#include "openssl_compat.h"

using std::string;

X509* parseCertificateFromFile(const char* filename) {
    int res;
    long len;
    char *name, *header;
    unsigned char *data;
    X509* cert = NULL;

    FILE* f = fopen(filename, "r");
    if (f == NULL) {
        return NULL;
    }

    res = 1;
    while (res == 1) {
        res = PEM_read(f, &name, &header, &data, &len);
        if (res == 0) {
            fclose(f);
            return NULL;
        }
        if (strcmp("CERTIFICATE", name) == 0) {
            const unsigned char* d = data;
            cert = d2i_X509(NULL, &d, len);
        }
        OPENSSL_free(name);
        OPENSSL_free(header);
        OPENSSL_free(data);
        if (cert != NULL) {
            fclose(f);
            return cert;
        }
    }

    fclose(f);
    return NULL;
}

X509* parseCertificateFromB64Der(const char* b64Der) {
    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, b64Der);
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, bio_mem);
    X509* cert = d2i_X509_bio(b64, NULL);
    BIO_free_all(b64);
    return cert;
}

X509* parseCertificateFromARN(const string &ca_arn, const string &arn, const std::string &region) {
    Aws::Client::ClientConfiguration awsConfig;
#ifdef AWS_SDK_USE_SYSTEM_PROXY
    awsConfig.allowSystemProxy = true;
#endif

    if (!region.empty())
        awsConfig.region = region;
    Aws::ACMPCA::ACMPCAClient acmpca(awsConfig);
    Aws::ACMPCA::Model::GetCertificateRequest req;

    req.SetCertificateArn(arn);
    req.SetCertificateAuthorityArn(ca_arn);
    auto res = acmpca.GetCertificate(req);
    if (!res.IsSuccess()) {
        debug("Failed to retrieve certificate %s from CA %s\n", arn.c_str(), ca_arn.c_str());
        return NULL;
    }
    auto pem = res.GetResult().GetCertificate();
    auto bio = BIO_new_mem_buf((char *)pem.c_str(), -1);
    if (!bio) {
        debug("Failed to allocate BIO for cert\n");
        return NULL;
    }
    auto cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
    BIO_free(bio);
    return cert;
}
