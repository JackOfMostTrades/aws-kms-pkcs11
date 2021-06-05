#include <stdio.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

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
