#include <openssl/x509.h>

X509* parseCertificateFromFile(const char* filename);
X509* parseCertificateFromB64Der(const char* b64Der);
