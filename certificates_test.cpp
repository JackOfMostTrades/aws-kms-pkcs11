#include "certificates.h"

int main(int argc, char** argv) {
    X509* cert = parseCertificateFromFile("test/cert.pem");
    if (cert == NULL) {
        printf("Failed to parse certificate from file.\n");
        return 1;
    }
    X509_free(cert);

    cert = parseCertificateFromB64Der("MIIBMzCB2qADAgECAhRhCYiLH5mYg8WuUXk7+QwmFqZaWjAKBggqhkjOPQQDAjARMQ8wDQYDVQQDDAZteWNlcnQwHhcNMjEwNjA1MDUwMzQ3WhcNMjIwNjA2MDUwMzQ3WjARMQ8wDQYDVQQDDAZteWNlcnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQOH6FWqrb+0jujRBi/LLCulKIy1DvLtNvQwV3N2dkM/86ieenmQF02gwaoPmQSEpsYi+swzkLiJiHxFHEP696VoxAwDjAMBgNVHRMBAf8EAjAAMAoGCCqGSM49BAMCA0gAMEUCIB0HGcO4henfTmmQbHAvp7karU25057Fjilwgz1hJEkCAiEAwoasCkulAYBdf1+L9F1+a/FGeFtel6d8G9J6VzhT/y0=");
    if (cert == NULL) {
        printf("Failed to parse B64 DER certificate.\n");
        return 1;
    }
    X509_free(cert);

    printf("Test successful.\n");
    return 0;
}
