#pragma once

#include <string>
#include <aws/core/utils/Array.h>
#include <openssl/x509.h>

using std::string;

class AwsKmsSlot {
private:
    string label;
    string aws_region;
    string kms_key_id;
    bool public_key_data_fetched;
    Aws::Utils::ByteBuffer public_key_data;
    X509* certificate;
public:
    AwsKmsSlot(string label, string kms_key_id, string aws_region, X509* certificate);
    string GetLabel();
    string GetKmsKeyId();
    string GetAwsRegion();
    X509* GetCertificate();
    Aws::Utils::ByteBuffer GetPublicKeyData();
};
