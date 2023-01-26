#pragma once

#include <string>
#include <aws/core/utils/Array.h>
#include <aws/kms/model/KeySpec.h>
#include <openssl/x509.h>

using std::string;

class AwsKmsSlot {
private:
    const string label;
    const string kms_key_id;
    const string aws_region;
    const X509* certificate;
    bool public_key_data_fetched;

    Aws::Utils::ByteBuffer public_key_data;
    Aws::KMS::Model::KeySpec key_spec;
    void FetchPublicKeyData();
public:
    AwsKmsSlot(const string &label, const string &kms_key_id, const string aws_region,
	       const X509* certificate);
    const string& GetLabel();
    const string& GetKmsKeyId();
    const string& GetAwsRegion();
    const X509* GetCertificate();
    Aws::Utils::ByteBuffer GetPublicKeyData();
    Aws::KMS::Model::KeySpec GetKeySpec();
};
