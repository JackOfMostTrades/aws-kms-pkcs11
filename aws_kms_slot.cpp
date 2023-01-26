#include <aws/core/Aws.h>
#include <aws/kms/KMSClient.h>
#include <aws/kms/model/GetPublicKeyRequest.h>
#include <openssl/x509.h>
#include <string>

#include "aws_kms_slot.h"
#include "debug.h"

using std::string;

AwsKmsSlot::AwsKmsSlot(const string &label, const string &kms_key_id, const string aws_region,
		       const X509* certificate) :
	label(label), kms_key_id(kms_key_id), aws_region(aws_region),
	certificate(certificate),
	public_key_data_fetched(false)
{
}

const string &AwsKmsSlot::GetLabel() {
    return this->label;
}
const string & AwsKmsSlot::GetAwsRegion() {
    return this->aws_region;
}
const string & AwsKmsSlot::GetKmsKeyId() {
    return this->kms_key_id;
}
const X509* AwsKmsSlot::GetCertificate() {
    return this->certificate;
}
void AwsKmsSlot::FetchPublicKeyData() {
    if (this->public_key_data_fetched) {
        return;
    }
    Aws::Client::ClientConfiguration awsConfig;
    if (!this->aws_region.empty()) {
        awsConfig.region = this->aws_region;
    }
    Aws::KMS::KMSClient kms(awsConfig);
    Aws::KMS::Model::GetPublicKeyRequest req;

    debug("Getting public key for key %s", this->kms_key_id.c_str());
    req.SetKeyId(this->kms_key_id);
    Aws::KMS::Model::GetPublicKeyOutcome res = kms.GetPublicKey(req);
    if (!res.IsSuccess()) {
        debug("Got error from AWS fetching public key for key id %s: %s", this->kms_key_id.c_str(), res.GetError().GetMessage().c_str());
        this->public_key_data = Aws::Utils::ByteBuffer();
        this->key_spec = Aws::KMS::Model::KeySpec::NOT_SET;
    } else {
        debug("Successfully fetched public key data.");
        this->public_key_data = res.GetResult().GetPublicKey();
        this->key_spec = res.GetResult().GetKeySpec();
    }
    this->public_key_data_fetched = true;
}
Aws::Utils::ByteBuffer AwsKmsSlot::GetPublicKeyData() {
    this->FetchPublicKeyData();
    return this->public_key_data;
}
Aws::KMS::Model::KeySpec AwsKmsSlot::GetKeySpec() {
    this->FetchPublicKeyData();
    return this->key_spec;
}
