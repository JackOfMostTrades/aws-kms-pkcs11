#include <aws/core/Aws.h>
#include <aws/kms/KMSClient.h>
#include <aws/kms/model/CreateKeyRequest.h>
#include <aws/kms/model/CreateKeyResult.h>
#include <aws/kms/model/KeySpec.h>
#include <aws/kms/model/KeyUsageType.h>
#include <string>
#include <fstream>
#include <cstring>
#include <json-c/json.h>
#include "pkcs11_compat.h"
#include "aws_kms_slot.h"
#include "util.h"
#include <vector>
#include "debug.h"

using std::string;
using std::vector;

// Externals from aws_kms_pkcs11.cpp
extern vector<AwsKmsSlot>* slots;

static const CK_OBJECT_HANDLE PRIVATE_KEY_HANDLE = 1;
static const CK_OBJECT_HANDLE PUBLIC_KEY_HANDLE = 3;

static string get_config_path() {
    const char* env = getenv("AWS_KMS_PKCS11_CONFIG");
    if (env != NULL) return string(env);
    return "/etc/aws-kms-pkcs11/config.json";
}

static void save_key_to_config(const string& label, const string& key_id, const string& region) {
    string config_path = get_config_path();
    
    // Read existing config
    json_object* config = json_object_from_file(config_path.c_str());
    if (config == NULL) {
        config = json_object_new_object();
    }
    
    // Get or create slots array
    json_object* slots_array = NULL;
    if (!json_object_object_get_ex(config, "slots", &slots_array)) {
        slots_array = json_object_new_array();
        json_object_object_add(config, "slots", slots_array);
    }
    
    // Create new slot entry
    json_object* slot = json_object_new_object();
    json_object_object_add(slot, "label", json_object_new_string(label.c_str()));
    json_object_object_add(slot, "kms_key_id", json_object_new_string(key_id.c_str()));
    if (!region.empty()) {
        json_object_object_add(slot, "aws_region", json_object_new_string(region.c_str()));
    }
    json_object_array_add(slots_array, slot);
    
    // Write back
    const char* json_str = json_object_to_json_string_ext(config, JSON_C_TO_STRING_PRETTY);
    std::ofstream out(config_path);
    out << json_str;
    out.close();
    
    json_object_put(config);
    debug("Saved new key %s (%s) to config %s", label.c_str(), key_id.c_str(), config_path.c_str());
}

CK_RV C_GenerateKeyPair(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pPublicKeyTemplate,
    CK_ULONG ulPublicKeyAttributeCount,
    CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
    CK_ULONG ulPrivateKeyAttributeCount,
    CK_OBJECT_HANDLE_PTR phPublicKey,
    CK_OBJECT_HANDLE_PTR phPrivateKey)
{
    debug("C_GenerateKeyPair called");

    if (pMechanism == NULL || phPublicKey == NULL || phPrivateKey == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    // Only support RSA key pair generation
    if (pMechanism->mechanism != CKM_RSA_PKCS_KEY_PAIR_GEN) {
        debug("Unsupported mechanism: %lu", pMechanism->mechanism);
        return CKR_MECHANISM_INVALID;
    }

    // Extract label and key size from templates
    string label;
    CK_ULONG modulus_bits = 4096; // default

    for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++) {
        if (pPublicKeyTemplate[i].type == CKA_LABEL && pPublicKeyTemplate[i].pValue != NULL) {
            label = string((char*)pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
        }
        if (pPublicKeyTemplate[i].type == CKA_MODULUS_BITS && pPublicKeyTemplate[i].pValue != NULL) {
            modulus_bits = *(CK_ULONG*)pPublicKeyTemplate[i].pValue;
        }
    }

    // Fall back to private key template for label
    if (label.empty()) {
        for (CK_ULONG i = 0; i < ulPrivateKeyAttributeCount; i++) {
            if (pPrivateKeyTemplate[i].type == CKA_LABEL && pPrivateKeyTemplate[i].pValue != NULL) {
                label = string((char*)pPrivateKeyTemplate[i].pValue, pPrivateKeyTemplate[i].ulValueLen);
            }
        }
    }

    if (label.empty()) {
        label = "generated-key";
    }

    debug("Generating RSA-%lu key pair with label: %s", modulus_bits, label.c_str());

    // Determine KMS key spec based on modulus bits
    Aws::KMS::Model::KeySpec key_spec;
    if (modulus_bits == 2048) {
        key_spec = Aws::KMS::Model::KeySpec::RSA_2048;
    } else if (modulus_bits == 3072) {
        key_spec = Aws::KMS::Model::KeySpec::RSA_3072;
    } else {
        key_spec = Aws::KMS::Model::KeySpec::RSA_4096;
    }

    // Get region from current slot
    string aws_region;
    if (slots != NULL && slots->size() > 0) {
        aws_region = slots->at(0).GetAwsRegion();
    }

    // Call KMS CreateKey
    Aws::Client::ClientConfiguration awsConfig = create_aws_config(aws_region);
    Aws::KMS::KMSClient kms(awsConfig);

    Aws::KMS::Model::CreateKeyRequest req;
    req.SetKeyUsage(Aws::KMS::Model::KeyUsageType::SIGN_VERIFY);
    req.SetKeySpec(key_spec);
    req.SetDescription(label);

    debug("Calling KMS CreateKey for label: %s", label.c_str());
    Aws::KMS::Model::CreateKeyOutcome res = kms.CreateKey(req);

    if (!res.IsSuccess()) {
        debug("KMS CreateKey failed: %s", res.GetError().GetMessage().c_str());
        return CKR_FUNCTION_FAILED;
    }

    string key_id = res.GetResult().GetKeyMetadata().GetKeyId();
    debug("KMS CreateKey succeeded, key_id: %s", key_id.c_str());

    // Save to config.json for persistence
    save_key_to_config(label, key_id, aws_region);

    // Add to in-memory slots
    if (slots != NULL) {
        slots->push_back(AwsKmsSlot(label, key_id, aws_region, NULL));
    }

    // Return object handles
    *phPrivateKey = PRIVATE_KEY_HANDLE;
    *phPublicKey = PUBLIC_KEY_HANDLE;

    debug("C_GenerateKeyPair completed successfully");
    return CKR_OK;
}
