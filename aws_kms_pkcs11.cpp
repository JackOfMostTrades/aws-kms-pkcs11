#include <assert.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <json.h>

#include <algorithm>
#include <vector>

#include <aws/core/Aws.h>
#include <aws/kms/KMSClient.h>
#include <aws/kms/model/ListKeysRequest.h>
#include <aws/kms/model/SignRequest.h>

#include "pkcs11_compat.h"
#include "attributes.h"
#include "aws_kms_slot.h"
#include "certificates.h"
#include "debug.h"
#include "unsupported.h"

using std::string;
using std::vector;

static_assert(sizeof(CK_SESSION_HANDLE) >= sizeof(void*), "Session handles are not big enough to hold a pointer to the session struct on this architecture");
static_assert(sizeof(CK_OBJECT_HANDLE) >= sizeof(void*), "Object handles are not big enough to hold a pointer to the session struct on this architecture");

static const CK_OBJECT_HANDLE PRIVATE_KEY_HANDLE = 0;
static const CK_OBJECT_HANDLE CERTIFICATE_HANDLE = 1;
static const CK_OBJECT_HANDLE FIRST_OBJECT_HANDLE = PRIVATE_KEY_HANDLE;
static const CK_OBJECT_HANDLE LAST_OBJECT_HANDLE = CERTIFICATE_HANDLE;

typedef struct _session {
    CK_SLOT_ID slot_id;
    CK_ATTRIBUTE_PTR find_objects_template;
    CK_ULONG find_objects_template_count;
    unsigned long find_objects_index;

    CK_MECHANISM_TYPE sign_mechanism;
} CkSession;

static Aws::SDKOptions options;
static vector<AwsKmsSlot>* slots = NULL;
static vector<CkSession*>* active_sessions = NULL;

static CK_RV load_config(json_object** config) {
    vector<string> config_paths;
    config_paths.push_back("/etc/aws-kms-pkcs11/config.json");

    const char* xdg_config_home_cstr = getenv("XDG_CONFIG_HOME");
    string xdg_config_home;
    if (xdg_config_home_cstr != NULL){
        xdg_config_home = string(xdg_config_home_cstr);
    } else {
        const char* user_home = getenv("HOME");
        if (user_home != NULL) {
            xdg_config_home = string(user_home) + "/.config";
        }
    }
    if (xdg_config_home.length() > 0) {
        config_paths.push_back(xdg_config_home + "/aws-kms-pkcs11/config.json");
    }

    std::reverse(config_paths.begin(), config_paths.end());
    for (size_t i = 0; i < config_paths.size(); i++) {
        string path = config_paths.at(i);
        debug("Attempting to load config from path: %s", path.c_str());

        FILE* f = fopen(path.c_str(), "r");
        if (f == NULL) {
            debug("Skipping config because we couldn't open the file.");
            continue;
        }

        fseek(f, 0L, SEEK_END);
        size_t file_size = ftell(f);
        fseek(f, 0L, SEEK_SET);

        char* buffer = (char*)malloc(file_size);
        if (buffer == NULL) {
            fclose(f);
            return CKR_HOST_MEMORY;
        }

        size_t actual = fread(buffer, file_size, 1, f);
        fclose(f);
        if (actual != 1) {
            free(buffer);
            return CKR_FUNCTION_FAILED;
        }

        struct json_tokener* tok = json_tokener_new();
        struct json_object* conf = json_tokener_parse_ex(tok, buffer, file_size);
        json_tokener_free(tok);
        free(buffer);

        if (conf != NULL) {
            *config = conf;
            return CKR_OK;
        } else {
            debug("Failed to parse config: %s", path.c_str());
        }
    }

    *config = json_object_new_object();
    return CKR_OK;
}

CK_RV C_Initialize(CK_VOID_PTR pInitArgs) {
    debug_enabled = CK_FALSE;
    const char* debug_env_var = getenv("AWS_KMS_PKCS11_DEBUG");
    if (debug_env_var != NULL) {
        if (strlen(debug_env_var) > 0) {
            debug_enabled = CK_TRUE;
            debug("Debug enabled.");
        }
    }

    Aws::SDKOptions options;
    Aws::InitAPI(options);

    json_object* config = NULL;
    CK_RV res = load_config(&config);
    if (res != CKR_OK || config == NULL) {
        debug("Failed to load config.");
        return res;
    }

    active_sessions = new vector<CkSession*>();
    slots = new vector<AwsKmsSlot>();
    struct json_object* slots_array;
    if (json_object_object_get_ex(config, "slots", &slots_array) && json_object_is_type(slots_array, json_type_array)) {
        for (size_t i = 0; i < json_object_array_length(slots_array); i++) {
            struct json_object* slot_item = json_object_array_get_idx(slots_array, i);
            if (json_object_is_type(slot_item, json_type_object)) {
                struct json_object* val;
                string label;
                string kms_key_id;
                string aws_region;
                X509* certificate = NULL;
                if (json_object_object_get_ex(slot_item, "label", &val) && json_object_is_type(val, json_type_string)) {
                    label = string(json_object_get_string(val));
                }
                if (json_object_object_get_ex(slot_item, "kms_key_id", &val) && json_object_is_type(val, json_type_string)) {
                    kms_key_id = string(json_object_get_string(val));
                }
                if (json_object_object_get_ex(slot_item, "aws_region", &val) && json_object_is_type(val, json_type_string)) {
                    aws_region = string(json_object_get_string(val));
                }
                if (json_object_object_get_ex(slot_item, "certificate", &val) && json_object_is_type(val, json_type_string)) {
                    debug("Parsing certificate for slot: %s", label.c_str());
                    certificate = parseCertificateFromB64Der(json_object_get_string(val));
                    if (certificate == NULL) {
                        debug("Failed to parse certificate for slot: %s", label.c_str());
                    }
                }
                if (json_object_object_get_ex(slot_item, "certificate_path", &val) && json_object_is_type(val, json_type_string)) {
                    const char* certificate_path = json_object_get_string(val);
                    debug("Parsing certificate for slot %s from path %s", label.c_str(), certificate_path);
                    certificate = parseCertificateFromFile(certificate_path);
                    if (certificate == NULL) {
                        debug("Failed to parse certificate_path for slot: %s", label.c_str());
                    }
                }
                slots->push_back(AwsKmsSlot(label, kms_key_id, aws_region, certificate));
            }
        }
    }
    json_object_put(config);

    if (slots->size() == 0) {
        debug("No KMS key ids configured; listing all keys.");
        Aws::Client::ClientConfiguration awsConfig;
        Aws::KMS::KMSClient kms(awsConfig);
        Aws::KMS::Model::ListKeysRequest req;
        req.SetLimit(1000);
        bool has_more = true;
        while (has_more) {
            Aws::KMS::Model::ListKeysOutcome res = kms.ListKeys(req);
            if (!res.IsSuccess()) {
                debug("Got error from AWS list keys: %s", res.GetError().GetMessage().c_str());
                C_Finalize(NULL_PTR);
                return CKR_FUNCTION_FAILED;
            }

            for (size_t i = 0; i < res.GetResult().GetKeys().size(); i++) {
                slots->push_back(AwsKmsSlot(string(), res.GetResult().GetKeys().at(i).GetKeyId(), string(), NULL));
            }

            has_more = res.GetResult().GetTruncated();
            if (has_more) {
                req.SetMarker(res.GetResult().GetNextMarker());
            }
        }
    }

    if (slots->size() == 0) {
        debug("No slots were configured and no KMS keys could be listed via an API call.");
        C_Finalize(NULL_PTR);
        return CKR_FUNCTION_FAILED;
    }

    debug("Configured slots:");
    for (size_t i = 0; i < slots->size(); i++) {
        debug("  %s", slots->at(i).GetKmsKeyId().c_str());
    }

    return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
    debug("Cleaning PKCS#11 provider.");

    if (slots != NULL) {
        for (size_t i = 0; i < slots->size(); i++) {
            AwsKmsSlot& slot = slots->at(i);
            X509* cert = slot.GetCertificate();
            if (cert != NULL) {
                X509_free(cert);
            }
        }

        delete slots;
        slots = NULL;
    }
    if (active_sessions != NULL) {
        if (active_sessions->size() > 0) {
            debug("There are still active sessions!");
        }
        delete active_sessions;
        active_sessions = NULL;
    }

    Aws::SDKOptions options;
    Aws::ShutdownAPI(options);

    return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo) {
    if (pInfo == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }
    memset(pInfo, 0, sizeof(*pInfo));
    pInfo->cryptokiVersion.major = 2;
    pInfo->cryptokiVersion.minor = 4;
    return CKR_OK;
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
    if (pulCount == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }
    if (pSlotList != NULL_PTR) {
        if (*pulCount < slots->size()) {
            return CKR_BUFFER_TOO_SMALL;
        }
        for (size_t i = 0; i < slots->size(); i++) {
            pSlotList[i] = i;
        }
    }
    *pulCount = slots->size();
    return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
    if (slotID < 0 || slotID >= slots->size()) {
        return CKR_SLOT_ID_INVALID;
    }
    if (pInfo == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    memset(pInfo, 0, sizeof(*pInfo));
    pInfo->flags = CKF_TOKEN_PRESENT;
    return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
    if (slotID < 0 || slotID >= slots->size()) {
        return CKR_SLOT_ID_INVALID;
    }
    if (pInfo == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }
    AwsKmsSlot& slot = slots->at(slotID);

    memset(pInfo, 0, sizeof(*pInfo));
    pInfo->flags = CKF_TOKEN_INITIALIZED;

    string label = slot.GetLabel();
    if (label.length() == 0) {
        label = slot.GetKmsKeyId();
    }
    size_t label_len = label.length();
    if (label_len > 32) {
        label_len = 32;
    }
    memset(pInfo->label, ' ', 32);
    memcpy(pInfo->label, label.c_str(), label_len);
    return CKR_OK;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
    return CKR_OK;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession) {
    return CKR_OK;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY notify, CK_SESSION_HANDLE_PTR phSession) {
    if (slotID < 0 || slotID >= slots->size()) {
        return CKR_SLOT_ID_INVALID;
    }

    CkSession* session = (CkSession*)malloc(sizeof(CkSession));
    if (session == NULL) {
        return CKR_HOST_MEMORY;
    }
    session->slot_id = slotID;

    *phSession = (CK_SESSION_HANDLE)session;
    return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
    CkSession *session = (CkSession*)hSession;
    if (session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    for (auto it = active_sessions->begin(); it != active_sessions->end(); ) {
        if (*it == session) {
            active_sessions->erase(it);
        } else {
            it++;
        }
    }
    free(session);
    return CKR_OK;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) {
    for (auto it = active_sessions->begin(); it != active_sessions->end(); ) {
        CkSession *session = *it;
        if (session->slot_id == slotID) {
            free(session);
            active_sessions->erase(it);
        } else {
            it++;
        }
    }
    return CKR_FUNCTION_FAILED;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
    CkSession *session = (CkSession*)hSession;
    if (session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    session->find_objects_template = (CK_ATTRIBUTE*)malloc(sizeof(CK_ATTRIBUTE) * ulCount);
    for (CK_ULONG i = 0; i < ulCount; i++) {
        session->find_objects_template[i].type = pTemplate[i].type;
        session->find_objects_template[i].pValue = malloc(pTemplate[i].ulValueLen);
        memcpy(session->find_objects_template[i].pValue, pTemplate[i].pValue, pTemplate[i].ulValueLen);
        session->find_objects_template[i].ulValueLen = pTemplate[i].ulValueLen;
    }
    session->find_objects_template_count = ulCount;
    session->find_objects_index = 0;

    return CKR_OK;
}

static CK_BBOOL has_object(AwsKmsSlot& slot, CK_OBJECT_HANDLE idx) {
    switch (idx) {
        case PRIVATE_KEY_HANDLE:
            return slot.GetPublicKeyData().GetLength() > 0;
            break;
        case CERTIFICATE_HANDLE:
            return slot.GetCertificate() != NULL;
            break;
    }

    return CK_FALSE;
}

static CK_RV getAttributeForObject(AwsKmsSlot& slot, CK_OBJECT_HANDLE idx, CK_ATTRIBUTE_TYPE attr, CK_VOID_PTR pValue, CK_ULONG_PTR pulValueLen) {
    switch (idx) {
        case PRIVATE_KEY_HANDLE:
            return getKmsKeyAttributeValue(slot, attr, pValue, pulValueLen);
        case CERTIFICATE_HANDLE:
            return getCertificateAttributeValue(slot, attr, pValue, pulValueLen);
    }

    return CKR_OBJECT_HANDLE_INVALID;
}

static CK_BBOOL matches_template(CkSession* session, AwsKmsSlot& slot, CK_OBJECT_HANDLE idx) {
    unsigned char* buffer = NULL;
    CK_ULONG buffer_size = 0;
    CK_RV res;

    for (CK_ULONG i = 0; i < session->find_objects_template_count; i++) {
        CK_ATTRIBUTE attr = session->find_objects_template[i];

        // Pull the real attribute value
        res = getAttributeForObject(slot, idx, attr.type, NULL_PTR, &buffer_size);
        if (res != CKR_OK) {
            return res;
        }
        if (buffer_size != attr.ulValueLen) {
            return CK_FALSE;
        }
        buffer = (unsigned char*)malloc(buffer_size);
        if (buffer == NULL) {
            return CKR_HOST_MEMORY;
        }
        res = getAttributeForObject(slot, idx, attr.type, buffer, &buffer_size);
        if (res != CKR_OK) {
            return res;
        }

        // Special case for CKA_CLASS because we want to match CKO_PUBLIC_KEY even though we have a CKO_PRIVATE_KEY
        if (attr.type == CKA_CLASS) {
            CK_OBJECT_CLASS match = *((CK_OBJECT_CLASS*)attr.pValue);
            CK_OBJECT_CLASS actual = *((CK_OBJECT_CLASS*)buffer);
            if (match == CKO_PUBLIC_KEY && (actual == CKO_PUBLIC_KEY || actual == CKO_PRIVATE_KEY)) {
                free(buffer);
                continue;
            }
        }

        // Otherwise require exact match
        if (memcmp(buffer, attr.pValue, buffer_size) != 0) {
            free(buffer);
            return CK_FALSE;
        }
        free(buffer);
    }
    return CK_TRUE;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount) {
    CkSession *session = (CkSession*)hSession;
    if (session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    AwsKmsSlot& slot = slots->at(session->slot_id);

    if (ulMaxObjectCount == 0 || session->find_objects_index > LAST_OBJECT_HANDLE) {
        *pulObjectCount = 0;
        return CKR_OK;
    }

    size_t found_objects = 0;
    while (found_objects < ulMaxObjectCount && session->find_objects_index <= LAST_OBJECT_HANDLE) {
        if (has_object(slot, session->find_objects_index)) {
            if (matches_template(session, slot, session->find_objects_index)) {
                phObject[found_objects] = session->find_objects_index;
                found_objects += 1;
            }
        }
        session->find_objects_index += 1;
    }

    *pulObjectCount = found_objects;
    return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession) {
    CkSession *session = (CkSession*)hSession;
    if (session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    for (CK_ULONG i = 0; i < session->find_objects_template_count; i++) {
        free(session->find_objects_template[i].pValue);
    }
    free(session->find_objects_template);

    session->find_objects_template = NULL;
    session->find_objects_template_count = 0;
    session->find_objects_index = 0;
    return CKR_OK;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
    CkSession *session = (CkSession*)hSession;
    if (session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (pTemplate == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    if (hObject < FIRST_OBJECT_HANDLE || hObject > LAST_OBJECT_HANDLE) {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    AwsKmsSlot& slot = slots->at(session->slot_id);
    if (!has_object(slot, hObject)) {
        return CKR_OBJECT_HANDLE_INVALID;
    }

    for (CK_ULONG i = 0; i < ulCount; i++) {
        CK_RV res = getAttributeForObject(slot, hObject, pTemplate[i].type, pTemplate[i].pValue, &pTemplate[i].ulValueLen);
        if (res != CKR_OK) {
            return res;
        }
    }
    return CKR_OK;
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
    CkSession *session = (CkSession*)hSession;
    if (session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (pMechanism == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }
    if (hKey != 0) {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    session->sign_mechanism = pMechanism->mechanism;

    return CKR_OK;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen) {
    return CKR_OK;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
    *pulSignatureLen = 0;
    return CKR_OK;
}

static const unsigned char rsa_id_sha256[] = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };
static CK_BBOOL has_prefix(CK_BYTE_PTR pData, CK_ULONG ulDataLen, const unsigned char* prefix, size_t prefixLen) {
    if (ulDataLen < sizeof(prefix)) {
        return CK_FALSE;
    }
    for (size_t i = 0; i < sizeof(prefix); i++) {
        if (pData[i] != prefix[i]) {
            return CK_FALSE;
        }
    }
    return CK_TRUE;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
    CkSession *session = (CkSession*)hSession;
    if (session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (pData == NULL_PTR || pulSignatureLen == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    AwsKmsSlot& slot = slots->at(session->slot_id);
    Aws::Utils::ByteBuffer key_data = slot.GetPublicKeyData();
    if (key_data.GetLength() == 0) {
        return CKR_ARGUMENTS_BAD;
    }

    size_t sig_size;
    const EC_KEY* ec_key;
    const RSA* rsa;
    const unsigned char* pubkey_bytes = key_data.GetUnderlyingData();
    EVP_PKEY* pkey = d2i_PUBKEY(NULL, &pubkey_bytes, key_data.GetLength());

    int key_type = EVP_PKEY_base_id(pkey);
    switch (key_type) {
        case EVP_PKEY_RSA:
            rsa = EVP_PKEY_get0_RSA(pkey);
            sig_size = BN_num_bytes(RSA_get0_n(rsa));
            break;
        case EVP_PKEY_EC:
            ec_key = EVP_PKEY_get0_EC_KEY(pkey);
            sig_size = ECDSA_size(ec_key);
            break;
        default:
            EVP_PKEY_free(pkey);
            return CKR_FUNCTION_FAILED;

    }
    EVP_PKEY_free(pkey);
    pkey = NULL;

    if (pSignature == NULL_PTR) {
        *pulSignatureLen = sig_size;
        return CKR_OK;
    }

    Aws::KMS::Model::SignRequest req;
    req.SetKeyId(slot.GetKmsKeyId());
    switch (session->sign_mechanism) {
        case CKM_ECDSA:
            req.SetMessage(Aws::Utils::CryptoBuffer(Aws::Utils::ByteBuffer(pData, ulDataLen)));
            req.SetMessageType(Aws::KMS::Model::MessageType::DIGEST);
            req.SetSigningAlgorithm(Aws::KMS::Model::SigningAlgorithmSpec::ECDSA_SHA_256);
            break;
        case CKM_RSA_PKCS:
            if (ulDataLen <= 32) {
                req.SetMessage(Aws::Utils::CryptoBuffer(Aws::Utils::ByteBuffer(pData, ulDataLen)));
            } else if (has_prefix(pData, ulDataLen, rsa_id_sha256, sizeof(rsa_id_sha256))) {
                // Strip the digest algorithm identifier if it has been provided
                req.SetMessage(Aws::Utils::CryptoBuffer(Aws::Utils::ByteBuffer(pData + sizeof(rsa_id_sha256), ulDataLen - sizeof(rsa_id_sha256))));
            } else {
                debug("Invalid data length for SHA256 RSA signature: %d", ulDataLen);
                return CKR_ARGUMENTS_BAD;
            }
            req.SetMessageType(Aws::KMS::Model::MessageType::DIGEST);
            req.SetSigningAlgorithm(Aws::KMS::Model::SigningAlgorithmSpec::RSASSA_PKCS1_V1_5_SHA_256);
            break;
        default:
            return CKR_ARGUMENTS_BAD;
    }

    Aws::Client::ClientConfiguration awsConfig;
    if (slot.GetAwsRegion().length() > 0) {
        awsConfig.region = slot.GetAwsRegion();
    }
    Aws::KMS::KMSClient kms(awsConfig);
    Aws::KMS::Model::SignOutcome res = kms.Sign(req);
    if (!res.IsSuccess()) {
        debug("Error signing: %s", res.GetError().GetMessage().c_str());
        return CKR_FUNCTION_FAILED;
    } else {
        debug("Successfully called KMS to do a signing operation.");
    }
    Aws::KMS::Model::SignResult response = res.GetResult();

    if (key_type == EVP_PKEY_EC) {
        const unsigned char* sigbytes = response.GetSignature().GetUnderlyingData();
        ECDSA_SIG* sig = d2i_ECDSA_SIG(NULL, &sigbytes, response.GetSignature().GetLength());
        if (sig == NULL) {
            return CKR_FUNCTION_FAILED;
        }
        const BIGNUM* r = ECDSA_SIG_get0_r(sig);
        const BIGNUM* s = ECDSA_SIG_get0_s(sig);

        if ((size_t)BN_num_bytes(r) + (size_t)BN_num_bytes(s) > sig_size) {
            return CKR_FUNCTION_FAILED;
        }
        int pos = BN_bn2bin(r, pSignature);
        pos += BN_bn2bin(s, pSignature + pos);
        *pulSignatureLen = pos;
        ECDSA_SIG_free(sig);
    } else {
        if (response.GetSignature().GetLength() > sig_size) {
            return CKR_FUNCTION_FAILED;
        }
        memcpy(pSignature, response.GetSignature().GetUnderlyingData(), response.GetSignature().GetLength());
        *pulSignatureLen = response.GetSignature().GetLength();
    }

    return CKR_OK;
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
    static CK_FUNCTION_LIST function_list = {
               version: {
                   major: 0,
                   minor: 0
               },
               C_Initialize: C_Initialize,
               C_Finalize: C_Finalize,
               C_GetInfo: C_GetInfo,
               C_GetFunctionList: C_GetFunctionList,
               C_GetSlotList: C_GetSlotList,
               C_GetSlotInfo: C_GetSlotInfo,
               C_GetTokenInfo: C_GetTokenInfo,
               C_GetMechanismList: C_GetMechanismList,
               C_GetMechanismInfo: C_GetMechanismInfo,
               C_InitToken: C_InitToken,
               C_InitPIN: C_InitPIN,
               C_SetPIN: C_SetPIN,
               C_OpenSession: C_OpenSession,
               C_CloseSession: C_CloseSession,
               C_CloseAllSessions: C_CloseAllSessions,
               C_GetSessionInfo: C_GetSessionInfo,
               C_GetOperationState: C_GetOperationState,
               C_SetOperationState: C_SetOperationState,
               C_Login: C_Login,
               C_Logout: C_Logout,
               C_CreateObject: C_CreateObject,
               C_CopyObject: C_CopyObject,
               C_DestroyObject: C_DestroyObject,
               C_GetObjectSize: C_GetObjectSize,
               C_GetAttributeValue: C_GetAttributeValue,
               C_SetAttributeValue: C_SetAttributeValue,
               C_FindObjectsInit: C_FindObjectsInit,
               C_FindObjects: C_FindObjects,
               C_FindObjectsFinal: C_FindObjectsFinal,
               C_EncryptInit: C_EncryptInit,
               C_Encrypt: C_Encrypt,
               C_EncryptUpdate: C_EncryptUpdate,
               C_EncryptFinal: C_EncryptFinal,
               C_DecryptInit: C_DecryptInit,
               C_Decrypt: C_Decrypt,
               C_DecryptUpdate: C_DecryptUpdate,
               C_DecryptFinal: C_DecryptFinal,
               C_DigestInit: C_DigestInit,
               C_Digest: C_Digest,
               C_DigestUpdate: C_DigestUpdate,
               C_DigestKey: C_DigestKey,
               C_DigestFinal: C_DigestFinal,
               C_SignInit: C_SignInit,
               C_Sign: C_Sign,
               C_SignUpdate: C_SignUpdate,
               C_SignFinal: C_SignFinal,
               C_SignRecoverInit: C_SignRecoverInit,
               C_SignRecover: C_SignRecover,
               C_VerifyInit: C_VerifyInit,
               C_Verify: C_Verify,
               C_VerifyUpdate: C_VerifyUpdate,
               C_VerifyFinal: C_VerifyFinal,
               C_VerifyRecoverInit: C_VerifyRecoverInit,
               C_VerifyRecover: C_VerifyRecover,
               C_DigestEncryptUpdate: C_DigestEncryptUpdate,
               C_DecryptDigestUpdate: C_DecryptDigestUpdate,
               C_SignEncryptUpdate: C_SignEncryptUpdate,
               C_DecryptVerifyUpdate: C_DecryptVerifyUpdate,
               C_GenerateKey: C_GenerateKey,
               C_GenerateKeyPair: C_GenerateKeyPair,
               C_WrapKey: C_WrapKey,
               C_UnwrapKey: C_UnwrapKey,
               C_DeriveKey: C_DeriveKey,
               C_SeedRandom: C_SeedRandom,
               C_GenerateRandom: C_GenerateRandom,
               C_GetFunctionStatus: C_GetFunctionStatus,
               C_CancelFunction: C_CancelFunction,
               C_WaitForSlotEvent: C_WaitForSlotEvent,
           };

    if (ppFunctionList == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    *ppFunctionList = &function_list;
    return CKR_OK;
}

