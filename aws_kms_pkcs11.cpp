#include <assert.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <pkcs11.h>
#include <json-c/json.h>

#include <algorithm>
#include <vector>

#include <aws/core/Aws.h>
#include <aws/core/utils/base64/Base64.h>
#include <aws/kms/KMSClient.h>
#include <aws/kms/model/GetPublicKeyRequest.h>
#include <aws/kms/model/ListKeysRequest.h>
#include <aws/kms/model/SignRequest.h>

#include "unsupported.h"

static_assert(sizeof(CK_SESSION_HANDLE) >= sizeof(void*), "Session handles are not big enough to hold a pointer to the session struct on this architecture");
static_assert(sizeof(CK_OBJECT_HANDLE) >= sizeof(void*), "Object handles are not big enough to hold a pointer to the session struct on this architecture");

using std::string;
using std::vector;

static bool debug_enabled = CK_FALSE;
static void inline debug(const char *fmt, ...) {
    va_list args;

    if (!debug_enabled) {
        return;
    }

    char* longer_fmt = (char*)malloc(strlen(fmt)+11);
    strcpy(longer_fmt, "AWS_KMS: ");
    strcpy(longer_fmt+9, fmt);
    longer_fmt[strlen(fmt)+9] = '\n';
    longer_fmt[strlen(fmt)+10] = '\0';

    va_start(args, fmt);
    vprintf(longer_fmt, args);
    va_end(args);

    free(longer_fmt);
}

class AwsKmsSlot {
private:
    string label;
    string aws_region;
    string kms_key_id;
    bool public_key_data_fetched;
    Aws::Utils::ByteBuffer public_key_data;
public:
    AwsKmsSlot(string label, string kms_key_id, string aws_region);
    string GetLabel();
    string GetKmsKeyId();
    string GetAwsRegion();
    Aws::Utils::ByteBuffer GetPublicKeyData();
};
AwsKmsSlot::AwsKmsSlot(string label, string kms_key_id, string aws_region) {
    this->label = label;
    this->kms_key_id = kms_key_id;
    this->aws_region = aws_region;
    this->public_key_data_fetched = false;
}
string AwsKmsSlot::GetLabel() {
    return this->label;
}
string AwsKmsSlot::GetAwsRegion() {
    return this->aws_region;
}
string AwsKmsSlot::GetKmsKeyId() {
    return this->kms_key_id;
}
Aws::Utils::ByteBuffer AwsKmsSlot::GetPublicKeyData() {
    if (this->public_key_data_fetched) {
        return this->public_key_data;
    }
    Aws::Client::ClientConfiguration awsConfig;
    if (this->aws_region.length() > 0) {
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
    } else {
        debug("Successfully fetched public key data.");
        this->public_key_data = res.GetResult().GetPublicKey();
    }
    this->public_key_data_fetched = true;
    return this->public_key_data;
}

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
                if (json_object_object_get_ex(slot_item, "label", &val) && json_object_is_type(val, json_type_string)) {
                    label = string(json_object_get_string(val));
                }
                if (json_object_object_get_ex(slot_item, "kms_key_id", &val) && json_object_is_type(val, json_type_string)) {
                    kms_key_id = string(json_object_get_string(val));
                }
                if (json_object_object_get_ex(slot_item, "aws_region", &val) && json_object_is_type(val, json_type_string)) {
                    kms_key_id = string(json_object_get_string(val));
                }
                slots->push_back(AwsKmsSlot(label, kms_key_id, aws_region));
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
                slots->push_back(AwsKmsSlot(string(), res.GetResult().GetKeys().at(i).GetKeyId(), string()));
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

CK_RV getAttributeValue(AwsKmsSlot& slot, CK_ATTRIBUTE_TYPE attr, CK_VOID_PTR pValue, CK_ULONG_PTR pulValueLen) {

    unsigned char* buffer, *buffer2;
    EVP_PKEY* pkey;
    const RSA* rsa;
    const EC_KEY* ec_key;
    const EC_GROUP* ec_group;
    const BIGNUM* bn;
    size_t len, len2;
    ASN1_OCTET_STRING* os;

    Aws::Utils::ByteBuffer key_data;
    const unsigned char* pubkey_bytes;

    switch (attr) {
        case CKA_CLASS:
            key_data = slot.GetPublicKeyData();
            *pulValueLen = sizeof(CK_OBJECT_CLASS);
            if (pValue != NULL_PTR) {
                if (key_data.GetLength() > 0) {
                    *((CK_OBJECT_CLASS*)pValue) = CKO_PRIVATE_KEY;
                } else {
                    *((CK_OBJECT_CLASS*)pValue) = CKO_DATA;
                }
            }
            break;
        case CKA_ID:
        case CKA_LABEL:
            *pulValueLen = slot.GetKmsKeyId().length();
            if (pValue != NULL_PTR) {
                memcpy(pValue, slot.GetKmsKeyId().c_str(), slot.GetKmsKeyId().length());
            }
            break;
        case CKA_SIGN:
            key_data = slot.GetPublicKeyData();
            if (key_data.GetLength() == 0) {
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            *pulValueLen = sizeof(CK_BBOOL);
            if (pValue != NULL_PTR) {
                *((CK_BBOOL*)pValue) = CK_TRUE;
            }
            break;
        case CKA_KEY_TYPE:
            key_data = slot.GetPublicKeyData();
            if (key_data.GetLength() == 0) {
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            pubkey_bytes = key_data.GetUnderlyingData();
            pkey = d2i_PUBKEY(NULL, &pubkey_bytes, key_data.GetLength());
            if (pkey == NULL) {
                return CKR_FUNCTION_FAILED;
            }

            CK_OBJECT_CLASS key_type;
            switch (EVP_PKEY_base_id(pkey)) {
                case EVP_PKEY_RSA:
                    key_type = CKK_RSA;
                    break;
                case EVP_PKEY_EC:
                    key_type = CKK_ECDSA;
                    break;
                default:
                    EVP_PKEY_free(pkey);
                    return CKR_ATTRIBUTE_TYPE_INVALID;
            }

            *pulValueLen = sizeof(CK_OBJECT_CLASS);
            if (pValue != NULL_PTR) {
                *((CK_OBJECT_CLASS*)pValue) = key_type;
            }
            EVP_PKEY_free(pkey);
            break;
        case CKA_ALWAYS_AUTHENTICATE:
            key_data = slot.GetPublicKeyData();
            if (key_data.GetLength() == 0) {
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            *pulValueLen = sizeof(CK_BBOOL);
            if (pValue != NULL_PTR) {
                *((CK_BBOOL*)pValue) = CK_FALSE;
            }
            break;
        case CKA_MODULUS:
            key_data = slot.GetPublicKeyData();
            if (key_data.GetLength() == 0) {
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            pubkey_bytes = key_data.GetUnderlyingData();
            pkey = d2i_PUBKEY(NULL, &pubkey_bytes, key_data.GetLength());
            if (pkey == NULL) {
                return CKR_FUNCTION_FAILED;
            }
            if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
                EVP_PKEY_free(pkey);
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            rsa = EVP_PKEY_get0_RSA(pkey);
            bn = RSA_get0_n(rsa);

            *pulValueLen = BN_num_bytes(bn);
            if (pValue != NULL_PTR) {
                BN_bn2bin(bn, (unsigned char*)pValue);
            }
            EVP_PKEY_free(pkey);
            break;
        case CKA_PUBLIC_EXPONENT:
            key_data = slot.GetPublicKeyData();
            if (key_data.GetLength() == 0) {
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            pubkey_bytes = key_data.GetUnderlyingData();
            pkey = d2i_PUBKEY(NULL, &pubkey_bytes, key_data.GetLength());
            if (pkey == NULL) {
                return CKR_FUNCTION_FAILED;
            }
            if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
                EVP_PKEY_free(pkey);
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            rsa = EVP_PKEY_get0_RSA(pkey);
            bn = RSA_get0_e(rsa);

            *pulValueLen = BN_num_bytes(bn);
            if (pValue != NULL_PTR) {
                BN_bn2bin(bn, (unsigned char*)pValue);
            }
            EVP_PKEY_free(pkey);
            break;
        case CKA_EC_POINT:
            key_data = slot.GetPublicKeyData();
            if (key_data.GetLength() == 0) {
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            pubkey_bytes = key_data.GetUnderlyingData();
            pkey = d2i_PUBKEY(NULL, &pubkey_bytes, key_data.GetLength());
            if (pkey == NULL) {
                return CKR_FUNCTION_FAILED;
            }
            if (EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
                EVP_PKEY_free(pkey);
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            ec_key = EVP_PKEY_get0_EC_KEY(pkey);

            buffer = NULL;
            len = i2o_ECPublicKey(ec_key, &buffer);

            // Wrap the point in an ASN.1 octet string
            os = ASN1_STRING_new();
            ASN1_OCTET_STRING_set(os, buffer, len);

            buffer2 = NULL;
            len2 = i2d_ASN1_OCTET_STRING(os, &buffer2);

            *pulValueLen = len2;
            if (pValue != NULL_PTR) {
                memcpy(pValue, buffer2, len2);
            }

            ASN1_STRING_free(os);
            free(buffer);
            free(buffer2);
            EVP_PKEY_free(pkey);
            break;
        case CKA_EC_PARAMS:
            key_data = slot.GetPublicKeyData();
            if (key_data.GetLength() == 0) {
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            pubkey_bytes = key_data.GetUnderlyingData();
            pkey = d2i_PUBKEY(NULL, &pubkey_bytes, key_data.GetLength());
            if (pkey == NULL) {
                return CKR_FUNCTION_FAILED;
            }
            if (EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
                EVP_PKEY_free(pkey);
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            ec_key = EVP_PKEY_get0_EC_KEY(pkey);
            ec_group = EC_KEY_get0_group(ec_key);

            buffer = NULL;
            len = i2d_ECPKParameters(ec_group, &buffer);

            *pulValueLen = len;
            if (pValue != NULL_PTR) {
                memcpy(pValue, buffer, len);
            }

            free(buffer);
            EVP_PKEY_free(pkey);
            break;
        default:
            return CKR_ATTRIBUTE_TYPE_INVALID;
    }

    return CKR_OK;
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

static CK_BBOOL matches_template(CkSession* session, AwsKmsSlot& slot) {
    unsigned char* buffer = NULL;
    CK_ULONG buffer_size = 0;
    CK_RV res;

    for (CK_ULONG i = 0; i < session->find_objects_template_count; i++) {
        CK_ATTRIBUTE attr = session->find_objects_template[i];

        // Pull the real attribute value
        res = getAttributeValue(slot, attr.type, NULL_PTR, &buffer_size);
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
        res = getAttributeValue(slot, attr.type, buffer, &buffer_size);
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

    if (ulMaxObjectCount == 0 || session->find_objects_index > 0) {
        *pulObjectCount = 0;
        return CKR_OK;
    }

    if (matches_template(session, slot)) {
        *pulObjectCount = 1;
        phObject[0] = 0;
    } else {
        *pulObjectCount = 0;
    }
    session->find_objects_index += 1;

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

    if (hObject != 0) {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    AwsKmsSlot& slot = slots->at(session->slot_id);

    for (CK_ULONG i = 0; i < ulCount; i++) {
        CK_RV res = getAttributeValue(slot, pTemplate[i].type, pTemplate[i].pValue, &pTemplate[i].ulValueLen);
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
    req.SetMessage(Aws::Utils::CryptoBuffer(Aws::Utils::ByteBuffer(pData, ulDataLen)));
    req.SetMessageType(Aws::KMS::Model::MessageType::DIGEST);
    switch (session->sign_mechanism) {
        case CKM_ECDSA:
            req.SetSigningAlgorithm(Aws::KMS::Model::SigningAlgorithmSpec::ECDSA_SHA_256);
            break;
        case CKM_RSA_PKCS:
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

