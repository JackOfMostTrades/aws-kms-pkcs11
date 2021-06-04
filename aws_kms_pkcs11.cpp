#include <assert.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <pkcs11.h>
#include <json-c/json.h>
#include <map>
#include <optional>
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

using std::map;
using std::optional;
using std::string;
using std::vector;

static bool debug_enabled = CK_FALSE;
static json_object* config = NULL;
static char* aws_region = NULL;
static map<string, optional<Aws::KMS::Model::GetPublicKeyResult>>* public_key_data = NULL;
static vector<string>* kms_key_ids = NULL;

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

// Returns the configuration value for the given key. The returned string does not need to be freed as it is owned by
// the configuration instance. However, any strings returned will be freed when C_Finalize is called, so if something
// needs to live longer than that, make sure to use strdup(). Will return NULL if no config value is set for the key.
static const char* get_config(const char* key) {
    if (config == NULL || !json_object_is_type(config, json_type_object)) {
        return NULL;
    }
    struct json_object* val;
    if (json_object_object_get_ex(config, key, &val) && json_object_is_type(val, json_type_string)) {
        return json_object_get_string(val);
    }
    return NULL;
}

static CK_RV load_config() {
    CK_RV res = CKR_OK;
    const char* system_path = "/etc/aws-kms-pkcs11/config.json";
    char* user_path = NULL;
    const char* paths[2] = {NULL, NULL};

    char* xdg_config_home = getenv("XDG_CONFIG_HOME");
    CK_BBOOL free_xdg_config_home = CK_FALSE;
    if (xdg_config_home == NULL) {
        char* home = getenv("HOME");
        if (home != NULL) {
            size_t len = strlen(home) + strlen("/.config");
            xdg_config_home = (char*)malloc(len+1);
            if (xdg_config_home == NULL) {
                res = CKR_HOST_MEMORY;
                goto cleanup;
            }
            free_xdg_config_home = CK_TRUE;
            snprintf(xdg_config_home, len+1, "%s/.config", home);
        }
    }
    if (xdg_config_home == NULL) {
        user_path = NULL;
    } else {
        size_t len = strlen(xdg_config_home) + strlen("/aws-kms-pkcs11/config.json");
        user_path = (char*)malloc(len+1);
        if (user_path == NULL) {
            res = CKR_HOST_MEMORY;
            goto cleanup;
        }
        snprintf(user_path, len+1, "%s/aws-kms-pkcs11/config.json", xdg_config_home);
        if (free_xdg_config_home && xdg_config_home != NULL) {
            free(xdg_config_home);
            xdg_config_home = NULL;
            free_xdg_config_home = CK_FALSE;
        }
    }

    paths[0] = system_path;
    paths[1] = user_path;
    config = json_object_new_object();
    for (size_t i = 0; i < sizeof(paths)/sizeof(char*); i++) {
        if (paths[i] == NULL) {
            continue;
        }
        debug("Attempting to load config from path: %s", paths[i]);

        FILE* f = fopen(paths[i], "r");
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
            res = CKR_HOST_MEMORY;
            goto cleanup;
        }

        size_t actual = fread(buffer, file_size, 1, f);
        fclose(f);
        if (actual != 1) {
            res = CKR_FUNCTION_FAILED;
            goto cleanup;
        }

        json_bool has_key = false;
        struct json_object* array = NULL;
        struct json_tokener* tok = json_tokener_new();
        struct json_object* conf = json_tokener_parse_ex(tok, buffer, file_size);
        json_tokener_free(tok);

        if (conf != NULL) {
            if (json_object_is_type(conf, json_type_object)) {
                json_object_object_foreach(conf, key, val) {
                    if (json_object_is_type(val, json_type_string)) {
                        json_object_object_add(config, key, json_object_new_string(json_object_get_string(val)));
                    } else if (json_object_is_type(val, json_type_array)) {
                        has_key = json_object_object_get_ex(config, key, &array);
                        if (!has_key) {
                            array = json_object_new_array();
                            json_object_object_add(config, key, array);
                        }
                        for (size_t i = 0; i < json_object_array_length(val); i++) {
                            struct json_object* v = json_object_array_get_idx(val, i);
                            json_object_get(v);
                            json_object_array_add(array, v);
                        }
                        array = NULL;
                    }
                }
            }
            json_object_put(conf);
        } else {
            debug("Failed to parse config: %s", paths[i]);
        }
    }

cleanup:
    if (free_xdg_config_home && xdg_config_home != NULL) {
        free(xdg_config_home);
    }
    if (user_path != NULL) {
        free(user_path);
    }
    if (config != NULL && res != CKR_OK) {
        json_object_put(config);
        config = NULL;
    }
    return res;
}

typedef struct _session {
    CK_ATTRIBUTE_PTR find_objects_template;
    CK_ULONG find_objects_template_count;
    unsigned long find_objects_index;

    unsigned long sign_key_index;
    CK_MECHANISM_TYPE sign_mechanism;
} CkSession;

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

    CK_RV res = load_config();
    if (res != CKR_OK) {
        debug("Failed to load config.");
        return res;
    }

    public_key_data = new map<string, optional<Aws::KMS::Model::GetPublicKeyResult>>();
    kms_key_ids = new vector<string>();
    const char* val;
    if ((val = get_config("kms_key_id")) != NULL) {
        kms_key_ids->push_back(string(val));
    }
    if ((val = get_config("aws_region")) != NULL) {
        aws_region = strdup(val);
    }

    if (aws_region == NULL) {
        debug("No AWS region configured; using default AWS region.");
    } else {
        debug("Configured to use AWS region: %s", aws_region);
    }

    struct json_object* configured_keys;
    json_bool has_key = false;
    has_key = json_object_object_get_ex(config, "kms_key_ids", &configured_keys);
    if (has_key && json_object_is_type(configured_keys, json_type_array)) {
        for (size_t i = 0; i < json_object_array_length(configured_keys); i++) {
            struct json_object* v = json_object_array_get_idx(configured_keys, i);
            if (json_object_is_type(v, json_type_string)) {
                kms_key_ids->push_back(string(json_object_get_string(v)));
            }
        }
    }

    if (kms_key_ids->size() == 0) {
        debug("No KMS key ids configured; listing all keys.");
        Aws::Client::ClientConfiguration awsConfig;
        if (aws_region != NULL) {
            awsConfig.region = aws_region;
        }
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
                kms_key_ids->push_back(res.GetResult().GetKeys().at(i).GetKeyId());
            }

            has_more = res.GetResult().GetTruncated();
            if (has_more) {
                req.SetMarker(res.GetResult().GetNextMarker());
            }
        }
    }

    if (kms_key_ids->size() == 0) {
        debug("No KMS keys were configured and none were listed.");
        C_Finalize(NULL_PTR);
        return CKR_FUNCTION_FAILED;
    }

    debug("Configured KMS key ids:");
    for (size_t i = 0; i < kms_key_ids->size(); i++) {
        debug("  %s", kms_key_ids->at(i).c_str());
    }

    return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
    debug("Cleaning PKCS#11 provider.");

    Aws::SDKOptions options;
    Aws::ShutdownAPI(options);

    if (kms_key_ids != NULL) {
        delete kms_key_ids;
        kms_key_ids = NULL;
    }
    if (public_key_data != NULL) {
        delete public_key_data;
        public_key_data = NULL;
    }
    if (aws_region != NULL) {
        free(aws_region);
        aws_region = NULL;
    }
    if (config != NULL) {
        json_object_put(config);
        config = NULL;
    }
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
        if (*pulCount == 0) {
            return CKR_BUFFER_TOO_SMALL;
        }
        pSlotList[0] = 0;
    } else {
        *pulCount = 1;
    }
    return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
    if (slotID != 0) {
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
    if (slotID != 0) {
        return CKR_SLOT_ID_INVALID;
    }
    if (pInfo == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    memset(pInfo, 0, sizeof(*pInfo));
    pInfo->flags = CKF_TOKEN_INITIALIZED;
    return CKR_OK;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
    return CKR_OK;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession) {
    return CKR_OK;
}

optional<Aws::KMS::Model::GetPublicKeyResult> get_public_key_data(string key_id) {
    if (public_key_data->count(key_id) > 0) {
        return public_key_data->at(key_id);
    }

    Aws::Client::ClientConfiguration awsConfig;
    if (aws_region != NULL) {
        awsConfig.region = aws_region;
    }
    Aws::KMS::KMSClient kms(awsConfig);
    Aws::KMS::Model::GetPublicKeyRequest req;

    debug("Getting public key for key %s", key_id.c_str());
    req.SetKeyId(key_id);
    Aws::KMS::Model::GetPublicKeyOutcome res = kms.GetPublicKey(req);
    optional<Aws::KMS::Model::GetPublicKeyResult> optRes;
    if (!res.IsSuccess()) {
        debug("Got error from AWS fetching public key for key id %s: %s", key_id.c_str(), res.GetError().GetMessage().c_str());
        optRes = std::nullopt;
    } else {
        debug("Successfully fetched public key data.");
        optRes = {res.GetResult()};
    }
    public_key_data->insert( std::pair<string, optional<Aws::KMS::Model::GetPublicKeyResult>>(key_id, optRes) );
    return optRes;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY notify, CK_SESSION_HANDLE_PTR phSession) {
    if (slotID != 0) {
        return CKR_SLOT_ID_INVALID;
    }

    CkSession* session = (CkSession*)malloc(sizeof(CkSession));
    if (session == NULL) {
        return CKR_HOST_MEMORY;
    }

    *phSession = (CK_SESSION_HANDLE)session;
    return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
    CkSession *session = (CkSession*)hSession;
    if (session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    free(session);
    return CKR_OK;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) {
    // Not supported
    return CKR_FUNCTION_FAILED;
}

CK_RV getAttributeValue(string key_id, CK_ATTRIBUTE_TYPE attr, CK_VOID_PTR pValue, CK_ULONG_PTR pulValueLen) {

    unsigned char* buffer, *buffer2;
    EVP_PKEY* pkey;
    const RSA* rsa;
    const EC_KEY* ec_key;
    const EC_GROUP* ec_group;
    const BIGNUM* bn;
    size_t len, len2;
    ASN1_OCTET_STRING* os;

    optional<Aws::KMS::Model::GetPublicKeyResult> key;
    const unsigned char* pubkey_bytes;

    switch (attr) {
        case CKA_CLASS:
            key = get_public_key_data(key_id);
            *pulValueLen = sizeof(CK_OBJECT_CLASS);
            if (pValue != NULL_PTR) {
                if (key.has_value()) {
                    *((CK_OBJECT_CLASS*)pValue) = CKO_PRIVATE_KEY;
                } else {
                    *((CK_OBJECT_CLASS*)pValue) = CKO_DATA;
                }
            }
            break;
        case CKA_ID:
        case CKA_LABEL:
            *pulValueLen = key_id.length();
            if (pValue != NULL_PTR) {
                memcpy(pValue, key_id.c_str(), key_id.length());
            }
            break;
        case CKA_SIGN:
            key = get_public_key_data(key_id);
            if (!key.has_value()) {
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            *pulValueLen = sizeof(CK_BBOOL);
            if (pValue != NULL_PTR) {
                *((CK_BBOOL*)pValue) = CK_TRUE;
            }
            break;
        case CKA_KEY_TYPE:
            key = get_public_key_data(key_id);
            if (!key.has_value()) {
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            pubkey_bytes = key.value().GetPublicKey().GetUnderlyingData();
            pkey = d2i_PUBKEY(NULL, &pubkey_bytes, key.value().GetPublicKey().GetLength());
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
            break;
        case CKA_ALWAYS_AUTHENTICATE:
            key = get_public_key_data(key_id);
            if (!key.has_value()) {
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            *pulValueLen = sizeof(CK_BBOOL);
            if (pValue != NULL_PTR) {
                *((CK_BBOOL*)pValue) = CK_FALSE;
            }
            break;
        case CKA_MODULUS:
            key = get_public_key_data(key_id);
            if (!key.has_value()) {
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            pubkey_bytes = key.value().GetPublicKey().GetUnderlyingData();
            pkey = d2i_PUBKEY(NULL, &pubkey_bytes, key.value().GetPublicKey().GetLength());
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
            break;
        case CKA_PUBLIC_EXPONENT:
            key = get_public_key_data(key_id);
            if (!key.has_value()) {
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            pubkey_bytes = key.value().GetPublicKey().GetUnderlyingData();
            pkey = d2i_PUBKEY(NULL, &pubkey_bytes, key.value().GetPublicKey().GetLength());
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
            break;
        case CKA_EC_POINT:
            key = get_public_key_data(key_id);
            if (!key.has_value()) {
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            pubkey_bytes = key.value().GetPublicKey().GetUnderlyingData();
            pkey = d2i_PUBKEY(NULL, &pubkey_bytes, key.value().GetPublicKey().GetLength());
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

            free(buffer);
            free(buffer2);
            EVP_PKEY_free(pkey);
            break;
        case CKA_EC_PARAMS:
            key = get_public_key_data(key_id);
            if (!key.has_value()) {
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            pubkey_bytes = key.value().GetPublicKey().GetUnderlyingData();
            pkey = d2i_PUBKEY(NULL, &pubkey_bytes, key.value().GetPublicKey().GetLength());
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

static CK_BBOOL matches_template(CkSession* session, string key_id) {
    unsigned char* buffer = NULL;
    CK_ULONG buffer_size = 0;
    CK_RV res;

    for (CK_ULONG i = 0; i < session->find_objects_template_count; i++) {
        CK_ATTRIBUTE attr = session->find_objects_template[i];

        // Pull the real attribute value
        res = getAttributeValue(key_id, attr.type, NULL_PTR, &buffer_size);
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
        res = getAttributeValue(key_id, attr.type, buffer, &buffer_size);
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

    if (kms_key_ids->size() == 0) {
        *pulObjectCount = 0;
        return CKR_OK;
    }

    unsigned long foundObjects = 0;
    while (foundObjects < ulMaxObjectCount && session->find_objects_index < kms_key_ids->size()) {
        string key_id = kms_key_ids->at(session->find_objects_index);
        if (matches_template(session, key_id)) {
            phObject[foundObjects] = session->find_objects_index;
            foundObjects += 1;
        }
        session->find_objects_index += 1;
    }

    *pulObjectCount = foundObjects;
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

    if (hObject >= kms_key_ids->size()) {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    string key_id = kms_key_ids->at(hObject);

    for (CK_ULONG i = 0; i < ulCount; i++) {
        CK_RV res = getAttributeValue(key_id, pTemplate[i].type, pTemplate[i].pValue, &pTemplate[i].ulValueLen);
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
    if (hKey >= kms_key_ids->size()) {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    session->sign_key_index = hKey;
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

    string key_id = kms_key_ids->at(session->sign_key_index);
    optional<Aws::KMS::Model::GetPublicKeyResult> key = get_public_key_data(key_id);
    if (!key.has_value()) {
        return CKR_ARGUMENTS_BAD;
    }

    size_t sig_size;
    const EC_KEY* ec_key;
    const RSA* rsa;
    const unsigned char* pubkey_bytes = key.value().GetPublicKey().GetUnderlyingData();
    EVP_PKEY* pkey = d2i_PUBKEY(NULL, &pubkey_bytes, key.value().GetPublicKey().GetLength());

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
    req.SetKeyId(key_id);
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
    if (aws_region != NULL) {
        awsConfig.region = aws_region;
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

