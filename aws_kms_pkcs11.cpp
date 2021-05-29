#include <assert.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <pkcs11.h>
#include <json-c/json.h>

#include <aws/core/Aws.h>
#include <aws/core/utils/base64/Base64.h>
#include <aws/kms/KMSClient.h>
#include <aws/kms/model/GetPublicKeyRequest.h>
#include <aws/kms/model/SignRequest.h>

static_assert(sizeof(CK_SESSION_HANDLE) >= sizeof(void*), "Session handles are not big enough to hold a pointer to the session struct on this architecture");
static_assert(sizeof(CK_OBJECT_HANDLE) >= sizeof(void*), "Object handles are not big enough to hold a pointer to the session struct on this architecture");

static bool debug_enabled = CK_FALSE;
static json_object* config = NULL;
static char* aws_region = NULL;
static char* kms_key_id = NULL;

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

        struct json_tokener* tok = json_tokener_new();
        struct json_object* conf = json_tokener_parse_ex(tok, buffer, file_size);
        json_tokener_free(tok);

        if (conf != NULL) {
            if (json_object_is_type(conf, json_type_object)) {
                json_object_object_foreach(conf, key, val) {
                    if (json_object_is_type(val, json_type_string)) {
                        json_object_object_add(config, key, json_object_new_string(json_object_get_string(val)));
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
    std::vector<Aws::KMS::Model::GetPublicKeyResult> *key_data;

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

    CK_RV res = load_config();
    if (res != CKR_OK) {
        debug("Failed to load config.");
        return res;
    }

    const char* val;
    if ((val = get_config("kms_key_id")) != NULL) {
        kms_key_id = strdup(val);
    } else {
        C_Finalize(NULL_PTR);
        return CKR_ARGUMENTS_BAD;
    }
    if ((val = get_config("aws_region")) != NULL) {
        aws_region = strdup(val);
    }

    debug("Configured to use AWS key: %s", kms_key_id);
    if (aws_region == NULL) {
        debug("No AWS region configured; using default AWS region.");
    } else {
        debug("Configured to use AWS region: %s", aws_region);
    }

    Aws::SDKOptions options;
    Aws::InitAPI(options);

    return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved) {
    debug("Cleaning PKCS#11 provider.");

    Aws::SDKOptions options;
    Aws::ShutdownAPI(options);

    if (kms_key_id != NULL) {
        free(kms_key_id);
        kms_key_id = NULL;
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

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY notify, CK_SESSION_HANDLE_PTR phSession) {
    if (slotID != 0) {
        return CKR_SLOT_ID_INVALID;
    }

    CkSession* session = (CkSession*)malloc(sizeof(CkSession));
    if (session == NULL) {
        return CKR_HOST_MEMORY;
    }

    Aws::Client::ClientConfiguration awsConfig;
    if (aws_region != NULL) {
        awsConfig.region = aws_region;
    }
    Aws::KMS::KMSClient kms(awsConfig);
    Aws::KMS::Model::GetPublicKeyRequest req;
    req.SetKeyId(kms_key_id);
    Aws::KMS::Model::GetPublicKeyOutcome res = kms.GetPublicKey(req);
    if (!res.IsSuccess()) {
        debug("Got error from AWS fetching public key: %s", res.GetError().GetMessage().c_str());
        return CKR_FUNCTION_FAILED;
    } else {
        debug("Successfully fetched public key data.");
        Aws::KMS::Model::GetPublicKeyResult result = res.GetResult();
        session->key_data = new std::vector<Aws::KMS::Model::GetPublicKeyResult>();
        session->key_data->push_back(result);
    }

    *phSession = (CK_SESSION_HANDLE)session;
    return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
    CkSession *session = (CkSession*)hSession;
    if (session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (session->key_data != NULL) {
        delete session->key_data;
        session->key_data = NULL;
    }
    free(session);
    return CKR_OK;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID) {
    // Not supported
    return CKR_FUNCTION_FAILED;
}

CK_RV getAttributeValue(Aws::KMS::Model::GetPublicKeyResult &key, CK_ATTRIBUTE_TYPE attr, CK_VOID_PTR pValue, CK_ULONG_PTR pulValueLen) {

    unsigned char* buffer, *buffer2;
    EVP_PKEY* pkey;
    const RSA* rsa;
    const EC_KEY* ec_key;
    const EC_GROUP* ec_group;
    const BIGNUM* bn;
    size_t len, len2;
    ASN1_OCTET_STRING* os;

    Aws::String key_id = key.GetKeyId();
    const unsigned char* pubkey_bytes = key.GetPublicKey().GetUnderlyingData();

    switch (attr) {
        case CKA_CLASS:
            *pulValueLen = sizeof(CK_OBJECT_CLASS);
            if (pValue != NULL_PTR) {
                *((CK_OBJECT_CLASS*)pValue) = CKO_PRIVATE_KEY;
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
            *pulValueLen = sizeof(CK_BBOOL);
            if (pValue != NULL_PTR) {
                *((CK_BBOOL*)pValue) = CK_TRUE;
            }
            break;
        case CKA_KEY_TYPE:
            pkey = d2i_PUBKEY(NULL, &pubkey_bytes, key.GetPublicKey().GetLength());
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
            *pulValueLen = sizeof(CK_BBOOL);
            if (pValue != NULL_PTR) {
                *((CK_BBOOL*)pValue) = CK_FALSE;
            }
            break;
        case CKA_MODULUS:
            pkey = d2i_PUBKEY(NULL, &pubkey_bytes, key.GetPublicKey().GetLength());
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
            pkey = d2i_PUBKEY(NULL, &pubkey_bytes, key.GetPublicKey().GetLength());
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
            pkey = d2i_PUBKEY(NULL, &pubkey_bytes, key.GetPublicKey().GetLength());
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
            pkey = d2i_PUBKEY(NULL, &pubkey_bytes, key.GetPublicKey().GetLength());
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

static CK_BBOOL matches_template(CkSession* session, Aws::KMS::Model::GetPublicKeyResult &key) {
    unsigned char* buffer = NULL;
    CK_ULONG buffer_size = 0;
    CK_RV res;

    for (CK_ULONG i = 0; i < session->find_objects_template_count; i++) {
        CK_ATTRIBUTE attr = session->find_objects_template[i];

        // Special case for CKA_CLASS because we want to match CKO_PUBLIC_KEY even though we have a CKO_PRIVATE_KEY
        if (attr.type == CKA_CLASS) {
            CK_OBJECT_CLASS clazz = *((CK_OBJECT_CLASS*)attr.pValue);
            if (clazz != CKO_PUBLIC_KEY && clazz != CKO_PRIVATE_KEY) {
                return CK_FALSE;
            }
            continue;
        }

        // Otherwise pull the real attribute value and check for a byte-array-equality on the value.
        res = getAttributeValue(key, attr.type, NULL_PTR, &buffer_size);
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
        res = getAttributeValue(key, attr.type, buffer, &buffer_size);
        if (res != CKR_OK) {
            return res;
        }
        if (memcmp(buffer, attr.pValue, buffer_size) != 0) {
            return CK_FALSE;
        }
    }
    return CK_TRUE;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount) {
    CkSession *session = (CkSession*)hSession;
    if (session == NULL) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (session->key_data->size() == 0) {
        *pulObjectCount = 0;
        return CKR_OK;
    }

    unsigned long foundObjects = 0;
    while (foundObjects < ulMaxObjectCount && session->find_objects_index < session->key_data->size()) {
        if (matches_template(session, session->key_data->at(session->find_objects_index))) {
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

    if (hObject >= session->key_data->size()) {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    Aws::KMS::Model::GetPublicKeyResult key = session->key_data->at(hObject);

    for (CK_ULONG i = 0; i < ulCount; i++) {
        CK_RV res = getAttributeValue(key, pTemplate[i].type, pTemplate[i].pValue, &pTemplate[i].ulValueLen);
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
    if (hKey >= session->key_data->size()) {
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

    Aws::KMS::Model::GetPublicKeyResult key = session->key_data->at(session->sign_key_index);

    const unsigned char* pubkey_bytes = key.GetPublicKey().GetUnderlyingData();
    size_t sig_size;
    EVP_PKEY* pkey = d2i_PUBKEY(NULL, &pubkey_bytes, key.GetPublicKey().GetLength());
    const EC_KEY* ec_key;
    const RSA* rsa;

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
    req.SetKeyId(kms_key_id);
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
               C_GetMechanismList: NULL_PTR,
               C_GetMechanismInfo: NULL_PTR,
               C_InitToken: NULL_PTR,
               C_InitPIN: NULL_PTR,
               C_SetPIN: NULL_PTR,
               C_OpenSession: C_OpenSession,
               C_CloseSession: C_CloseSession,
               C_CloseAllSessions: C_CloseAllSessions,
               C_GetSessionInfo: NULL_PTR,
               C_GetOperationState: NULL_PTR,
               C_SetOperationState: NULL_PTR,
               C_Login: C_Login,
               C_Logout: C_Logout,
               C_CreateObject: NULL_PTR,
               C_CopyObject: NULL_PTR,
               C_DestroyObject: NULL_PTR,
               C_GetObjectSize: NULL_PTR,
               C_GetAttributeValue: C_GetAttributeValue,
               C_SetAttributeValue: NULL_PTR,
               C_FindObjectsInit: C_FindObjectsInit,
               C_FindObjects: C_FindObjects,
               C_FindObjectsFinal: C_FindObjectsFinal,
               C_EncryptInit: NULL_PTR,
               C_Encrypt: NULL_PTR,
               C_EncryptUpdate: NULL_PTR,
               C_EncryptFinal: NULL_PTR,
               C_DecryptInit: NULL_PTR,
               C_Decrypt: NULL_PTR,
               C_DecryptUpdate: NULL_PTR,
               C_DecryptFinal: NULL_PTR,
               C_DigestInit: NULL_PTR,
               C_Digest: NULL_PTR,
               C_DigestUpdate: NULL_PTR,
               C_DigestKey: NULL_PTR,
               C_DigestFinal: NULL_PTR,
               C_SignInit: C_SignInit,
               C_Sign: C_Sign,
               C_SignUpdate: C_SignUpdate,
               C_SignFinal: C_SignFinal,
               C_SignRecoverInit: NULL_PTR,
               C_SignRecover: NULL_PTR,
               C_VerifyInit: NULL_PTR,
               C_Verify: NULL_PTR,
               C_VerifyUpdate: NULL_PTR,
               C_VerifyFinal: NULL_PTR,
               C_VerifyRecoverInit: NULL_PTR,
               C_VerifyRecover: NULL_PTR,
               C_DigestEncryptUpdate: NULL_PTR,
               C_DecryptDigestUpdate: NULL_PTR,
               C_SignEncryptUpdate: NULL_PTR,
               C_DecryptVerifyUpdate: NULL_PTR,
               C_GenerateKey: NULL_PTR,
               C_GenerateKeyPair: NULL_PTR,
               C_WrapKey: NULL_PTR,
               C_UnwrapKey: NULL_PTR,
               C_DeriveKey: NULL_PTR,
               C_SeedRandom: NULL_PTR,
               C_GenerateRandom: NULL_PTR,
               C_GetFunctionStatus: NULL_PTR,
               C_CancelFunction: NULL_PTR,
               C_WaitForSlotEvent: NULL_PTR,
           };

    if (ppFunctionList == NULL_PTR) {
        return CKR_ARGUMENTS_BAD;
    }

    *ppFunctionList = &function_list;
    return CKR_OK;
}

