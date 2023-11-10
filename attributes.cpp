#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "pkcs11_compat.h"
#include "openssl_compat.h"
#include "aws_kms_slot.h"

static CK_RV copyAttribute(CK_VOID_PTR pDest, CK_ULONG_PTR pulDestLen, const void *pSrc, CK_ULONG ulSrcLen)
{
    if (pulDestLen == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    if (pDest == NULL) {
        *pulDestLen = ulSrcLen;
        return CKR_OK;
    }
    if (*pulDestLen < ulSrcLen) {
        *pulDestLen = CK_UNAVAILABLE_INFORMATION;
        return CKR_BUFFER_TOO_SMALL;
    }
    memcpy(pDest, pSrc, ulSrcLen);
    *pulDestLen = ulSrcLen;

    return CKR_OK;
}

static CK_RV copyBoolAttribute(CK_VOID_PTR pDest, CK_ULONG_PTR pulDestLen, CK_BBOOL value)
{
    return copyAttribute(pDest, pulDestLen, &value, sizeof(CK_BBOOL));
}

static CK_RV copyBNAttribute(CK_VOID_PTR pDest, CK_ULONG_PTR pulDestLen, const BIGNUM *bn)
{
    CK_ULONG bnLen = BN_num_bytes(bn);

    if (pulDestLen == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    if (pDest == NULL) {
        *pulDestLen = bnLen;
        return CKR_OK;
    }
    if (*pulDestLen < bnLen) {
        *pulDestLen = CK_UNAVAILABLE_INFORMATION;
        return CKR_BUFFER_TOO_SMALL;
    }
    BN_bn2bin(bn, (unsigned char*)pDest);
    *pulDestLen = bnLen;

    return CKR_OK;
}

CK_RV getCommonAttributeValue(AwsKmsSlot& slot, CK_ATTRIBUTE_TYPE attr, CK_VOID_PTR pValue, CK_ULONG_PTR pulValueLen) {
    switch (attr) {
        case CKA_TOKEN:
            return copyBoolAttribute(pValue, pulValueLen, CK_TRUE);

        case CKA_ID: {
            string label = slot.GetKmsKeyId();
            return copyAttribute(pValue, pulValueLen, label.c_str(), label.length());
        }

        case CKA_LABEL: {
            string label = slot.GetLabel();
            if (label.length() == 0) {
                label = slot.GetKmsKeyId();
            }
            return copyAttribute(pValue, pulValueLen, label.c_str(), label.length());
        }

        default:
            *pulValueLen = CK_UNAVAILABLE_INFORMATION;
            return CKR_ATTRIBUTE_TYPE_INVALID;
    }
    return CKR_OK;
}

CK_RV getKmsKeyAttributeValue(AwsKmsSlot& slot, CK_ATTRIBUTE_TYPE attr, CK_VOID_PTR pValue, CK_ULONG_PTR pulValueLen) {
    /* Not *all* attributes need this but most of them do, so do it once here */
    Aws::Utils::ByteBuffer key_data = slot.GetPublicKeyData();

    switch (attr) {
        case CKA_CLASS: {
            CK_OBJECT_CLASS obj_class = key_data.GetLength() > 0 ? CKO_PRIVATE_KEY : CKO_DATA;
            return copyAttribute(pValue, pulValueLen, &obj_class, sizeof(CK_OBJECT_CLASS));
        }

        case CKA_SENSITIVE:
            return copyBoolAttribute(pValue, pulValueLen, CK_TRUE);

        case CKA_EXTRACTABLE:
            return copyBoolAttribute(pValue, pulValueLen, CK_FALSE);

        case CKA_SIGN:
            if (key_data.GetLength() == 0) {
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            return copyBoolAttribute(pValue, pulValueLen, CK_TRUE);

        case CKA_KEY_TYPE: {
            if (key_data.GetLength() == 0) {
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            const unsigned char* pubkey_bytes = key_data.GetUnderlyingData();
            EVP_PKEY* pkey = d2i_PUBKEY(NULL, &pubkey_bytes, key_data.GetLength());
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
            EVP_PKEY_free(pkey);
            return copyAttribute(pValue, pulValueLen, &key_type, sizeof(CK_OBJECT_CLASS));
        }

        case CKA_ALWAYS_AUTHENTICATE:
            if (key_data.GetLength() == 0) {
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            return copyBoolAttribute(pValue, pulValueLen, CK_FALSE);

        case CKA_MODULUS:
        case CKA_PUBLIC_EXPONENT: {
            if (key_data.GetLength() == 0) {
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            const unsigned char* pubkey_bytes = key_data.GetUnderlyingData();
            EVP_PKEY* pkey = d2i_PUBKEY(NULL, &pubkey_bytes, key_data.GetLength());
            if (pkey == NULL) {
                return CKR_FUNCTION_FAILED;
            }
            if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
                EVP_PKEY_free(pkey);
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            const RSA* rsa = EVP_PKEY_get0_RSA(pkey);
            const BIGNUM* bn;
            if (attr == CKA_MODULUS) {
                bn = RSA_get0_n(rsa);
            } else {
                bn = RSA_get0_e(rsa);
            }
            CK_RV ret = copyBNAttribute(pValue, pulValueLen, bn);
            EVP_PKEY_free(pkey);
            return ret;
        }

        case CKA_EC_POINT: {
            if (key_data.GetLength() == 0) {
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            const unsigned char* pubkey_bytes = key_data.GetUnderlyingData();
            EVP_PKEY *pkey = d2i_PUBKEY(NULL, &pubkey_bytes, key_data.GetLength());
            if (pkey == NULL) {
                return CKR_FUNCTION_FAILED;
            }
            if (EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
                EVP_PKEY_free(pkey);
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            const EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(pkey);

            unsigned char* buffer = NULL;
	    // ec_key argument isn't const on openssl 1.0.x
            size_t len = i2o_ECPublicKey((EC_KEY*)ec_key, &buffer);

            // Wrap the point in an ASN.1 octet string
            ASN1_OCTET_STRING* os = ASN1_STRING_new();
            ASN1_OCTET_STRING_set(os, buffer, len);

            unsigned char* buffer2 = NULL;
            size_t len2 = i2d_ASN1_OCTET_STRING(os, &buffer2);

            CK_RV ret = copyAttribute(pValue, pulValueLen, buffer2, len2);

            ASN1_STRING_free(os);
            free(buffer);
            free(buffer2);
            EVP_PKEY_free(pkey);
            return ret;
        }

        case CKA_EC_PARAMS: {
            key_data = slot.GetPublicKeyData();
            if (key_data.GetLength() == 0) {
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            const unsigned char* pubkey_bytes = key_data.GetUnderlyingData();
            EVP_PKEY *pkey = d2i_PUBKEY(NULL, &pubkey_bytes, key_data.GetLength());
            if (pkey == NULL) {
                return CKR_FUNCTION_FAILED;
            }
            if (EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
                EVP_PKEY_free(pkey);
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            const EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(pkey);
            const EC_GROUP* ec_group = EC_KEY_get0_group(ec_key);

            unsigned char *buffer = NULL;
            size_t len = i2d_ECPKParameters(ec_group, &buffer);

            CK_RV ret = copyAttribute(pValue, pulValueLen, buffer, len);

            free(buffer);
            EVP_PKEY_free(pkey);
            return ret;
        }
        default:
            return getCommonAttributeValue(slot, attr, pValue, pulValueLen);
    }

    return CKR_OK;
}

CK_RV do_get_raw_cert(const X509* cert, CK_VOID_PTR pValue, CK_ULONG_PTR pulValueLen) {
    CK_BYTE_PTR buffer = NULL;
    CK_ULONG len = i2d_X509(OSSL_UNCONST(X509, cert), &buffer);
    CK_RV ret = CKR_FUNCTION_FAILED;
    if (len > 0)
        ret = copyAttribute(pValue, pulValueLen, buffer, len);
    OPENSSL_free(buffer);
    return ret;    
}

CK_RV do_get_raw_name(const X509_NAME* name, CK_VOID_PTR pValue, CK_ULONG_PTR pulValueLen) {
    CK_BYTE_PTR buffer = NULL;
    CK_ULONG len = i2d_X509_NAME(OSSL_UNCONST(X509_NAME, name), &buffer);
    CK_RV ret = CKR_FUNCTION_FAILED;
    if (len > 0)
        ret = copyAttribute(pValue, pulValueLen, buffer, len);
    OPENSSL_free(buffer);
    return ret;    
}

CK_RV do_get_raw_integer(const ASN1_INTEGER* serial, CK_VOID_PTR pValue, CK_ULONG_PTR pulValueLen) {
    CK_BYTE_PTR buffer = NULL;
    CK_ULONG len = i2d_ASN1_INTEGER(OSSL_UNCONST(ASN1_INTEGER, serial), &buffer);
    CK_RV ret = CKR_FUNCTION_FAILED;
    if (len > 0)
        ret = copyAttribute(pValue, pulValueLen, buffer, len);
    OPENSSL_free(buffer);
    return ret;    
}

CK_RV getCertificateAttributeValue(AwsKmsSlot& slot, CK_ATTRIBUTE_TYPE attr, CK_VOID_PTR pValue, CK_ULONG_PTR pulValueLen) {
    const X509* cert = slot.GetCertificate();
    if (cert == NULL) {
        return CKR_OBJECT_HANDLE_INVALID;
    }

    switch (attr) {
        case CKA_CLASS: {
            CK_OBJECT_CLASS obj_class = CKO_CERTIFICATE;
            return copyAttribute(pValue, pulValueLen, &obj_class, sizeof(CK_OBJECT_CLASS));
        }

        case CKA_PRIVATE:
            return copyBoolAttribute(pValue, pulValueLen, CK_FALSE);

        case CKA_CERTIFICATE_TYPE: {
            CK_ULONG type = CKC_X_509;
            return copyAttribute(pValue, pulValueLen, &type, sizeof(CK_ULONG));
        }

        case CKA_MODIFIABLE:
            return copyBoolAttribute(pValue, pulValueLen, CK_FALSE);

        case CKA_TRUSTED: /* This should probably go into the JSON file */
            return copyBoolAttribute(pValue, pulValueLen, CK_FALSE);

        case CKA_SUBJECT:
            return do_get_raw_name(X509_get_subject_name(OSSL_UNCONST(X509, cert)), pValue, pulValueLen);

        case CKA_ISSUER:
            return do_get_raw_name(X509_get_issuer_name(OSSL_UNCONST(X509, cert)), pValue, pulValueLen);

        case CKA_SERIAL_NUMBER:
	    return do_get_raw_integer(X509_get0_serialNumber(OSSL_UNCONST(X509, cert)), pValue, pulValueLen);

        case CKA_VALUE:
            return do_get_raw_cert(cert, pValue, pulValueLen);
        default:
            return getCommonAttributeValue(slot, attr, pValue, pulValueLen);
    }
    return CKR_OK;
}
