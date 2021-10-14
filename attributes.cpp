#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "pkcs11_compat.h"
#include "aws_kms_slot.h"

CK_RV getKmsKeyAttributeValue(AwsKmsSlot& slot, CK_ATTRIBUTE_TYPE attr, CK_VOID_PTR pValue, CK_ULONG_PTR pulValueLen) {

    unsigned char* buffer, *buffer2;
    EVP_PKEY* pkey;
    const RSA* rsa;
    const EC_KEY* ec_key;
    const EC_GROUP* ec_group;
    const BIGNUM* bn;
    size_t len, len2;
    string label;
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
        case CKA_TOKEN:
            *pulValueLen = sizeof(CK_BBOOL);
            if (pValue != NULL_PTR) {
                *((CK_BBOOL*)pValue) = CK_TRUE;
            }
            break;
        case CKA_ID:
	    label = slot.GetKmsKeyId();
            *pulValueLen = label.length();
            if (pValue != NULL_PTR) {
                memcpy(pValue, label.c_str(), label.length());
            }
            break;
        case CKA_LABEL:
	    label = slot.GetLabel();
	    if (label.length() == 0) {
		    label = slot.GetKmsKeyId();
	    }
            *pulValueLen = label.length();
            if (pValue != NULL_PTR) {
                memcpy(pValue, label.c_str(), label.length());
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

CK_RV do_get_raw_cert(X509* cert, CK_BYTE_PTR* out, CK_ULONG_PTR out_len) {
  *out = NULL;
  *out_len = i2d_X509(cert, out);
  if (*out_len <= 0) {
    if (*out != NULL) {
      OPENSSL_free(*out);
      *out = NULL;
    }
    return CKR_FUNCTION_FAILED;
  }
  return CKR_OK;
}

CK_RV do_get_raw_name(X509_NAME* name, CK_BYTE_PTR* out, CK_ULONG_PTR out_len) {
  *out = NULL;
  *out_len = i2d_X509_NAME(name, out);
  if (*out_len <= 0) {
    if (*out != NULL) {
      OPENSSL_free(*out);
      *out = NULL;
    }
    return CKR_FUNCTION_FAILED;
  }
  return CKR_OK;
}

CK_RV do_get_raw_integer(ASN1_INTEGER* serial, CK_BYTE_PTR* out, CK_ULONG_PTR out_len) {
  *out = NULL;
  *out_len = i2d_ASN1_INTEGER(serial, out);
  if (*out_len <= 0) {
    if (*out != NULL) {
      OPENSSL_free(*out);
      *out = NULL;
    }
    return CKR_FUNCTION_FAILED;
  }
  return CKR_OK;
}

CK_RV getCertificateAttributeValue(AwsKmsSlot& slot, CK_ATTRIBUTE_TYPE attr, CK_VOID_PTR pValue, CK_ULONG_PTR pulValueLen) {
  CK_BYTE_PTR data = NULL;
  CK_BBOOL    free_data = CK_FALSE;
  CK_BBOOL    bool_tmp;
  CK_ULONG    ul_tmp;
  CK_ULONG    len = 0;
  CK_RV       rv;
  string      label;

  X509* cert = slot.GetCertificate();
  if (cert == NULL) {
    return CKR_OBJECT_HANDLE_INVALID;
  }

  switch (attr) {
  case CKA_CLASS:
    len = sizeof(CK_ULONG);
    ul_tmp = CKO_CERTIFICATE;
    data = (CK_BYTE_PTR) &ul_tmp;
    break;

  case CKA_TOKEN:
    len = sizeof(CK_BBOOL);
    bool_tmp = CK_TRUE;
    data = (CK_BYTE_PTR) &bool_tmp;
    break;

  case CKA_PRIVATE:
    len = sizeof(CK_BBOOL);
    bool_tmp = CK_FALSE;
    data = (CK_BYTE_PTR) &bool_tmp;
    break;

  case CKA_CERTIFICATE_TYPE:
    len = sizeof(CK_ULONG);
    ul_tmp = CKC_X_509; // Support only X.509 certs
    data = (CK_BYTE_PTR) &ul_tmp;
    break;

  case CKA_MODIFIABLE:
    len = sizeof(CK_BBOOL);
    bool_tmp = CK_FALSE;
    data = (CK_BYTE_PTR) &bool_tmp;
    break;

  case CKA_TRUSTED:
    len = sizeof(CK_BBOOL);
    bool_tmp = CK_FALSE;
    data = (CK_BYTE_PTR) &bool_tmp;
    break;

  case CKA_ID:
    label = slot.GetKmsKeyId();
    len = label.length();
    data = (CK_BYTE_PTR)label.c_str();
    break;

  case CKA_LABEL:
    label = slot.GetLabel();
    if (label.length() == 0) {
      label = slot.GetKmsKeyId();
    }
    len = label.length();
    data = (CK_BYTE_PTR)label.c_str();
    break;

  case CKA_SUBJECT:
    if ((rv = do_get_raw_name(X509_get_subject_name(cert), &data, &len)) != CKR_OK) {
      return rv;
    }
    free_data = CK_TRUE;
    break;

  case CKA_ISSUER:
    if ((rv = do_get_raw_name(X509_get_issuer_name(cert), &data, &len)) != CKR_OK) {
      return rv;
    }
    free_data = CK_TRUE;
    break;

  case CKA_SERIAL_NUMBER:
    if ((rv = do_get_raw_integer(X509_get_serialNumber(cert), &data, &len)) != CKR_OK) {
      return rv;
    }
    free_data = CK_TRUE;
    break;

  case CKA_VALUE:
    if ((rv = do_get_raw_cert(cert, &data, &len)) != CKR_OK) {
      return rv;
    }
    free_data = CK_TRUE;
    break;

  default:
    *pulValueLen = CK_UNAVAILABLE_INFORMATION;
    return CKR_ATTRIBUTE_TYPE_INVALID;
  }

  /* Just get the length */
  if (pValue == NULL) {
    *pulValueLen = len;
    if (free_data) {
      free(data);
    }
    return CKR_OK;
  }

  /* Actually get the attribute */
  if (*pulValueLen < len) {
    if (free_data) {
      free(data);
    }
    return CKR_BUFFER_TOO_SMALL;
  }

  *pulValueLen = len;
  memcpy(pValue, data, len);

  if (free_data) {
    free(data);
  }
  return CKR_OK;
}
