#include <stdio.h>
#include <stdlib.h>
#include <pkcs11.h>
#include <dlfcn.h>

void dump_bytes(const char* name, const unsigned char* bytes, unsigned long len) {
    printf("%s=", name);
    for (unsigned long i = 0; i < len; i++) {
        printf("%.2X ", bytes[i]);
    }
    printf("\n");
}

CK_RV get_and_dump_attribute(CK_FUNCTION_LIST* f, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_TYPE type, const char* name) {
    CK_ATTRIBUTE attrs[1];
    attrs[0].type = type;
    attrs[0].pValue = NULL;
    attrs[0].ulValueLen = 0;
    CK_RV res = f->C_GetAttributeValue(session, obj, attrs, 1);
    if (res != CKR_OK) {
        printf("Fail C_GetAttributeValue for attribute size, res=%ld\n", res);
        return res;
    }
    attrs[0].pValue = malloc(attrs[0].ulValueLen);
    res = f->C_GetAttributeValue(session, obj, attrs, 1);
    if (res != CKR_OK) {
        printf("Fail C_GetAttributeValue for getting attribute, res=%ld\n", res);
        return res;
    }

    dump_bytes(name, (const unsigned char*)attrs[0].pValue, attrs[0].ulValueLen);
    free(attrs[0].pValue);

    return CKR_OK;
}

CK_RV test_all_keys_in_slot(CK_FUNCTION_LIST* f, CK_SLOT_ID slotID) {
    printf("Testing slot ID: %ld\n", slotID);

    CK_TOKEN_INFO token_info;
    CK_RV res = f->C_GetTokenInfo(slotID, &token_info);
    if (res != CKR_OK) {
        printf("Fail C_GetTokenInfo, res=%ld", res);
        return res;
    }
    token_info.label[31] = '\0';
    printf("Slot=%ld, token=%s\n", slotID, token_info.label);

    CK_SESSION_HANDLE session;
    res = f->C_OpenSession(slotID, (CK_FLAGS)0, NULL_PTR, NULL_PTR, &session);
    if (res != CKR_OK) {
        printf("Fail C_OpenSession, res=%ld", res);
        return res;
    }

    res = f->C_FindObjectsInit(session, NULL_PTR, 0);
    if (res != CKR_OK) {
        printf("Fail C_FindObjectsInit, res=%ld\n", res);
        return res;
    }

    CK_ULONG objectCount = 1;
    while (objectCount == 1) {
        CK_OBJECT_HANDLE obj;
        res = f->C_FindObjects(session, &obj, 1, &objectCount);
        if (res != CKR_OK) {
            printf("Fail C_FindObjects, res=%ld\n", res);
            return res;
        }
        if (objectCount == 0) {
            break;
        }

        CK_OBJECT_CLASS object_class;
        CK_OBJECT_CLASS key_type;
        CK_ATTRIBUTE attrs[1];

        attrs[0].type = CKA_CLASS;
        attrs[0].pValue = &object_class;
        attrs[0].ulValueLen = sizeof(CK_OBJECT_CLASS);
        CK_RV res = f->C_GetAttributeValue(session, obj, attrs, 1);
        if (res != CKR_OK) {
            printf("Fail C_GetAttributeValue for CKA_CLASS, res=%ld\n", res);
            return res;
        }
        if (object_class != CKO_PRIVATE_KEY) {
            printf("Skipping object because it is not a private key.\n");
            continue;
        }

        attrs[0].type = CKA_KEY_TYPE;
        attrs[0].pValue = &key_type;
        attrs[0].ulValueLen = sizeof(CK_OBJECT_CLASS);
        res = f->C_GetAttributeValue(session, obj, attrs, 1);
        if (res != CKR_OK) {
            printf("Fail C_GetAttributeValue for CKA_KEY_TYPE, res=%ld\n", res);
            return res;
        }

        if (key_type == CKK_RSA) {
            res = get_and_dump_attribute(f, session, obj, CKA_PUBLIC_EXPONENT, "exponent");
            if (res != CKR_OK) {
                printf("Fail get_and_dump_attribute for attribute CKA_PUBLIC_EXPONENT\n");
                return res;
            }

            res = get_and_dump_attribute(f, session, obj, CKA_MODULUS, "modulus");
            if (res != CKR_OK) {
                printf("Fail get_and_dump_attribute for attribute CKA_MODULUS\n");
                return res;
            }
        } else if (key_type == CKK_ECDSA) {
            res = get_and_dump_attribute(f, session, obj, CKA_EC_PARAMS, "group");
            if (res != CKR_OK) {
                printf("Fail get_and_dump_attribute for attribute CKA_EC_PARAMS\n");
                return res;
            }

            res = get_and_dump_attribute(f, session, obj, CKA_EC_POINT, "point");
            if (res != CKR_OK) {
                printf("Fail get_and_dump_attribute for attribute CKA_EC_POINT\n");
                return res;
            }
        }

        const unsigned char DATA[] = {
          0xb5, 0xbb, 0x9d, 0x80, 0x14, 0xa0, 0xf9, 0xb1, 0xd6, 0x1e, 0x21, 0xe7,
          0x96, 0xd7, 0x8d, 0xcc, 0xdf, 0x13, 0x52, 0xf2, 0x3c, 0xd3, 0x28, 0x12,
          0xf4, 0x85, 0x0b, 0x87, 0x8a, 0xe4, 0x94, 0x4c
        };

        CK_MECHANISM mechanism;
        if (key_type == CKK_RSA) {
            mechanism.mechanism = CKM_RSA_PKCS;
        } else if (key_type == CKK_ECDSA) {
            mechanism.mechanism = CKM_ECDSA;
        }
        res = f->C_SignInit(session, &mechanism, obj);
        if (res != CKR_OK) {
            printf("Fail C_SignInit, res=%ld\n", res);
            return res;
        }

        unsigned char *dgst = (unsigned char*)DATA;
        CK_ULONG siglen = 0;
        res = f->C_Sign(session, dgst, sizeof(DATA), NULL_PTR, &siglen);
        if (res != CKR_OK) {
            printf("Failed to call C_Sign to get signature size, res=%ld\n", res);
            return res;
        }

        unsigned char* sig = (unsigned char*)malloc(siglen);
        res = f->C_Sign(session, dgst, sizeof(DATA), sig, &siglen);
        if (res != CKR_OK) {
            printf("Fail C_Sign, res=%ld\n", res);
            return res;
        }
        dump_bytes("sig", sig, siglen);
        free(sig);
    }
    res = f->C_FindObjectsFinal(session);
    if (res != CKR_OK) {
        printf("Fail C_FindObjectsFinal, res=%ld\n", res);
        return res;
    }

    res = f->C_CloseSession(session);
    if (res != CKR_OK) {
        printf("Failed to call C_CloseSession, res=%ld", res);
        return res;
    }

    return CKR_OK;
}

int main(int argc, char** argv) {
    void* handle;
    CK_RV (*getfunctionlist)(CK_FUNCTION_LIST **);
    CK_FUNCTION_LIST* f;
    CK_RV res;

    handle = dlopen("./aws_kms_pkcs11.so", RTLD_NOW);
    if (handle == NULL) {
        printf("Fail to load aws_kms_pkcs11.so: %s\n", dlerror());
        return 1;
    }
    getfunctionlist = (CK_RV (*)(CK_FUNCTION_LIST**)) dlsym(handle, "C_GetFunctionList");
    if (getfunctionlist == NULL) {
        printf("dlsym(C_GetFunctionList) failed: %s", dlerror());
        return 1;
    }

    res = (*getfunctionlist)(&f);
    if (res != CKR_OK) {
        printf("C_GetFunctionList failed: %lu", res);
        return 1;
    }

    res = f->C_Initialize(NULL_PTR);
    if (res != CKR_OK) {
        printf("Fail C_Initialize, res=%ld\n", res);
        return 1;
    }

    CK_SLOT_ID_PTR pSlotList = NULL_PTR;
    CK_ULONG slotCount;
    res = f->C_GetSlotList(CK_TRUE, NULL_PTR, &slotCount);
    if (res != CKR_OK) {
        printf("Fail C_GetSlotList, res=%ld\n", res);
        return 1;
    }

    pSlotList = malloc(slotCount * sizeof(CK_SLOT_ID));
    if (pSlotList == NULL) {
        printf("Failed to allocate memory to store slot IDs.");
        return 1;
    }
    res = f->C_GetSlotList(CK_TRUE, pSlotList, &slotCount);
    if (res != CKR_OK) {
        printf("Fail C_GetSlotList, res=%ld\n", res);
        return 1;
    }

    for (size_t i = 0; i < slotCount; i++) {
        res = test_all_keys_in_slot(f, pSlotList[i]);
        if (res != CKR_OK) {
            printf("Failed to run test on slot %ld\n", pSlotList[i]);
            return 1;
        }
    }
    free(pSlotList);

    res = f->C_Finalize(NULL_PTR);
    if (res != CKR_OK) {
        printf("Fail C_Finalize, res=%ld\n", res);
        return 1;
    }

    printf("Test successful!\n");
    dlclose(handle);
    return 0;
}
