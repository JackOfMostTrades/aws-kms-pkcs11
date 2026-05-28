/*
 * Wrapper around pkcs11.h which defines some macros/types that may or may not be
 * there depending on the variant of pkcs11.h present on the system.
 *
 * The recommendation seems to be, long run, to switch to using NULL, true and false
 * directly rather than those macros.
 */
#ifndef __PKCS11_COMPAT_H__
#define __PKCS11_COMPAT_H__

#include <stdbool.h>
#include <pkcs11.h>

#ifndef CK_NULL_PTR
#define CK_NULL_PTR NULL
#endif

#ifndef NULL_PTR
#define NULL_PTR NULL
#endif

#ifndef CK_TRUE
#define CK_TRUE true
#endif

#ifndef CK_FALSE
#define CK_FALSE false
#endif

/*
 * PKCS#11 v3.2 mechanism, key type, and parameter-set constants for ML-DSA
 * (FIPS 204). Defined here only if the system pkcs11.h predates v3.2.
 * Values match the OASIS PKCS#11 v3.2 spec (pkcs11t.h) and what
 * Kryoptic / pkcs11-provider use:
 *   CKM_ML_DSA = 0x1D, CKK_ML_DSA = 0x4A, CKA_PARAMETER_SET = 0x61D,
 *   CKP_ML_DSA_{44,65,87} = 1/2/3.
 */
#ifndef CKM_ML_DSA
#define CKM_ML_DSA 0x0000001DUL
#endif
#ifndef CKK_ML_DSA
#define CKK_ML_DSA 0x0000004AUL
#endif

#ifndef CKA_PUBLIC_KEY_INFO
#define CKA_PUBLIC_KEY_INFO 0x00000129UL
#endif

#ifndef CKA_COPYABLE
#define CKA_COPYABLE 0x00000171UL
#endif

#ifndef CKA_PARAMETER_SET
#define CKA_PARAMETER_SET 0x0000061DUL
#endif

#ifndef CKP_ML_DSA_44
#define CKP_ML_DSA_44 0x00000001UL
#define CKP_ML_DSA_65 0x00000002UL
#define CKP_ML_DSA_87 0x00000003UL
#endif

/* opencryptoki in ubuntu 20.04 is missing that one */
#ifndef CKR_ACTION_PROHIBITED
#define CKR_ACTION_PROHIBITED			(0x1BUL)
#endif

#endif /* __PKCS11_COMPAT_H__ */

