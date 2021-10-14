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

/* opencryptoki in ubuntu 20.04 is missing that one */
#ifndef CKR_ACTION_PROHIBITED
#define CKR_ACTION_PROHIBITED			(0x1BUL)
#endif

#endif /* __PKCS11_COMPAT_H__ */

