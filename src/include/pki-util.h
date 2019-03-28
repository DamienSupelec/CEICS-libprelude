#ifndef PKI_UTIL_H
#define PKI_UTIL_H

#include "prelude-connection.h"

#ifdef __cplusplus
 extern "C" {
#endif

int pki_set_conn_perm_from_profile(prelude_connection_permission_t *permission, prelude_client_profile_t *profile);

#endif

#ifdef __cplusplus
 }
#endif

