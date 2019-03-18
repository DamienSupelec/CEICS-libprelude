/*****
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2, or (at your option)
* any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License along
* with this program; if not, write to the Free Software Foundation, Inc.,
* 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*
*****/

#ifndef _LIBPRELUDE_PKI_AUTH_H
#define _LIBPRELUDE_PKI_AUTH_H

#ifdef __cplusplus
 extern "C" {
#endif

#include "prelude-client-profile.h"

typedef struct pki_credentials pki_credentials_t;

int pki_credentials_new(pki_credentials_t **newcred);

void pki_credentials_destroy(pki_credentials_t *cred);

char *pki_credentials_get_pubcert(pki_credentials_t *cred);

char *pki_credentials_get_privkey(pki_credentials_t *cred);

char *pki_credentials_get_trustca(pki_credentials_t *cred);

int pki_auth_init(prelude_client_profile_t *cp, pki_credentials_t **cred);

#ifdef __cplusplus
 }
#endif

#endif
