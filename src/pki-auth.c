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

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include "prelude-error.h"

#include "common.h"
#include "prelude-log.h"
#include "prelude-client-profile.h"

#include "pki-auth.h"

struct pki_credentials {
	int refcount;
	char *privkey_filename;
	char *pubcert_filename;
	char *trustca_filename;
};


/**
 * pki_credentials_new:
 * @newcred: pointer to pki_credentials objet to initialize
 *
 * This function initialize the @newcred object.
 * 
 * Returns: 0 on success or a negativie value if an error occur.
 */
int pki_credentials_new(pki_credentials_t **newcred)
{
	pki_credentials_t *cred;
	cred = calloc(1, sizeof(*cred));
	if ( ! cred )
		return prelude_error_from_errno(errno);
	cred->refcount = 1;
	cred->privkey_filename = cred->pubcert_filename = cred->trustca_filename = NULL;
	*newcred = cred;
	return 0;
}

/**
 * pki_credentials_destroy:
 * @cred: pki_credentials objet to destroy
 *
 * This function destroy the @cred object.
 * 
 * Returns: 0 on success or a negativie value if an error occur.
 */
void pki_credentials_destroy(pki_credentials_t *cred)
{
	prelude_return_if_fail(cred);
	if ( --cred->refcount > 0 )
		return;
	free(cred->privkey_filename);
	free(cred->pubcert_filename);
	free(cred->trustca_filename);
	free(cred);
}
	

/**
 * pki_auth_init:
 * @cred: pointer to pki_credentials objet to fill 
 *
 * This function allocates the object pointed by @cred if it is NULL,
 * and fill it with the credentials associated with @cp.
 * 
 * Returns: 0 on success or a negativie value if an error occur.
 */
int pki_auth_init(prelude_client_profile_t *cp, pki_credentials_t **cred)
{
	int ret;
	char keyfile[PATH_MAX], certfile[PATH_MAX], trustfile[PATH_MAX];
	if ( ! *cred ){
		ret = pki_credentials_new(cred);
		if ( ret < 0 )
			return ret;
	}
	free((*cred)->privkey_filename);
	free((*cred)->pubcert_filename);
	free((*cred)->trustca_filename);
	(*cred)->privkey_filename = (*cred)->pubcert_filename = (*cred)->trustca_filename = NULL;

	prelude_client_profile_get_pki_key_filename(cp, keyfile, sizeof(keyfile));
	ret = access(keyfile, F_OK);
	if ( ret < 0 )
		return prelude_error_verbose_make(PRELUDE_ERROR_SOURCE_CLIENT, PRELUDE_ERROR_PROFILE, "access to %s failed: %s", keyfile, strerror(errno));

	prelude_client_profile_get_pki_pubcert_filename(cp, certfile, sizeof(keyfile));
	ret = access(certfile, F_OK);
	if ( ret < 0 )
		return prelude_error_verbose_make(PRELUDE_ERROR_SOURCE_CLIENT, PRELUDE_ERROR_PROFILE, "access to %s failed: %s", certfile, strerror(errno));

	prelude_client_profile_get_pki_cacert_filename(cp, trustfile, sizeof(keyfile));
	ret = access(trustfile, F_OK);
	if ( ret < 0 )
		return prelude_error_verbose_make(PRELUDE_ERROR_SOURCE_CLIENT, PRELUDE_ERROR_PROFILE, "access to %s failed: %s", trustfile, strerror(errno));
	
	(*cred)->privkey_filename = strdup(keyfile);
	(*cred)->pubcert_filename = strdup(certfile);
	(*cred)->trustca_filename = strdup(trustfile);
	
	return 0;
}

char *pki_credentials_get_pubcert(pki_credentials_t *cred)
{
	prelude_return_val_if_fail(cred, NULL);
	prelude_return_val_if_fail(cred->pubcert_filename, NULL);
	
	return cred->pubcert_filename;		
}

char *pki_credentials_get_privkey(pki_credentials_t *cred)
{
	prelude_return_val_if_fail(cred, NULL);
	prelude_return_val_if_fail(cred->privkey_filename, NULL);
	
	return cred->privkey_filename;		
}

char *pki_credentials_get_trustca(pki_credentials_t *cred)
{
	prelude_return_val_if_fail(cred, NULL);
	prelude_return_val_if_fail(cred->trustca_filename, NULL);
	
	return cred->trustca_filename;		
}

