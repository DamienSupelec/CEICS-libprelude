#include "config.h"

#include <stdlib.h>
#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "common.h"
#include "prelude-error.h"
#include "prelude-connection.h"
#include "prelude-client-profile.h"
#include "pki-auth.h"
#include "tls-util.h"
#include "mqtt-util.h"


int mqtt_set_conn_perm_from_profile(prelude_connection_permission_t *permission, prelude_client_profile_t *profile)
{
	pki_credentials_t *pki_credentials;
	char buf[1024];
	int ret, tmp, i;
	unsigned int crt_list_size;
	size_t size;
	gnutls_x509_crt_t pubcert[1];
	gnutls_datum_t certfile;
	char *pubcert_path;

	size = sizeof(buf)/sizeof(buf[0]);
		

	ret = prelude_client_profile_get_pkicredentials(profile, (void **) &pki_credentials);
	if ( ret < 0 )
		return ret;
	
	pubcert_path = pki_credentials_get_pubcert(pki_credentials);
	if ( ! pubcert_path )
		return -1;

	ret = _prelude_load_file(pubcert_path, &certfile.data, &size);
	if ( ret < 0 )
		return ret;
	certfile.size = (unsigned int) size;

	crt_list_size = sizeof(pubcert)/sizeof(*pubcert);
	
	ret = _prelude_tls_crt_list_import(pubcert, &crt_list_size, &certfile, GNUTLS_X509_FMT_PEM);
	if ( ret < 0 ) {
		ret = prelude_error_verbose(PRELUDE_ERROR_PROFILE, "error importing certificate: %s", gnutls_strerror(ret));
		_prelude_unload_file(certfile.data, certfile.size);
		return ret;
	}
	_prelude_unload_file(certfile.data, certfile.size);
	
	ret = gnutls_x509_crt_get_dn_by_oid(pubcert[0], GNUTLS_OID_X520_COMMON_NAME, 0, 0, buf, &size);
	if ( ret < 0 ) {
		for (i = 0; i < crt_list_size; ++i) gnutls_x509_crt_deinit(pubcert[i]);
		return prelude_error_verbose(PRELUDE_ERROR_TLS, "could not get certificate CN field: %s", gnutls_strerror(ret));
	}
	ret = sscanf(buf, "%d", &tmp);
	if ( ret != 1 ) {
		for (i = 0; i < crt_list_size; ++i) gnutls_x509_crt_deinit(pubcert[i]);
		return prelude_error_verbose(PRELUDE_ERROR_TLS, "certificate analyzer id value '%s' is invalid", buf);
	}

	*permission = (prelude_connection_permission_t) tmp;
	for (i = 0; i < crt_list_size; ++i) gnutls_x509_crt_deinit(pubcert[i]);

	return 0;	
}

