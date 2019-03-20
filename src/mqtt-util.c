#include "config.h"

#include <stdlib.h>
#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "prelude-error.h"
#include "prelude-connection.h"
#include "prelude-client-profile.h"
#include "mqtt-util.h"

int mqtt_set_conn_perm_from_profile(prelude_connection_permission_t *permission, prelude_client_profile_t *profile)
{
	gnutls_x509_crt_t *pubcertlist;
	gnutls_certificate_credentials_t tls_credentials;
	char buf[1024];
	int ret, tmp, i;
	unsigned int crt_list_size;
	size_t size;

	size = sizeof(buf)/sizeof(buf[0]);
		

	ret = prelude_client_profile_get_credentials(profile, (void **) &tls_credentials);
	if ( ret < 0 )
		return ret;
	
	ret = gnutls_certificate_get_x509_crt(tls_credentials, 0, &pubcertlist, &crt_list_size);
	if ( ret < 0 )
		return ret;

	
	ret = gnutls_x509_crt_get_dn_by_oid(pubcertlist[0], GNUTLS_OID_X520_COMMON_NAME, 0, 0, buf, &size);
	if ( ret < 0 ) {
		for (i = 0; i < crt_list_size; ++i) gnutls_x509_crt_deinit(pubcertlist[i]);
		gnutls_free(pubcertlist);
		return prelude_error_verbose(PRELUDE_ERROR_TLS, "could not get certificate CN field: %s", gnutls_strerror(ret));
	}
	ret = sscanf(buf, "%d", &tmp);
	if ( ret != 1 ) {
		for (i = 0; i < crt_list_size; ++i) gnutls_x509_crt_deinit(pubcertlist[i]);
		gnutls_free(pubcertlist);
		return prelude_error_verbose(PRELUDE_ERROR_TLS, "certificate analyzer id value '%s' is invalid", buf);
	}

	*permission = (prelude_connection_permission_t) tmp;
	for (i = 0; i < crt_list_size; ++i) gnutls_x509_crt_deinit(pubcertlist[i]);
	gnutls_free(pubcertlist);

	return 0;	
}

