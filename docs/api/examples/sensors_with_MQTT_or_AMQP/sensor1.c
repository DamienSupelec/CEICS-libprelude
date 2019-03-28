#include <libprelude/prelude.h>

int main(int argc, char *argv[])
{
	int ret;
	prelude_client_t *client;
	idmef_message_t *idmef;

	ret = prelude_init(&argc, argv);
	if ( ret < 0 ) {
		prelude_perror(ret, "unable to initialize the prelude library");
		return -1;
	}

	ret = prelude_client_new(&client, "sensor1");
	if (  ! client ) {
		prelude_perror(ret, "Unable to create a prelude client object");
		return -1;
	}

	ret = prelude_client_start(client);
	if ( ret < 0 ) {
		prelude_perror(ret, "Unable to start prelude client");
		return -1;
	}
	
	ret = prelude_client_set_flags(client, PRELUDE_CLIENT_FLAGS_ASYNC_SEND|PRELUDE_CLIENT_FLAGS_ASYNC_TIMER);
	if ( ret < 0 ) {
		fprintf(stderr, "Unable to set flags");
		return -1;
	}

	
	ret = idmef_message_new(&idmef);
	idmef_message_set_string(idmef, "alert.classification.text", "My classification text");
	idmef_message_set_string(idmef, "alert.classification.reference(0).name", "OSVDB-XXXX");
	idmef_message_set_string(idmef, "alert.classification.reference(0).origin", "osvdb");
	idmef_message_set_string(idmef, "alert.classification.reference(0).url", "htp://my.url/");

	prelude_client_send_idmef(client, idmef);

	idmef_message_destroy(idmef);

	prelude_client_destroy(client, PRELUDE_CLIENT_EXIT_STATUS_SUCCESS);
	
}
