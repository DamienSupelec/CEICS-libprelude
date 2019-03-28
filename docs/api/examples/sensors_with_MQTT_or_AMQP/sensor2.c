#include <stdlib.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include <libprelude/prelude.h>
#include <libprelude/prelude-message-id.h>
#include <libprelude/idmef-message-print.h>

int enter_key_pressed(void)
{
        fd_set set;
        struct timeval tv;

        tv.tv_sec = 0;
        tv.tv_usec = 100;

        FD_ZERO(&set);
        FD_SET(0, &set);

        return select(1, &set, NULL, NULL, &tv) > 0 ? 1 : 0;
}

void flush_stdin(void)
{
        int c;
        while ( (c = getchar()) != '\n' && c != EOF );
}



void handle_idmef_message(prelude_msg_t *msg)
{
	idmef_message_t *idmef;
	prelude_io_t *pio;
	int ret;
	ssize_t size;
	char *buffer;	

	ret = prelude_io_new(&pio);
	if ( ret < 0 ){
		fputs("Failed to create pio object\n", stderr);
		return;
	}

	prelude_io_set_buffer_io(pio);

	ret =idmef_message_new(&idmef);
	if ( ret < 0 ){
		fputs("Failed to create idmef msg object\n", stderr);
		prelude_io_destroy(pio);
		return;
	}

	ret = idmef_message_read(idmef, msg);
	if ( ret < 0 ){
		fputs("Failed to read idmef message\n", stderr);
		prelude_io_destroy(pio);
		idmef_message_destroy(idmef);
		return;
	}
	
	idmef_message_print(idmef, pio);	
	if ( ret < 0 ){
		fputs("Failed to print idmef message\n", stderr);
		prelude_io_destroy(pio);
		idmef_message_destroy(idmef);
		return;
	}
	size = prelude_io_pending(pio);
	if ( ! (buffer = malloc(size * sizeof(*buffer))) ){
		fputs("Failed to malloc\n", stderr);
		prelude_io_destroy(pio);
		idmef_message_destroy(idmef);
		return;
	}
	if ( size <= 0 ){
		fputs("Nothing to be read after idmef_message_print\n", stderr);
		free(buffer);
		prelude_io_destroy(pio);
		idmef_message_destroy(idmef);
		return;
	}
	size = prelude_io_read(pio, buffer, size);

	printf("%s\n", buffer);
	
	free(buffer);
	prelude_io_destroy(pio);
	idmef_message_destroy(idmef);
}

void receive_and_handle_msg(prelude_client_t *client, int timeout)
{
	int ret;
	uint8_t tag;
	prelude_msg_t *msg;
	
	ret = prelude_client_recv_msg(client, timeout, &msg);
	if (ret < 0){
		fputs("Failed to receive a message", stderr);
		return;
	} else if (ret == 0)
		return;
	
	tag = prelude_msg_get_tag(msg);
	fputs("\n=== Got a new message ===\n", stdout);
	switch (tag){
	case PRELUDE_MSG_IDMEF:
		fputs("=> This is an IDMEF message\n", stdout);
		handle_idmef_message(msg);
		break;
	case PRELUDE_MSG_ID:
		fputs("=> This is an ID message\n", stdout);
		break;
	case PRELUDE_MSG_AUTH:
		fputs("=> This is an AUTH message\n", stdout);
		break;
	case PRELUDE_MSG_CM:
		fputs("=> This is an CM message\n", stdout);
		break;
	case PRELUDE_MSG_CONNECTION_CAPABILITY:
		fputs("=> This is an CONNECTION_CAPABILITY message\n", stdout);
		break;
	case PRELUDE_MSG_OPTION_REQUEST:
		fputs("=> This is an OPTION_REQUEST message\n", stdout);
		break;
	case PRELUDE_MSG_OPTION_REPLY:
		fputs("=> This is an OPTION_REPLY message\n", stdout);
		break;
	default:
		fprintf(stdout, "/!\\ Unknown tag (%hhu)\n", tag);
		break;
	}
	
	prelude_msg_destroy(msg);	
}

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

	ret = prelude_client_new(&client, "sensor2");
	if (  ! client ) {
		prelude_perror(ret, "Unable to create a prelude client object");
		return -1;
	}

	prelude_client_set_required_permission(client, PRELUDE_CONNECTION_PERMISSION_IDMEF_WRITE | PRELUDE_CONNECTION_PERMISSION_IDMEF_READ);

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

	puts("Ready, now waiting for messages. Press Enter to terminate");
	while ( !enter_key_pressed() ){	
		receive_and_handle_msg(client, 2);
	}	
	flush_stdin();
	prelude_client_destroy(client, PRELUDE_CLIENT_EXIT_STATUS_SUCCESS);
	
}
