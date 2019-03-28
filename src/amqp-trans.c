#include "config.h"
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>

#include "cpikalib.h"
#include "amqp-trans.h"

#define return_val_if_null(obj, val) do{ if ( ! ( obj ) ){\
                                     		fputs( #obj " is NULL\n", stderr);\
                                     		return (val) ;\
                                     	 }\
                        	    }while(0)

#define return_if_null(obj) do{ if ( ! ( obj ) ){\
                            		fputs( #obj " is NULL\n", stderr);\
                           		return ;\
                            	}\
                     	    }while(0)

typedef enum { AMQP_TRANSPORTER_NEED_CREDS, AMQP_TRANSPORTER_CONNECTED, AMQP_TRANSPORTER_DISCONNECTED } AMQP_transporter_state;

struct AMQP_transporter {
	struct {
		PyObject *module;
		PyObject *producer;
		PyObject *consumer;
	} client;

	AMQP_transporter_state state;
	
	char *address;
	unsigned int port;

	pthread_t thread;
};

int AMQP_transporter_new(AMQP_transporter_t **new, int * const rfd, const char *address, const unsigned int port)
{
	AMQP_transporter_t *newtrans;
	int ret, tmprfd;

	return_val_if_null(new, -1);
	return_val_if_null(rfd, -1);
	return_val_if_null(address, -1);
	
	newtrans = calloc(1, sizeof(*newtrans));
	if ( !newtrans )
		return -1;
	
	newtrans->address = strdup(address);
	if ( !newtrans->address ){
		free(newtrans);
		return -1;
	}

	newtrans->port = port;
	
	ret = cpl_init(&newtrans->client.module);
	if ( ret < 0 ){
		free(newtrans->address);
		free(newtrans);
		return -1;
	}

	ret = cpl_AMQP_producer_new(&newtrans->client.producer, address, port, newtrans->client.module);
	if ( ret < 0 ){
		free(newtrans->address);
		cpl_finalize();
		free(newtrans);
		return -1;
	}

	ret = cpl_AMQP_consumer_new(&newtrans->client.consumer, address, port, newtrans->client.module);
	if ( ret < 0 ){
		free(newtrans->address);
		cpl_destroy(newtrans->client.producer);
		cpl_finalize();
		free(newtrans);
		return -1;
	}

	ret = cpl_AMQP_consumer_get_rfd(newtrans->client.consumer, &tmprfd);
	if ( ret < 0 ){
		free(newtrans->address);
		cpl_destroy(newtrans->client.producer);
		cpl_destroy(newtrans->client.consumer);
		cpl_finalize();
		free(newtrans);
		return -1;
	}
	*rfd = tmprfd;

	ret = fcntl(*rfd, F_SETFL, (fcntl(*rfd, F_GETFL) | O_NONBLOCK));
	if ( ret < 0 ){
		perror("fcntl failed while making read-end of pipe non blocking: ");
		free(newtrans->address);
		close(*rfd);	
		cpl_destroy(newtrans->client.producer);
		cpl_destroy(newtrans->client.consumer);
		cpl_finalize();
		free(newtrans);
		return -1;
	}

	newtrans->state = AMQP_TRANSPORTER_NEED_CREDS;

	*new = newtrans;
	return 0;
}

int AMQP_transporter_set_pkicredentials(AMQP_transporter_t * const trans, const char *pubcert_filename, const char *privkey_filename, const char *cacert_filename)
{
	int ret;
	return_val_if_null(trans, -1);
	return_val_if_null(pubcert_filename, -1);
	return_val_if_null(privkey_filename, -1);
	return_val_if_null(cacert_filename, -1);


	if ( trans->state != AMQP_TRANSPORTER_NEED_CREDS ){
		fputs("Already has credentials\n", stderr);
		return -1;
	}

	ret = cpl_AMQP_set_pkicredentials(trans->client.producer, pubcert_filename, privkey_filename, cacert_filename);
	if ( ret < 0 ){
		fputs("Failed to set pki credentials\n", stderr);
		return ret;
	}
	ret = cpl_AMQP_set_pkicredentials(trans->client.consumer, pubcert_filename, privkey_filename, cacert_filename);
	if ( ret < 0 ){
		fputs("Failed to set pki credentials\n", stderr);
		return ret;
	}
	trans->state = AMQP_TRANSPORTER_DISCONNECTED;
	return 0;	
}

int AMQP_transporter_add_pub_queue(AMQP_transporter_t * const trans, const char * queuename)
{
	int ret;
	return_val_if_null(trans, -1);
	return_val_if_null(queuename, -1);
	

	if ( trans->state != AMQP_TRANSPORTER_NEED_CREDS && trans->state != AMQP_TRANSPORTER_DISCONNECTED ){
		fputs("Current state does not allow adding queue\n", stderr);
		return -1;
	}
		
	ret = cpl_AMQP_add_queue(trans->client.producer, queuename);
	if ( ret < 0 ){
		fputs("Failed to add publication queue\n", stderr);
		return ret;
	}
	return 0;
}

int AMQP_transporter_add_sub_queue(AMQP_transporter_t * const trans, const char * queuename)
{
	int ret;
	return_val_if_null(trans, -1);
	return_val_if_null(queuename, -1);
	

	if ( trans->state != AMQP_TRANSPORTER_NEED_CREDS && trans->state != AMQP_TRANSPORTER_DISCONNECTED ){
		fputs("Current state does not allow adding queue\n", stderr);
		return -1;
	}

	ret = cpl_AMQP_add_queue(trans->client.consumer, queuename);
	if ( ret < 0 ){
		fputs("Failed to add subscription queue\n", stderr);
		return ret;
	}
	return 0;
}

int AMQP_transporter_send(AMQP_transporter_t * const trans, const void *buffer, size_t len)
{
	int ret;
	return_val_if_null(trans, -1);
	return_val_if_null(buffer, -1);
	
	
	if ( trans->state != AMQP_TRANSPORTER_CONNECTED ){
		fputs("Transporter is not connected, sending is not allowed\n", stderr);
		return -1;
	}
	
	ret = cpl_AMQP_producer_send_msg(trans->client.producer, buffer, len);
	if ( ret < 0 ){
		fputs("Failed to send\n", stderr);
		return ret;
	}
	return ret;
}


#define JOIN_TIMEOUT 0.2f
static void *check_python_threads(void *data)
{
	AMQP_transporter_t *trans;

	int prod_alive, cons_alive;
	
	trans = (AMQP_transporter_t *) data;
	prod_alive = cons_alive = 1;
	
	while ( prod_alive || cons_alive ){
		if ( prod_alive ){
			cpl_AMQP_join(trans->client.producer, JOIN_TIMEOUT);
			prod_alive = cpl_AMQP_is_alive(trans->client.producer);
		}
		if ( cons_alive ){
			cpl_AMQP_join(trans->client.consumer, JOIN_TIMEOUT);
			prod_alive = cpl_AMQP_is_alive(trans->client.consumer);
		}	
	}
	pthread_exit((void *) 0);
}

int AMQP_transporter_connect(AMQP_transporter_t * const trans)
{
	int ret;

	return_val_if_null(trans, -1);
	
	
	if ( trans->state == AMQP_TRANSPORTER_CONNECTED ){
		fputs("Already connected\n", stderr);
		return 0;
	}
	if ( trans->state != AMQP_TRANSPORTER_DISCONNECTED ){
		fputs("Transporter not ready for connection\n", stderr);
		return -1;
	}

	ret = cpl_AMQP_start(trans->client.producer);
	if ( ret < 0 )
		fputs("Failed to start producer\n", stderr);
	ret = cpl_AMQP_start(trans->client.consumer);
	if ( ret < 0 )
		fputs("Failed to start consumer\n", stderr);
	
	trans->state = AMQP_TRANSPORTER_CONNECTED;
	
	ret = pthread_create(&trans->thread, NULL, check_python_threads, (void *) trans);
	return ret;		
}

int AMQP_transporter_disconnect(AMQP_transporter_t * const trans)
{
	int ret;

	if ( trans->state == AMQP_TRANSPORTER_DISCONNECTED ){
		fputs("Already disconnected\n", stderr);
		return 0;
	}
	if ( trans->state != AMQP_TRANSPORTER_CONNECTED ){
		fputs("Transporter is neither connected nor ready to connect\n", stderr);
		return -1;
	}
	
	ret = cpl_AMQP_stop(trans->client.producer);
	if ( ret < 0 )
		fputs("Failed to stop producer\n", stderr);
	ret = cpl_AMQP_stop(trans->client.consumer);
	if ( ret < 0 )
		fputs("Failed to stop consumer\n", stderr);
	
	trans->state = AMQP_TRANSPORTER_DISCONNECTED;

	return 0;
}

int AMQP_transporter_destroy(AMQP_transporter_t **trans)
{
	return_val_if_null(trans, 0);
	return_val_if_null(*trans, 0);
	
	if ( (*trans)->state == AMQP_TRANSPORTER_CONNECTED ){
		fputs("Transporter is still connected\n", stderr);
		return -1;
	}

	if ( (*trans)->address )
		free((*trans)->address);
	
	cpl_finalize();
	free(*trans);
	*trans = NULL;

	return 0;	
}

