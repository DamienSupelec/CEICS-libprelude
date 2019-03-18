#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "MQTTAsync.h"
#include "mqtt-trans.h"

#define DEFAULT_CLIENTID "mqtt-transporter"
#define RAND_ID_LEN 6

#define DEFAULT_USERNAME "guest"
#define DEFAULT_PASSWORD "guest"
#define DEFAULT_PRIVATE_KEY_PASSWORD ""

#define DEFAULT_KEEPALIVE_INTERVAL 20
#define DEFAULT_TIMEOUT 10000
#define DEFAULT_QOS 1
#define DEFAULT_CLEANSESSION 0
#define DEFAULT_RETAINED 0

#define DEFAULT_RAND_SOURCE "/dev/urandom"

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

/* String list, used to hold topics */
typedef struct str_list{
	struct str_list *next;
	char *str;
} str_list_t;

/* Creates a node containing the string str
 * Write the node in *new 
 * Returns 0 on success, -1 on failure
 * NB : data from str is being duplicated
 */
static int str_list_new(str_list_t **new, const char *str)
{
	str_list_t *strl;
	strl = calloc(1, sizeof(*strl));
	if ( ! strl )
		return -1;
	strl->next = NULL;
	strl->str = strdup(str);
	*new = strl;
	return 0;
}

/* Creates a node containing the string str
 * Prepend it to the list currently held by *list
 * Write the resulting list in *list
 * Returns 0 on success, -1 on failure
 * NB : data from str is being duplicated
 */ 
static int str_list_prepend(str_list_t **list, const char *str)
{
	str_list_t *head;
	if ( str_list_new(&head, str) < 0 )
		return -1;
	head->next = *list;
	*list = head;
	return 0;
}

/* Destroys the string list held in *list
 * Afterhand, *list is set to NULL
 */
static void str_list_destroy(str_list_t **list)
{
	str_list_t *oldnode;
	while ( *list ){
		oldnode = *list;
		*list = (*list)->next;
		free(oldnode->str);
		free(oldnode);
	}
}

/* Seeds the PRNG rand() once using a random seed
 * read from DEFAULT_RAND_SOURCE
 * Returns 0 on success, -1 on failure
 */
static int seed_rand_once(void)
{
	union seed{
		unsigned int seed;
		unsigned char seedbytes[sizeof(unsigned int)];
	};
	static int initialized = 0;
	static union seed randseed;
	int fd, count, toread;
	
	if ( initialized )
		return 0;
	
	fd = open(DEFAULT_RAND_SOURCE, O_RDONLY);
	if ( fd < 0 ){
		fputs("Failed to access " DEFAULT_RAND_SOURCE "\n", stderr);
		return -1;
	}
	count = 0;
	toread = sizeof(unsigned int);
	
	do{
		count = read(fd, randseed.seedbytes + count, toread - count);
	} while ( count < toread );
	
	srand(randseed.seed);
	initialized = 1;
	return 0;
}

/* Charset used for generating random client ID */
static const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/* Generates a new random client id
 * and store it into *new
 * Returns 0 on success, -1 on failure
 */ 
static int new_randomid(char **new)
{
	char *id;
	int size, i;
	char randid[RAND_ID_LEN+1];

	return_val_if_null(new, -1);

	seed_rand_once();

	for ( i = 0; i < RAND_ID_LEN; ++i )
		randid[i] = charset[rand()%(sizeof(charset)/sizeof(charset[0]))];
	randid[RAND_ID_LEN] = '\0';

	id = NULL;
	size = snprintf(id, 0, "%s_%s", DEFAULT_CLIENTID, randid);
	id = malloc((size+1) * sizeof(*id));
	if ( ! id )
		return -1;
	snprintf(id, size+1, "%s_%s", DEFAULT_CLIENTID, randid);

	*new = id;
	return 0;	
}

typedef enum { MQTT_TRANSPORTER_NEED_CREDS, MQTT_TRANSPORTER_CONNECTED, MQTT_TRANSPORTER_DISCONNECTED } MQTT_transporter_state;

struct MQTT_transporter {
	MQTTAsync client;
	MQTTAsync_connectOptions conn_opts;
	MQTT_transporter_state state;
	MQTTAsync_SSLOptions ssl_opts;
	int qos;
	char *address;
	char *username;
	char *password;
	char *clientid;
	str_list_t *pubtopics;
	str_list_t *subtopics;
	int wfd;
	struct {
		int wait:1;
		int success:1;
	} lock;
};

#define prepare_sleep(trans) do{ (trans)->lock.wait=1; (trans)->lock.success=0;} while(0)
#define operation_success(trans) do{ (trans)->lock.wait=0; (trans)->lock.success=1;} while(0)
#define operation_failure(trans) do{ (trans)->lock.wait=0; (trans)->lock.success=0;} while(0)
#define operation_is_successful(trans)  ((trans)->lock.success)
#define sleep_till_completion(trans) do{\
                                     	while ( (trans)->lock.wait ) usleep(10000);\
                                     }while(0)

/* Creates a new MQTT_transport_t object into *new
 * rfd is a pointer to an integer which will hold the
 * file descriptor from which message will be available for reading
 * address contains the hostname or IP addr of the MQTT server
 * port contains the port on which the MQTT server is listening for SSL connections
 * NB : address data is being duplicated
 * Returns 0 on success, a negative value on failure
 */
int MQTT_transporter_new(MQTT_transporter_t **new, int * const rfd, const char *address, const unsigned int port)
{
	MQTT_transporter_t *newtrans;
	int size, ret, fdpipe[2];

	return_val_if_null(new, -1);
	return_val_if_null(rfd, -1);
	return_val_if_null(address, -1);

	newtrans = calloc(1, sizeof(*newtrans));
	if ( ! newtrans )
		return -1;

	ret = pipe(fdpipe);
	if (  ret < 0 ){
		fprintf(stderr, "failed to create a pipe : %s\n", strerror(errno));
		free(newtrans);
		return ret;
	}
	ret = fcntl(fdpipe[0], F_SETFL, (fcntl(fdpipe[0], F_GETFL) | O_NONBLOCK));
	if ( ret < 0 ){
		perror("fcntl failed while making read-end pipe non blocking: ");
		free(newtrans);
		return ret;
	}

	size = snprintf(newtrans->address, 0, "ssl://%s:%u", address, port);
	newtrans->address = malloc(sizeof(*newtrans->address) * (size + 1));
	if ( ! newtrans->address ){
		free(newtrans);
		return -1;
	}
	snprintf(newtrans->address, size+1, "ssl://%s:%u", address, port);
	
	newtrans->qos = DEFAULT_QOS;
	new_randomid(&newtrans->clientid);
	newtrans->pubtopics = NULL;
	newtrans->subtopics = NULL;
	
	ret = MQTTAsync_create(&newtrans->client, newtrans->address, newtrans->clientid, MQTTCLIENT_PERSISTENCE_NONE, NULL);
	if ( ret != MQTTASYNC_SUCCESS ){
		fputs("failed to create mqtt transporter client\n", stderr);
		free(newtrans->address);
		free(newtrans->clientid);
		free(newtrans);
		return -1;
	}

	newtrans->conn_opts = (MQTTAsync_connectOptions) MQTTAsync_connectOptions_initializer;
	newtrans->ssl_opts = (MQTTAsync_SSLOptions) MQTTAsync_SSLOptions_initializer;

	newtrans->conn_opts.username = strdup(DEFAULT_USERNAME);
	newtrans->conn_opts.password = strdup(DEFAULT_PASSWORD);
	newtrans->conn_opts.cleansession = DEFAULT_CLEANSESSION;
	newtrans->conn_opts.keepAliveInterval = DEFAULT_KEEPALIVE_INTERVAL;
	newtrans->conn_opts.context = newtrans;

	newtrans->conn_opts.ssl = &newtrans->ssl_opts;

	newtrans->wfd = fdpipe[1];
	
	newtrans->state = MQTT_TRANSPORTER_NEED_CREDS;
	
	*rfd = fdpipe[0];
	*new = newtrans;
	return 0;	
}

/* Sets the PKI credentials required by the MQTT_transporter_t
 * *trans is the MQTT_transporter_t whose credentials are being set
 * pubcert_filename holds the path to the public certificate
 * privkey_filename holds the path to the private key
 * cacert_filename holds the path to the trusted CA certificate(s)
 * NB : data from pubcert_filename, privkey_filename, cacert_filename are being duplicated
 * Returns 0 on success, -1 on failure
 */
int MQTT_transporter_set_pkicredentials(MQTT_transporter_t * const trans, const char *pubcert_filename, const char *privkey_filename, const char *cacert_filename)
{
	return_val_if_null(trans, -1);
	return_val_if_null(pubcert_filename, -1);
	return_val_if_null(privkey_filename, -1);
	return_val_if_null(cacert_filename, -1);

	trans->ssl_opts.keyStore = strdup(pubcert_filename);
	trans->ssl_opts.privateKey = strdup(privkey_filename);
	trans->ssl_opts.privateKeyPassword = strdup(DEFAULT_PRIVATE_KEY_PASSWORD);
	trans->ssl_opts.trustStore = strdup(cacert_filename);
	trans->state = MQTT_TRANSPORTER_DISCONNECTED;
	
	return 0;
}

/* Sets the MQTT credentials used to connect to the sever
 * *trans is the MQTT_transporter_t whose credentials are being set
 * username holds the username to present to the server
 * password holds the passord to present to the server
 * NB : data from username and password are being duplicated
 * Returns 0 on success, -1 on failure
 */
int MQTT_transporter_set_credentials(MQTT_transporter_t * const trans, const char *username, const char *password)
{
	return_val_if_null(trans,-1);
	return_val_if_null(username,-1);
	return_val_if_null(password,-1);

	if (trans->username)
		free(trans->username);
	if (trans->password)
		free(trans->password);
	trans->username = strdup(username);
	trans->password = strdup(username);
	
	return 0;
}

/* Adds a topic to which *trans must publish each message
 * topicname holds the name of the topic *trans must publish
 * NB : data from topicname is being duplicated
 * Returns 0 on success, -1 on failure
 */ 
int MQTT_transporter_add_pub_topic(MQTT_transporter_t * const trans, const char * topicname)
{
	return_val_if_null(trans, -1);
	return_val_if_null(topicname, -1);

	if ( ! trans->pubtopics ){
		if ( str_list_new(&trans->pubtopics, topicname) < 0 ){
			fputs("failed to add topic\n", stderr);
			return -1;
		}
	}else{
		if ( str_list_prepend(&trans->pubtopics, topicname) < 0){
			fputs("failed to add topic\n", stderr);
			return -1;
		}
	}
	return 0;
}

/* Adds a topic to which *trans must subscribe
 * topicname holds the name of the topic *trans must subscribe 
 * NB : data from topicname is being duplicated
 * Returns 0 on success, -1 on failure
 */ 
int MQTT_transporter_add_sub_topic(MQTT_transporter_t * const trans, const char * topicname)
{
	return_val_if_null(trans, -1);
	return_val_if_null(topicname, -1);

	if ( ! trans->subtopics ){
		if ( str_list_new(&trans->subtopics, topicname) < 0 ){
			fputs("failed to add topic\n", stderr);
			return -1;
		}
	}else{
		if ( str_list_prepend(&trans->subtopics, topicname) < 0){
			fputs("failed to add topic\n", stderr);
			return -1;
		}
	}
	return 0;
}

/* Callback to be called when connection with
 * the MQTT server has been lost.
 * Tries to restablish connection
 */
static void on_conn_lost(void *context, char *cause)
{
	MQTT_transporter_t *trans;
	trans = (MQTT_transporter_t *) context;
	
	trans->state = MQTT_TRANSPORTER_DISCONNECTED;
	fprintf(stderr, "Connection lost (%s)\n", cause);
	fputs("Trying to reconnect\n", stderr);
	if ( MQTT_transporter_connect(trans) < 0 ) 
		fputs("Failed to reconnect\n", stderr);
	else{
		trans->state = MQTT_TRANSPORTER_CONNECTED;
		fputs("Reconnected !\n", stderr);	
	}
}

/* Callback to be called when message arrives
 * Writes the data into a pipe associated with
 * the MQTT_transporter_t who recieves the message,
 * in order to make them available for read
 * Returns 1 to indicate that message processing
 * is a success
 */ 
static int on_msg_arrived(void *context, char *topicname, int topiclen, MQTTAsync_message *message)
{
	ssize_t written;
	MQTT_transporter_t *trans;
	trans = (MQTT_transporter_t *) context;
	
	written = 0;
	do{
		written = write(trans->wfd, ((unsigned char *)message->payload) + written, message->payloadlen - written);
		if (written < 0)
			perror("write failed: ");
	} while (written < message->payloadlen); 

	MQTTAsync_freeMessage(&message);
	MQTTAsync_free(topicname);
	return 1;
}

/* Callback to be called when a message is successfully delivered
 */
static void on_delivery_success(void *context, MQTTAsync_token token)
{
	return;
}

/* Callback to be called when an asynchronous operation
 * is a success
 * Unlocks the application thread and notify the success
 */
static void on_success(void *context, MQTTAsync_successData *response)
{
	MQTT_transporter_t *t;
	
	t = (MQTT_transporter_t *) context;
	operation_success(t);	
}

/* Callback to be called when an asynchronous operation
 * has failed
 * Unlocks the application thread and notify the failure
 */
static void on_failure(void *context, MQTTAsync_failureData *response)
{
	MQTT_transporter_t *t;
	
	t = (MQTT_transporter_t *) context;
	operation_failure(t);	
}

/* Connects the MQTT_transporter_t *trans to the
 * address that was specified during its creation
 * Returns 0 on success, -1 on failure
 */ 
int MQTT_transporter_connect(MQTT_transporter_t * const trans)
{
	int rc;

	return_val_if_null(trans, -1);

	if ( trans->state == MQTT_TRANSPORTER_NEED_CREDS ){
		fputs("MQTT transporter has not be given credentials\n", stderr);
		return -1;
	}
	if ( trans->state == MQTT_TRANSPORTER_CONNECTED ){
		fputs("MQTT transporter already connected\n", stderr);
		return 0;
	}
	if ( trans->state == MQTT_TRANSPORTER_DISCONNECTED ){
		trans->conn_opts.onSuccess = on_success;
		trans->conn_opts.onFailure = on_failure;
		trans->conn_opts.context = trans;
		
		rc = MQTTAsync_setCallbacks(trans->client, trans, on_conn_lost, on_msg_arrived, on_delivery_success);
		if ( rc != MQTTASYNC_SUCCESS ){
			fputs("failed to set callbacks before connecting\n", stderr);
			return -1;
		}
		
		prepare_sleep(trans);
		rc = MQTTAsync_connect(trans->client, &trans->conn_opts);
		if ( rc != MQTTASYNC_SUCCESS ){
			fprintf(stderr,"failed to start connect, return code %d\n", rc);
			return -1;
		}	
		sleep_till_completion(trans);
		if ( ! operation_is_successful(trans) ){
			fputs("Connection has failed\n", stderr);
			return -1;
		}
			
		trans->state = MQTT_TRANSPORTER_CONNECTED;
		return 0;		

	}
	return -1;	
	
}

/* Disconnects the MQTT_transporter_t *trans
 * Returns 0 on success, -1 on failure 
 */
int MQTT_transporter_disconnect(MQTT_transporter_t * const trans)
{
	return_val_if_null(trans, -1);

	if ( trans->state != MQTT_TRANSPORTER_CONNECTED ){
		fputs("MQTT transporter not connected\n", stderr);
		return 0;
	}

	MQTTAsync_disconnectOptions disconn_opts = MQTTAsync_disconnectOptions_initializer;
	disconn_opts.timeout = DEFAULT_TIMEOUT;
	disconn_opts.onFailure = on_failure;
	disconn_opts.onSuccess = on_success;
	disconn_opts.context = trans;
	
	prepare_sleep(trans);
	if (MQTTAsync_disconnect(trans->client, &disconn_opts) != MQTTASYNC_SUCCESS){
		fputs("Failed to start disconnect\n", stderr);
		return -1;
	}
	sleep_till_completion(trans);
	if ( ! operation_is_successful(trans) ){
		fputs("Disconnection failed\n", stderr);
		return -1;
	}

	trans->state = MQTT_TRANSPORTER_DISCONNECTED;
	return 0;
}

/* Sends len bytes from buffer to all the topics to
 * which *trans must publish
 * Returns len on success, -1 on failure 
 */
int MQTT_transporter_send(MQTT_transporter_t * const trans, const void *buffer, size_t len)
{
	int has_failed;
	str_list_t *topics;
	MQTTAsync_message msg = MQTTAsync_message_initializer;
	MQTTAsync_responseOptions opts = MQTTAsync_responseOptions_initializer;
	
	return_val_if_null(trans, -1);

	if ( trans->state != MQTT_TRANSPORTER_CONNECTED ){
		fputs("MQTT transporter not connected\n", stderr);
		return -1;
	}
	if ( ! trans->pubtopics ){
		fputs("MQTT transporter has no topics to publish to\n", stderr);
		return -1;
	}

	msg.payload = buffer;
	msg.payloadlen = len;
	msg.qos = trans->qos;
	msg.retained = DEFAULT_RETAINED;
	
	opts.context = trans;
	opts.onSuccess = on_success;
	opts.onFailure = on_failure;
	
	topics = trans->pubtopics;
	
	has_failed = 0;
	while ( topics ){ 
		prepare_sleep(trans);
		MQTTAsync_sendMessage(trans->client, topics->str, &msg, &opts);
		sleep_till_completion(trans);
		if ( ! operation_is_successful(trans) ){
			fprintf(stderr, "Send fail on topic \"%s\"\n", topics->str);
			has_failed = 1;
		}	
		topics = topics->next;
	}
	return has_failed ? -1 : len;
}

/* Make *trans subscribe to all the topics
 * it has been indicated to subscribe
 * Returns the number of topics it subscribed,
 * -1 on a failure 
 * NB : this means the function will return 0 if
 *      it could not subscribe to any topic
 */
int MQTT_transporter_subscribe(MQTT_transporter_t * const trans)
{
	int rc, count;
	str_list_t *topics;
	MQTTAsync_responseOptions opts = MQTTAsync_responseOptions_initializer;

	return_val_if_null(trans, -1);

	if ( trans->state != MQTT_TRANSPORTER_CONNECTED ){
		fputs("MQTT transporter not connected\n", stderr);
		return -1;
	}
	if ( ! trans->subtopics ){
		fputs("MQTT transporter has no topics to subscribe to\n", stderr);
		return -1;
	}
	
	opts.onSuccess = on_success;
	opts.onFailure = on_failure;	
	opts.context = trans;

	topics = trans->subtopics;
	count = 0;
	while ( topics ){
		prepare_sleep(trans);
		rc = MQTTAsync_subscribe(trans->client, topics->str, trans->qos, &opts);
		if ( rc != MQTTASYNC_SUCCESS )
			fprintf(stderr, "Failed to start subscribe to topic \"%s\", error code %d\n", topics->str, rc);
		sleep_till_completion(trans);
		if ( ! operation_is_successful(trans) ){
			fprintf(stderr, "Subscribe fail on topic \"%s\"\n", topics->str);
		}else
			++count;	
		topics = topics->next;
	}
	return count;
}

/* Destroys the MQTT_transporter **trans
 * All resources are freed
 * *trans is set to NULL
 */
void MQTT_transporter_destroy(MQTT_transporter_t **trans)
{
	return_if_null(trans);
	return_if_null(*trans);

	if ( (*trans)->client )
		MQTTAsync_destroy(&(*trans)->client);
	free((char *)(*trans)->ssl_opts.keyStore);
	free((char *)(*trans)->ssl_opts.privateKey);
	free((char *)(*trans)->ssl_opts.privateKeyPassword);
	free((char *)(*trans)->ssl_opts.trustStore);
	free((*trans)->address);
	free((*trans)->username);
	free((*trans)->password);
	free((*trans)->clientid);
	str_list_destroy(&(*trans)->pubtopics);
	str_list_destroy(&(*trans)->subtopics);
	close((*trans)->wfd);	
	free(*trans);
	*trans = NULL;
}

