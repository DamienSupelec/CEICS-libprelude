#ifndef AMQP_TRANS_H
#define AMQP_TRANS_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct AMQP_transporter AMQP_transporter_t;

int AMQP_transporter_new(AMQP_transporter_t **newtrans, int * const rfd, const char *address, const unsigned int port);

int AMQP_transporter_set_pkicredentials(AMQP_transporter_t * const trans, const char *pubcert_filename, const char *privkey_filename, const char *cacert_filename);

int AMQP_transporter_add_pub_queue(AMQP_transporter_t * const trans, const char *queuename);

int AMQP_transporter_add_sub_queue(AMQP_transporter_t * const trans, const char *queuename);

int AMQP_transporter_send(AMQP_transporter_t * const trans, const void *buffer, size_t len);

int AMQP_transporter_connect(AMQP_transporter_t * const trans);

int AMQP_transporter_disconnect(AMQP_transporter_t * const trans);

int AMQP_transporter_destroy(AMQP_transporter_t **trans);


#ifdef __cplusplus
}
#endif

#endif

