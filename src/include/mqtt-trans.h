#ifndef MQTT_TRANS_H
#define MQTT_TRANS_H

#ifdef __cplusplus
 extern "C" {
#endif

typedef struct MQTT_transporter MQTT_transporter_t;

int MQTT_transporter_new(MQTT_transporter_t **newtrans, int * const rfd, const char *address, const unsigned int port);

int MQTT_transporter_set_pkicredentials(MQTT_transporter_t * const trans, const char *pubcert_filename, const char *privkey_filename, const char *cacert_filename);

int MQTT_transporter_set_credentials(MQTT_transporter_t * const trans, const char *username, const char *password);

int MQTT_transporter_add_pub_topic(MQTT_transporter_t * const trans, const char *topicname);

int MQTT_transporter_add_sub_topic(MQTT_transporter_t * const trans, const char *topicname);

int MQTT_transporter_connect(MQTT_transporter_t * const trans);

int MQTT_transporter_disconnect(MQTT_transporter_t * const trans);

int MQTT_transporter_send(MQTT_transporter_t * const trans, const void *buffer, size_t len);

int MQTT_transporter_subscribe(MQTT_transporter_t * const trans);

void MQTT_transporter_destroy(MQTT_transporter_t **trans);

#endif

#ifdef __cplusplus
 }
#endif

