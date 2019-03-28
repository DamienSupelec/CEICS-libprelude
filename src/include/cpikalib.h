#ifndef CPIKALIB_H
#define CPIKALIB_H

#include <python3.5m/Python.h>

#ifdef __cplusplus
extern "C" {
#endif

int cpl_init(PyObject **Module);

int cpl_finalize(void);

int cpl_AMQP_producer_new(PyObject **pProducer, const char *address, const unsigned int port, PyObject *pModule);

int cpl_AMQP_consumer_new(PyObject **pConsumer, const char *address, const unsigned int port, PyObject *pModule);

int cpl_AMQP_set_pkicredentials(PyObject *pAgent, const char *pubcert, const char *privkey, const char *cacert);

int cpl_AMQP_add_queue(PyObject *pAgent, const char *queue);

int cpl_AMQP_consumer_get_rfd(PyObject *pConsumer, int *rfd);

int cpl_AMQP_set_exchange(PyObject *pAgent, const char *exchange);

int cpl_AMQP_producer_send_msg(PyObject *pProducer, const void *buffer, const size_t len);

int cpl_AMQP_start(PyObject *pAgent);

int cpl_AMQP_stop(PyObject *pAgent);

int cpl_AMQP_is_alive(PyObject *pAgent);

int cpl_AMQP_join(PyObject *pAgent, float timeout_sec);

void cpl_destroy(PyObject *obj);

#ifdef __cplusplus
}
#endif

#endif

