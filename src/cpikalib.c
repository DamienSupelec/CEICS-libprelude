#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <python3.5m/Python.h>

#include "cpikalib.h"

#define PYTHONFILE "pikalib"
//#define PIKALIBDIR "/root/amqp-trans2"

#define AMQPPRODUCER "AMQPProducer"
#define AMQPCONSUMER "AMQPConsumer"
#define AMQPCLIENT_SET_PKICREDS "set_pkicredentials"
#define AMQPCLIENT_ADD_QUEUE "add_queue"
#define AMQPCONSUMER_GET_RFD "get_rfd"
#define AMQPCLIENT_SET_EXCHANGE "set_exchange"
#define AMQPPRODUCER_SEND_MSG "send_msg"
#define AMQPCLIENT_START "start"
#define AMQPCLIENT_REQUEST_STOP "request_stop"

#define return_val_if_null(obj, val) do{ if ( !obj ) return val; }while(0)

#define PYFUNC_DECL PyGILState_STATE gstate
#define PYFUNC_ENTER gstate = PyGILState_Ensure()
#define PYFUNC_LEAVE PyGILState_Release(gstate)


int cpl_init(PyObject **Module)
{
	PYFUNC_DECL;
	PyObject *pValue, *pModule;

	return_val_if_null(Module, -1);


	Py_Initialize();
	PyEval_InitThreads();
	PyEval_SaveThread();
	
	PYFUNC_ENTER;
	
	pValue = PyUnicode_FromString(PYTHONFILE);
	if ( !pValue ){
		Py_Finalize();
		return -1;
	}

	pModule = PyImport_Import(pValue);

	Py_DECREF(pValue);
	if ( !pModule ){
		fputs("Failed to import module\n", stderr);
		Py_Finalize();
		return -1;
	}

	PYFUNC_LEAVE;
	*Module = pModule;
	return 0;
}

int cpl_finalize(void)
{
	PYFUNC_DECL;
	PYFUNC_ENTER;
	
	Py_Finalize();

	return 0;
}

int cpl_AMQP_producer_new(PyObject **pProducer, const char *address, const unsigned int port, PyObject *pModule)
{
	PYFUNC_DECL;
	int ret;
	PyObject *pInstance, *pFunc, *pValue, *pArgs;
	
	return_val_if_null(pProducer, -1);
	return_val_if_null(address, -1);
	return_val_if_null(pModule, -1);

	PYFUNC_ENTER;

	pFunc = PyObject_GetAttrString(pModule, AMQPPRODUCER);
	if ( !pFunc ){
		PYFUNC_LEAVE;
		return -1;
	}
	if ( !PyCallable_Check(pFunc) ){
		Py_DECREF(pFunc);	
		PYFUNC_LEAVE;
		return -1;
	}

	pArgs = PyTuple_New(2);
	if ( !pArgs ){
		Py_DECREF(pFunc);
		PYFUNC_LEAVE;
		return -1;
	}
	
	pValue = PyUnicode_FromString(address);
	if ( !pValue ){
		Py_DECREF(pFunc);
		Py_DECREF(pArgs);
		PYFUNC_LEAVE;
		return -1;
	}

	ret = PyTuple_SetItem(pArgs, 0, pValue);
	if ( ret != 0 ){
		Py_DECREF(pFunc);
		Py_DECREF(pArgs);
		Py_DECREF(pValue);
		PYFUNC_LEAVE;
		return -1;
	}

	pValue = PyLong_FromLong(port);
	if ( !pValue ){
		Py_DECREF(pFunc);
		Py_DECREF(pArgs);
		PYFUNC_LEAVE;
		return -1;
	}

	ret = PyTuple_SetItem(pArgs, 1, pValue);
	if ( ret != 0 ){
		Py_DECREF(pFunc);
		Py_DECREF(pArgs);
		Py_DECREF(pValue);
		PYFUNC_LEAVE;
		return -1;
	}

	pInstance = PyObject_CallObject(pFunc, pArgs);
	if ( !pInstance ){
		PyErr_Print();
		Py_DECREF(pFunc);
		Py_DECREF(pArgs);
		PYFUNC_LEAVE;
		return -1;
	}else{
		*pProducer = pInstance;
		Py_DECREF(pFunc);
		Py_DECREF(pArgs);
		PYFUNC_LEAVE;
		return 0;
	}
}

int cpl_AMQP_consumer_new(PyObject **pConsumer, const char *address, const unsigned int port, PyObject *pModule)
{
	PYFUNC_DECL;
	int ret;
	PyObject *pInstance, *pFunc, *pValue, *pArgs;
	
	return_val_if_null(pConsumer, -1);
	return_val_if_null(address, -1);
	return_val_if_null(pModule, -1);

	PYFUNC_ENTER;

	pFunc = PyObject_GetAttrString(pModule, AMQPCONSUMER);
	if ( !pFunc ){
		PYFUNC_LEAVE;
		return -1;
	}
	if ( !PyCallable_Check(pFunc) ){
		Py_DECREF(pFunc);	
		PYFUNC_LEAVE;
		return -1;
	}

	pArgs = PyTuple_New(2);
	if ( !pArgs ){
		Py_DECREF(pFunc);
		PYFUNC_LEAVE;
		return -1;
	}
	
	pValue = PyUnicode_FromString(address);
	if ( !pValue ){
		Py_DECREF(pFunc);
		Py_DECREF(pArgs);
		PYFUNC_LEAVE;
		return -1;
	}

	ret = PyTuple_SetItem(pArgs, 0, pValue);
	if ( ret != 0 ){
		Py_DECREF(pFunc);
		Py_DECREF(pArgs);
		Py_DECREF(pValue);
		PYFUNC_LEAVE;
		return -1;
	}

	pValue = PyLong_FromLong(port);
	if ( !pValue ){
		Py_DECREF(pFunc);
		Py_DECREF(pArgs);
		PYFUNC_LEAVE;
		return -1;
	}

	ret = PyTuple_SetItem(pArgs, 1, pValue);
	if ( ret != 0 ){
		Py_DECREF(pFunc);
		Py_DECREF(pArgs);
		Py_DECREF(pValue);
		PYFUNC_LEAVE;
		return -1;
	}

	pInstance = PyObject_CallObject(pFunc, pArgs);
	if ( !pInstance ){
		PyErr_Print();
		Py_DECREF(pFunc);
		Py_DECREF(pArgs);
		PYFUNC_LEAVE;
		return -1;
	}else{
		*pConsumer = pInstance;
		Py_DECREF(pFunc);
		Py_DECREF(pArgs);
		PYFUNC_LEAVE;
		return 0;
	}
}

int cpl_AMQP_set_pkicredentials(PyObject *pAgent, const char *pubcert, const char *privkey, const char *cacert)
{
	PYFUNC_DECL;
	PyObject *pValue;

	return_val_if_null(pAgent, -1);
	return_val_if_null(pubcert, -1);
	return_val_if_null(privkey, -1);
	return_val_if_null(cacert, -1);

	PYFUNC_ENTER;
	
	pValue = PyObject_CallMethod(pAgent, AMQPCLIENT_SET_PKICREDS, "sss", pubcert, privkey, cacert);
	if ( !pValue ){
		PyErr_Print();
		PYFUNC_LEAVE;
		return -1;
	}else{
		Py_DECREF(pValue);
		PYFUNC_LEAVE;
		return 0;
	}
}

int cpl_AMQP_add_queue(PyObject *pAgent, const char *queue)
{
	PYFUNC_DECL;
	PyObject *pValue;
	
	return_val_if_null(pAgent, -1);
	return_val_if_null(queue, -1);
	
	PYFUNC_ENTER;

	pValue = PyObject_CallMethod(pAgent, AMQPCLIENT_ADD_QUEUE, "s", queue);
	if ( !pValue ){
		PyErr_Print();
		PYFUNC_LEAVE;
		return -1;
	}else{
		Py_DECREF(pValue);
		PYFUNC_LEAVE;
		return 0;
	}
}

int cpl_AMQP_consumer_get_rfd(PyObject *pConsumer, int *rfd)
{
	PYFUNC_DECL;
	PyObject *pValue;

	return_val_if_null(pConsumer, -1);
	return_val_if_null(rfd, -1);

	PYFUNC_ENTER;
	
	pValue = PyObject_CallMethod(pConsumer, AMQPCONSUMER_GET_RFD, NULL);
	if ( !pValue ){
		PyErr_Print();
		PYFUNC_LEAVE;
		return -1;
	}else if ( !PyLong_Check(pValue) ){
		fputs("Returned rfd is not a integer\n", stderr);
		Py_DECREF(pValue);
		PYFUNC_LEAVE;
		return -1;
	}else{
		*rfd = (int) PyLong_AsLong(pValue);
		Py_DECREF(pValue);
		PYFUNC_LEAVE;
		return 0;
	}
}

int cpl_AMQP_set_exchange(PyObject *pAgent, const char *exchange)
{
	PYFUNC_DECL;
	PyObject *pValue;

	return_val_if_null(pAgent, -1);
	return_val_if_null(exchange, -1);

	PYFUNC_ENTER;
	pValue = PyObject_CallMethod(pAgent, AMQPCLIENT_SET_EXCHANGE, "s", exchange);
	if ( !pValue ){
		PyErr_Print();
		PYFUNC_LEAVE;
		return -1;
	}else{
		Py_DECREF(pValue);
		PYFUNC_LEAVE;
		return 0;
	}
}

int cpl_AMQP_producer_send_msg(PyObject *pProducer, const void *buffer,  const size_t len)
{
	PYFUNC_DECL;
	PyObject *pValue;
	
	return_val_if_null(pProducer, -1);
	return_val_if_null(buffer, -1);

	if ( len == 0 )
		return 0;

	PYFUNC_ENTER;
	pValue = PyObject_CallMethod(pProducer, AMQPPRODUCER_SEND_MSG, "y#", (char *) buffer, len);
	if ( !pValue ){
		PyErr_Print();
		PYFUNC_LEAVE;
		return -1;
	}else{
		Py_DECREF(pValue);
		PYFUNC_LEAVE;
		return len;
	}
}

int cpl_AMQP_start(PyObject *pAgent)
{
	PYFUNC_DECL;
	PyObject *pValue;

	return_val_if_null(pAgent, -1);
	
	PYFUNC_ENTER;
	pValue = PyObject_CallMethod(pAgent, AMQPCLIENT_START, NULL);
	if ( !pValue ){
		PyErr_Print();
		PYFUNC_LEAVE;
		return -1;
	}else{
		Py_DECREF(pValue);
		PYFUNC_LEAVE;
		return 0;
	}	
}

int cpl_AMQP_stop(PyObject *pAgent)
{
	PYFUNC_DECL;
	PyObject *pValue;

	return_val_if_null(pAgent, -1);
	
	PYFUNC_ENTER;
	pValue = PyObject_CallMethod(pAgent, AMQPCLIENT_REQUEST_STOP, NULL);
	if ( !pValue ){
		PyErr_Print();
		PYFUNC_LEAVE;
		return -1;
	}else{
		Py_DECREF(pValue);
		PYFUNC_LEAVE;
		return 0;
	}	
}

int cpl_AMQP_is_alive(PyObject *pAgent)
{
	PYFUNC_DECL;
	PyObject *pValue;
	int ret;

	return_val_if_null(pAgent, 0);

	PYFUNC_ENTER;
	pValue = PyObject_CallMethod(pAgent, "isAlive", NULL);
	if ( !pValue ){
		PyErr_Print();
		PYFUNC_LEAVE;
		return -1;
	}else{
		ret = PyLong_AsLong(pValue);
		Py_DECREF(pValue);
		PYFUNC_LEAVE;
		return ret;
	}
}

int cpl_AMQP_join(PyObject *pAgent, float timeout_sec)
{
	PYFUNC_DECL;
	PyObject *pValue;

	return_val_if_null(pAgent, -1);
	
	PYFUNC_ENTER;
	pValue = PyObject_CallMethod(pAgent, "join", "f", timeout_sec);
	PYFUNC_LEAVE;
	return 0;
}

void cpl_destroy(PyObject *obj)
{
	PYFUNC_DECL;
	PYFUNC_ENTER;

	Py_XDECREF(obj);
	
	PYFUNC_LEAVE;
}


