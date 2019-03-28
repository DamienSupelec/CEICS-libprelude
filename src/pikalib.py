import pika
import ssl
import os
import base64
import threading

import time

class AMQPClient(threading.Thread):
    exchange = "direct_prelude"
    exchange_type = "direct"
    CHECK_FOR_STOP_INTERVAL = 2

    def __init__(self, address, port):
        threading.Thread.__init__(self)
        self._connection = None
        self._channel = None
        self._closing = False
        self._consumer_tag = None
        self._address = address
        self._port = port
        self.queues = []
        self.queues_index = 0
        self.mutex_stop = threading.Lock()
        self.has_to_stop = False
        self.sem_terminated = threading.Semaphore(0)

    def set_pkicredentials(self, pubcert, privkey, cacert):
        self._conn_params = pika.ConnectionParameters(self._address, self._port, '/', 
                                                      ssl = True, ssl_options = dict(
                                                      ca_certs = cacert,
                                                      cert_reqs = ssl.CERT_REQUIRED,
                                                      keyfile = privkey,
                                                      certfile = pubcert,
                                                      ssl_version = ssl.PROTOCOL_TLSv1))

    def set_exchange(self, exchange):
        self.exchange = exchange

    def add_queue(self, queue):
        self.queues.append(queue)

    def connect(self):
        return pika.SelectConnection(self._conn_params,
                                     self.on_connection_open,
                                     stop_ioloop_on_close=False)

    def on_connection_open(self, unused_connection):
        self._connection.add_on_close_callback(self.on_connection_closed)
        self.open_channel()

    def on_connection_closed(self, connection, reply_code, reply_text):
        self._channel = None
        if self._closing:
            self._connection.ioloop.stop()
            self.sem_terminated.release();
        else:
            self._connection.add_timeout(5, self.reconnect)

    def reconnect(self):
        self._connection.ioloop.stop()
        if not self._closing:
            self._connection = self.connect()
            self._connection.ioloop.start()

    def open_channel(self):
        self._connection.channel(on_open_callback=self.on_channel_open)

    def on_channel_open(self, channel):
        self._channel = channel
        self._channel.add_on_close_callback(self.on_channel_closed)
        self.setup_exchange()

    def on_channel_closed(self, channel, reply_code, reply_text):
        self._connection.close()

    def setup_exchange(self):
        self._channel.exchange_declare(self.on_exchange_declareok,
                                       exchange=self.exchange,
                                       exchange_type=self.exchange_type)    

    def on_exchange_declareok(self, unused_frame):
        self.start_working()

    def start_working_self(self):
        return

    def stop_working_self(self):
        return

    def check_for_stop(self):
        self.mutex_stop.acquire()
        if self.has_to_stop :
            self.mutex_stop.release()
            self.stop()
        else:
            self.mutex_stop.release()            
            self._connection.add_timeout(self.CHECK_FOR_STOP_INTERVAL, self.check_for_stop)
    
    def close_channel(self):
        self._channel.close()

    def request_stop(self):
        if self.queues :
            self.mutex_stop.acquire()
            self.has_to_stop = True
            self.mutex_stop.release()
            self.sem_terminated.acquire()

    def stop(self):
        self._closing = True
        self.stop_working()
        self._connection.ioloop.start()

    def run(self):
        if self.queues:
            self._connection = self.connect()
            self._connection.ioloop.start()


class AMQPProducer(AMQPClient):
    FLUSH_INTERVAL = 1

    def __init__(self, address, port):
        AMQPClient.__init__(self, address, port)
        self.msgs = []
        self.mutex_msgs = threading.Lock()

    def send_msg(self, msg):
        b64_msg = base64.standard_b64encode(msg)
        self.mutex_msgs.acquire()
        self.msgs.append(b64_msg)
        self.mutex_msgs.release()

    def flush_msgs_loop(self):
        self.flush_msgs()
        if not self._closing:
            self._connection.add_timeout(self.FLUSH_INTERVAL, self.flush_msgs_loop)

    def flush_msgs(self):
        self.mutex_msgs.acquire()
        for msg in self.msgs:
            for j in range(0, len(self.queues)): 
                #print("Publishing msg %s ! exchange : %s queue %s", msg, self.exchange, self.queues[j])          
                self._channel.basic_publish(exchange=self.exchange, routing_key=self.queues[j], body=msg)
        self.msgs = []
        self.mutex_msgs.release()

    def start_working(self):
        self._connection.add_timeout(self.CHECK_FOR_STOP_INTERVAL, self.check_for_stop)
        self._connection.add_timeout(self.FLUSH_INTERVAL, self.flush_msgs_loop)

    def stop_working(self):
        if self._channel is not None:
            self.flush_msgs()
            self.close_channel()

class AMQPConsumer(AMQPClient):
    def __init__(self, address, port):
        AMQPClient.__init__(self, address, port)
        self.rfd, self.wfd = os.pipe()
        self.mutex_w_pipe = threading.Lock()

    def setup_queues(self):
        self.queues_len = len(self.queues)
        self.queues_index = 0
        for i in range(0, self.queues_len):
            self._channel.queue_declare(self.on_queue_declareok, self.queues[i])

    def get_rfd(self):
        return self.rfd

    def on_queue_declareok(self, method_frame):        
        self._channel.queue_bind(self.on_bindok, self.queues[self.queues_index],
                                 self.exchange, self.queues[self.queues_index]) #HERE ?
        self.queues_index += 1
        if self.queues_index == self.queues_len:
            self.queues_index = 0

    def on_bindok(self, unused_frame):    
        self.queues_index += 1
        if self.queues_index == self.queues_len:
            self.queues_index = 0
            self.start_consuming()

    def on_consumer_cancelled(self, method_frame):
        if self._channel:
            self._channel.close()

    def on_message(self, unused_channel, basic_deliver, properties, b64body):
        self.acknowledge_message(basic_deliver.delivery_tag)
        body = base64.standard_b64decode(b64body)
        self.mutex_w_pipe.acquire()
        os.write(self.wfd, body)
        self.mutex_w_pipe.release()

    def acknowledge_message(self, delivery_tag):
        self._channel.basic_ack(delivery_tag)

    def start_consuming(self):
        self._channel.add_on_cancel_callback(self.on_consumer_cancelled)
        for i in range(0, self.queues_len):
            self._consumer_tag = self._channel.basic_consume(self.on_message,
                                                         self.queues[i])
    def on_cancelok(self, unused_frame):
        os.close(self.rfd)
        self.close_channel()

    def start_working(self):
        self.setup_queues()
        self._connection.add_timeout(self.CHECK_FOR_STOP_INTERVAL, self.check_for_stop)

    def stop_working(self):
        if self._channel:
            self._channel.basic_cancel(self.on_cancelok, self._consumer_tag)

