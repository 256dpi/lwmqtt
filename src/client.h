#ifndef LWMQTT_CLIENT_H
#define LWMQTT_CLIENT_H

#include "helpers.h"
#include "packet.h"

/**
 * The message structure used to publish and receive messages.
 */
typedef struct {
  lwmqtt_qos_t qos;
  bool retained;
  void *payload;
  int payload_len;
} lwmqtt_message_t;

/**
 * The initializer for messages structures.
 */
#define lwmqtt_default_message \
  { LWMQTT_QOS0, false, NULL, 0 }

/**
 * Forward declaration of the MQTT client object.
 */
typedef struct lwmqtt_client_t lwmqtt_client_t;

/**
 * The callback used to read from a network object. It may set read to zero if no data is available.
 *
 * Note: The callback is expected to read the exact amount of bytes requested.
 */
typedef lwmqtt_err_t (*lwmqtt_network_read_t)(lwmqtt_client_t *c, void *ref, unsigned char *buf, int len, int *read,
                                              int timeout);

/**
 * The callback used to write to a network object.
 *
 * Note: The callback is expected to write the exact amount of bytes requested.
 */
typedef lwmqtt_err_t (*lwmqtt_network_write_t)(lwmqtt_client_t *c, void *ref, unsigned char *buf, int len, int *sent,
                                               int timeout);

/**
 * The callback used to set a timer.
 */
typedef void (*lwmqtt_timer_set_t)(lwmqtt_client_t *c, void *ref, unsigned int timeout);

/**
 * The callback used to get a timers value.
 */
typedef int (*lwmqtt_timer_get_t)(lwmqtt_client_t *c, void *ref);

/**
 * The callback used to forward incoming messages.
 */
typedef void (*lwmqtt_callback_t)(lwmqtt_client_t *, lwmqtt_string_t *, lwmqtt_message_t *);

/**
 * The MQTT client object.
 */
struct lwmqtt_client_t {
  unsigned short next_packet_id;
  unsigned int keep_alive_interval;
  bool ping_outstanding;
  bool is_connected;

  int write_buf_size, read_buf_size;
  unsigned char *write_buf, *read_buf;

  lwmqtt_callback_t callback;

  void *network_ref;
  lwmqtt_network_read_t network_read;
  lwmqtt_network_write_t network_write;

  void *timer_keep_alive_ref;
  void *timer_network_ref;
  lwmqtt_timer_set_t timer_set;
  lwmqtt_timer_get_t timer_get;
};

/**
 * Will initialize the specified client object.
 *
 * @param client - The client object.
 * @param write_buf
 * @param write_buf_size
 * @param read_buf
 * @param read_buf_size
 */
void lwmqtt_init(lwmqtt_client_t *client, unsigned char *write_buf, int write_buf_size, unsigned char *read_buf,
                 int read_buf_size);

/**
 * Will set the network reference and callbacks for this client object.
 *
 * @param client - The client object.
 * @param ref - The reference to the network object.
 * @param read The read callback.
 * @param write The write callback.
 */
void lwmqtt_set_network(lwmqtt_client_t *client, void *ref, lwmqtt_network_read_t read, lwmqtt_network_write_t write);

/**
 * Will set the timer references and callbacks for this client objects.
 *
 * @param client - The client object.
 * @param keep_alive_ref - The reference to the keep alive timer.
 * @param network_ref - The reference to the network timer.
 * @param set - The set callback.
 * @param get - The get callback.
 */
void lwmqtt_set_timers(lwmqtt_client_t *client, void *keep_alive_ref, void *network_ref, lwmqtt_timer_set_t set,
                       lwmqtt_timer_get_t get);

/**
 * Will set the callback used to receive incoming messages.
 *
 * @param client - The client object.
 * @param cb - The callback to be called.
 */
void lwmqtt_set_callback(lwmqtt_client_t *client, lwmqtt_callback_t cb);

/**
 * Will send a connect packet and wait for a connack response and set the return code.
 *
 * Note: The network object must already be connected to the server. An error is returned if the broker rejects the
 * connection.
 *
 * @param client - The client object.
 * @param options - The options structure.
 * @param will - The will structure.
 * @param timeout - The command timeout.
 * @return An error value.
 */
lwmqtt_err_t lwmqtt_connect(lwmqtt_client_t *client, lwmqtt_options_t *options, lwmqtt_will_t *will,
                            lwmqtt_return_code_t *return_code, unsigned int timeout);

/**
 * Will send a publish packet and wait for all acks to complete.
 *
 * @param client - The client object.
 * @param topic - The topic.
 * @param message - The message.
 * @param timeout - The command timeout.
 * @return An error value.
 */
lwmqtt_err_t lwmqtt_publish(lwmqtt_client_t *client, const char *topic, lwmqtt_message_t *msg, unsigned int timeout);

/**
 * Will send a subscribe packet with a single topic filter - qos level pair and wait for the suback to complete.
 *
 * @param client - The client object.
 * @param topic_filter - The topic filter.
 * @param qos - The QoS level.
 * @param timeout - The command timeout.
 * @return An error value.
 */
lwmqtt_err_t lwmqtt_subscribe(lwmqtt_client_t *client, const char *topic_filter, lwmqtt_qos_t qos,
                              unsigned int timeout);

/**
 * Will send an unsubscribe packet and wait for the unsuback to complete.
 *
 * @param client - The client object.
 * @param topic_filter - The topic filter.
 * @param timeout - The command timeout.
 * @return An error value.
 */
lwmqtt_err_t lwmqtt_unsubscribe(lwmqtt_client_t *client, const char *topic_filter, unsigned int timeout);

/**
 * Will send a disconnect packet and finish the client.
 *
 * @param client - The client object.
 * @param timeout - The command timeout.
 * @return An error value.
 */
lwmqtt_err_t lwmqtt_disconnect(lwmqtt_client_t *client, unsigned int timeout);

/**
 * Will yield control to the client and read from the network and keep the connection alive.
 *
 * @param client - The client object.
 * @param timeout - The command timeout.
 * @return An error value.
 */
lwmqtt_err_t lwmqtt_yield(lwmqtt_client_t *client, unsigned int timeout);

#endif  // LWMQTT_CLIENT_H
