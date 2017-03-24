#ifndef LWMQTT_CLIENT_H
#define LWMQTT_CLIENT_H

#include "helpers.h"
#include "packet.h"

typedef struct {
  lwmqtt_qos_t qos;
  bool retained;
  bool dup;
  unsigned short id;
  void *payload;
  int payload_len;
} lwmqtt_message_t;

#define lwmqtt_default_message \
  { LWMQTT_QOS0, 0, 0, 0, NULL, 0 }

typedef struct lwmqtt_client_t lwmqtt_client_t;

typedef lwmqtt_err_t (*lwmqtt_network_read_t)(lwmqtt_client_t *c, void *ref, unsigned char *buf, int len, int *read,
                                              int timeout);
typedef lwmqtt_err_t (*lwmqtt_network_write_t)(lwmqtt_client_t *c, void *ref, unsigned char *buf, int len, int *sent,
                                               int timeout);

typedef void (*lwmqtt_timer_set_t)(lwmqtt_client_t *c, void *ref, unsigned int timeout);
typedef int (*lwmqtt_timer_get_t)(lwmqtt_client_t *c, void *ref);

typedef void (*lwmqtt_callback_t)(lwmqtt_client_t *, lwmqtt_string_t *, lwmqtt_message_t *);

struct lwmqtt_client_t {
  unsigned short next_packet_id;
  unsigned int command_timeout;
  int write_buf_size, read_buf_size;
  unsigned char *write_buf, *read_buf;
  unsigned int keep_alive_interval;
  char ping_outstanding;
  int is_connected;

  lwmqtt_callback_t callback;

  void *network_ref;
  lwmqtt_network_read_t network_read;
  lwmqtt_network_write_t networked_write;

  void *timer_keep_alive_ref;
  void *timer_network_ref;
  lwmqtt_timer_set_t timer_set;
  lwmqtt_timer_get_t timer_get;
};

#define lwmqtt_default_client \
  { 0, 0, 0, 0, NULL, NULL, 0, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }

/**
 * Create an MQTT client object.
 *
 * @param client
 * @param command_timeout
 * @param write_buf
 * @param write_buf_size
 * @param read_buf
 * @param read_buf_size
 */
void lwmqtt_init(lwmqtt_client_t *c, unsigned int command_timeout, unsigned char *write_buf, int write_buf_size,
                 unsigned char *read_buf, int read_buf_size);

void lwmqtt_set_network(lwmqtt_client_t *c, void *ref, lwmqtt_network_read_t read, lwmqtt_network_write_t write);

void lwmqtt_set_timers(lwmqtt_client_t *c, void *keep_alive_ref, void *network_ref, lwmqtt_timer_set_t set,
                       lwmqtt_timer_get_t get);

void lwmqtt_set_callback(lwmqtt_client_t *c, lwmqtt_callback_t cb);

/**
 * MQTT Connect - send an MQTT connect packet down the network and wait for a Connack
 *  The network object must be connected to the network endpoint before calling this
 *  @param options - connect options
 *  @param will - the will message
 *  @return success code
 */
lwmqtt_err_t lwmqtt_connect(lwmqtt_client_t *c, lwmqtt_options_t *options, lwmqtt_will_t *will,
                            lwmqtt_connack_t *connack);

/**
 * MQTT Publish - send an MQTT publish packet and wait for all acks to complete for all QoSs
 *  @param client - the client object to use
 *  @param topic - the topic to publish to
 *  @param message - the message to send
 *  @return success code
 */
lwmqtt_err_t lwmqtt_publish(lwmqtt_client_t *c, const char *topic, lwmqtt_message_t *msg);

/**
 * MQTT Subscribe - send an MQTT subscribe packet and wait for suback before returning.
 *
 * @param c - the client object to use
 * @param topic_filter  - the topic filter to subscribe to
 * @param qos
 * @return
 */
lwmqtt_err_t lwmqtt_subscribe(lwmqtt_client_t *c, const char *topic_filter, lwmqtt_qos_t qos);

/**
 * MQTT Subscribe - send an MQTT unsubscribe packet and wait for unsuback before returning.
 *  @param client - the client object to use
 *  @param topic - the topic filter to unsubscribe from
 *  @return success code
 */
lwmqtt_err_t lwmqtt_unsubscribe(lwmqtt_client_t *c, const char *topic);

/**
 * MQTT Disconnect - send an MQTT disconnect packet and close the connection
 *  @param client - the client object to use
 *  @return success code
 */
lwmqtt_err_t lwmqtt_disconnect(lwmqtt_client_t *c);

/**
 * MQTT Yield - MQTT background
 *  @param client - the client object to use
 *  @param time - the time, in milliseconds, to yield for
 *  @return success code
 */
lwmqtt_err_t lwmqtt_yield(lwmqtt_client_t *c, unsigned int timeout);

#endif  // LWMQTT_CLIENT_H
