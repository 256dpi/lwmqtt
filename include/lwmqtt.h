#ifndef LWMQTT_CLIENT_H
#define LWMQTT_CLIENT_H

#include <stdbool.h>

/**
 * The error type used by all exposed APIs.
 */
typedef enum {
    LWMQTT_SUCCESS = 0,
    LWMQTT_FAILURE = -1,
    LWMQTT_BUFFER_TOO_SHORT = -2,
    LWMQTT_REMAINING_LENGTH_OVERFLOW = -3,
    LWMQTT_LENGTH_MISMATCH = -4,
    LWMQTT_NOT_ENOUGH_DATA = -5
} lwmqtt_err_t;

/**
 * A multi value string. Can be either a c string or a length prefixed string.
 */
typedef struct {
    char *c_string;
    struct {
        int len;
        char *data;
    } lp_string;
} lwmqtt_string_t;

/**
 * The initializer for string structures.
 */
#define lwmqtt_default_string \
  {                           \
    NULL, { 0, NULL }         \
  }

/**
 * Returns the length of the string object.
 *
 * @param str - The string to return the length of.
 * @return The length of the string.
 */
int lwmqtt_strlen(lwmqtt_string_t str);

/**
 * Compares a string object to a c-string.
 *
 * @param a - The string object to compare.
 * @param b - The c string to compare.
 * @return Similarity e.g. strcmp().
 */
int lwmqtt_strcmp(lwmqtt_string_t *a, char *b);

/**
 * The available QOS levels.
 */
typedef enum { LWMQTT_QOS0 = 0, LWMQTT_QOS1 = 1, LWMQTT_QOS2 = 2 } lwmqtt_qos_t;

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
 * Forward declaration of the client object.
 */
typedef struct lwmqtt_client_t lwmqtt_client_t;

/**
 * The callback used to peek the available bytes from a network object.
 */
typedef lwmqtt_err_t (*lwmqtt_network_peek_t)(lwmqtt_client_t *c, void *ref, int *available);

/**
 * The callback used to read from a network object. It may set read to zero if no data is available.
 *
 * Note: The callback is expected to read the exact amount of bytes requested. It should wait up to the specified
 * timeout to read the requested data from the network.
 */
typedef lwmqtt_err_t (*lwmqtt_network_read_t)(lwmqtt_client_t *c, void *ref, unsigned char *buf, int len, int *read,
                                              unsigned int timeout);

/**
 * The callback used to write to a network object.
 *
 * Note: The callback is expected to write the exact amount of bytes requested. If should wait up to the specified
 * timeout to read write the specified data to the network.
 */
typedef lwmqtt_err_t (*lwmqtt_network_write_t)(lwmqtt_client_t *c, void *ref, unsigned char *buf, int len, int *sent,
                                               unsigned int timeout);

/**
 * The callback used to set a timer.
 */
typedef void (*lwmqtt_timer_set_t)(lwmqtt_client_t *c, void *ref, unsigned int timeout);

/**
 * The callback used to get a timers value.
 */
typedef unsigned int (*lwmqtt_timer_get_t)(lwmqtt_client_t *c, void *ref);

/**
 * The callback used to forward incoming messages.
 */
typedef void (*lwmqtt_callback_t)(lwmqtt_client_t *, lwmqtt_string_t *, lwmqtt_message_t *);

/**
 * The client object.
 */
struct lwmqtt_client_t {
    unsigned short next_packet_id;
    unsigned int keep_alive_interval;
    bool ping_outstanding;

    int write_buf_size, read_buf_size;
    unsigned char *write_buf, *read_buf;

    lwmqtt_callback_t callback;

    void *network;
    lwmqtt_network_peek_t network_peek;
    lwmqtt_network_read_t network_read;
    lwmqtt_network_write_t network_write;

    void *keep_alive_timer;
    void *command_timer;
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
 * Note: The peek callback is optional.
 *
 * @param client - The client object.
 * @param ref - The reference to the network object.
 * @param peek - The peek callback.
 * @param read - The read callback.
 * @param write - The write callback.
 */
void lwmqtt_set_network(lwmqtt_client_t *client, void *ref, lwmqtt_network_peek_t peek, lwmqtt_network_read_t read, lwmqtt_network_write_t write);

/**
 * Will set the timer references and callbacks for this client objects.
 *
 * @param client - The client object.
 * @param keep_alive_timer - The reference to the keep alive timer.
 * @param network_timer - The reference to the network timer.
 * @param set - The set callback.
 * @param get - The get callback.
 */
void lwmqtt_set_timers(lwmqtt_client_t *client, void *keep_alive_timer, void *network_timer, lwmqtt_timer_set_t set,
                       lwmqtt_timer_get_t get);

/**
 * Will set the callback used to receive incoming messages.
 *
 * @param client - The client object.
 * @param cb - The callback to be called.
 */
void lwmqtt_set_callback(lwmqtt_client_t *client, lwmqtt_callback_t cb);

/**
 * The structure defining the last will of a client.
 */
typedef struct {
    lwmqtt_string_t topic;
    void *payload;
    int payload_len;
    bool retained;
    lwmqtt_qos_t qos;
} lwmqtt_will_t;

/**
 * The default initializer for the will structure.
 */
#define lwmqtt_default_will \
  { lwmqtt_default_string, NULL, 0, false, LWMQTT_QOS0 }

/**
 * The structure containing the connections options for a client.
 */
typedef struct {
    lwmqtt_string_t client_id;
    unsigned short keep_alive;
    bool clean_session;
    lwmqtt_string_t username;
    lwmqtt_string_t password;
} lwmqtt_options_t;

/**
 * The default initializer for the options structure.
 */
#define lwmqtt_default_options \
  { lwmqtt_default_string, 60, 1, lwmqtt_default_string, lwmqtt_default_string }

/**
 * The available return codes transported by the connack packet.
 */
typedef enum {
    LWMQTT_CONNACK_CONNECTION_ACCEPTED = 0,
    LWMQTT_CONNACK_UNACCEPTABLE_PROTOCOL = 1,
    LWMQTT_CONNACK_IDENTIFIER_REJECTED = 2,
    LWMQTT_CONNACK_SERVER_UNAVAILABLE = 3,
    LWMQTT_CONNACK_BAD_USERNAME_OR_PASSWORD = 4,
    LWMQTT_CONNACK_NOT_AUTHORIZED = 5
} lwmqtt_return_code_t;

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

// TODO: Improve yield timeouts:
// Calling yield to check if data is available (read one byte) should only block for a short period, while reading the
// whole packet my block up to the specified timeout.

/**
 * Will yield control to the client and read from the network and keep the connection alive.
 *
 * @param client - The client object.
 * @param timeout - The command timeout.
 * @return An error value.
 */
lwmqtt_err_t lwmqtt_yield(lwmqtt_client_t *client, unsigned int timeout);

/**
 * Will yield control to the client to keep the connection alive.
 *
 * @param client - The client object.
 * @param timeout - The command timeout.
 * @return An error value.
 */
lwmqtt_err_t lwmqtt_keep_alive(lwmqtt_client_t *client, unsigned int timeout);

#endif  // LWMQTT_CLIENT_H
