#ifndef LWMQTT_UNIX_H
#define LWMQTT_UNIX_H

#include <sys/time.h>

#include <lwmqtt.h>

/**
 * The UNIX timer object.
 */
typedef struct { struct timeval end; } lwmqtt_unix_timer_t;

/**
 * Callback to set the UNIX timer object.
 */
void lwmqtt_unix_timer_set(lwmqtt_client_t *client, void *ref, uint32_t timeout);

/**
 * Callback to read the UNIX timer object.
 */
uint32_t lwmqtt_unix_timer_get(lwmqtt_client_t *client, void *ref);

/**
 * The UNIX network object.
 */
typedef struct { int socket; } lwmqtt_unix_network_t;

/**
 * Function to establish a UNIX network connection.
 *
 * @param network - The network object.
 * @param host - The host.
 * @param port - The port.
 * @return An error value.
 */
lwmqtt_err_t lwmqtt_unix_network_connect(lwmqtt_unix_network_t *network, char *host, int port);

/**
 * Function to disconnect a UNIX network connection.
 *
 * @param network - The network object.
 */
void lwmqtt_unix_network_disconnect(lwmqtt_unix_network_t *network);

/**
 * Function to peek available bytes on a UNIX network connection.
 *
 * @param network - The network object.
 * @param available - The available bytes.
 * @return An error value.
 */
lwmqtt_err_t lwmqtt_unix_network_peek(lwmqtt_unix_network_t *network, size_t *available);

/**
 * Callback to read from a UNIX network connection.
 */
lwmqtt_err_t lwmqtt_unix_network_read(lwmqtt_client_t *client, void *ref, uint8_t *buf, size_t len, size_t *read,
                                      uint32_t timeout);

/**
 * Callback to write to a UNIX network connection.
 */
lwmqtt_err_t lwmqtt_unix_network_write(lwmqtt_client_t *client, void *ref, uint8_t *buf, size_t len, size_t *sent,
                                       uint32_t timeout);

#endif  // LWMQTT_UNIX_H
