#ifndef LWMQTT_POSIX_H
#define LWMQTT_POSIX_H

#include <sys/time.h>

#include <lwmqtt.h>

/**
 * The POSIX timer object.
 */
typedef struct {
  struct timeval end;
} lwmqtt_posix_timer_t;

/**
 * Callback to set the POSIX timer object.
 *
 * @see lwmqtt_timer_set_t.
 */
void lwmqtt_posix_timer_set(void *ref, uint32_t timeout);

/**
 * Callback to read the POSIX timer object.
 *
 * @see lwmqtt_timer_get_t.
 */
int32_t lwmqtt_posix_timer_get(void *ref);

/**
 * The POSIX network object.
 */
typedef struct {
  int socket;
} lwmqtt_posix_network_t;

/**
 * Function to establish a POSIX network connection.
 *
 * @param network The network object.
 * @param host The host.
 * @param port The port.
 * @return An error value.
 */
lwmqtt_err_t lwmqtt_posix_network_connect(lwmqtt_posix_network_t *network, char *host, int port);

/**
 * Function to disconnect a POSIX network connection.
 *
 * @param network The network object.
 */
void lwmqtt_posix_network_disconnect(lwmqtt_posix_network_t *network);

/**
 * Function to peek available bytes on a POSIX network connection.
 *
 * @param network The network object.
 * @param available Variable that is set with the available bytes.
 * @return An error value.
 */
lwmqtt_err_t lwmqtt_posix_network_peek(lwmqtt_posix_network_t *network, size_t *available);

/**
 * Function to wait for a socket until data is available or the timeout has been reached.
 *
 * @param network The network object.
 * @param available Variables that is set with the available bytes.
 * @param timeout The timeout.
 * @return An error value.
 */
lwmqtt_err_t lwmqtt_posix_network_select(lwmqtt_posix_network_t *network, bool *available, uint32_t timeout);

/**
 * Callback to read from a POSIX network connection.
 *
 * @see lwmqtt_network_read_t.
 */
lwmqtt_err_t lwmqtt_posix_network_read(void *ref, uint8_t *buf, size_t len, size_t *received, uint32_t timeout);

/**
 * Callback to write to a POSIX network connection.
 *
 * @see lwmqtt_network_write_t.
 */
lwmqtt_err_t lwmqtt_posix_network_write(void *ref, uint8_t *buf, size_t len, size_t *sent, uint32_t timeout);

#endif  // LWMQTT_POSIX_H
