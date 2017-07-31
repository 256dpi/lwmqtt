#ifndef LWMQTT_UNIX_H
#define LWMQTT_UNIX_H

#include <sys/time.h>

#include <lwmqtt.h>

typedef struct { struct timeval end; } lwmqtt_unix_timer_t;

void lwmqtt_unix_timer_set(lwmqtt_client_t *client, void *ref, int timeout);

int lwmqtt_unix_timer_get(lwmqtt_client_t *client, void *ref);

typedef struct { int socket; } lwmqtt_unix_network_t;

lwmqtt_err_t lwmqtt_unix_network_connect(lwmqtt_unix_network_t *network, char *host, int port);

void lwmqtt_unix_network_disconnect(lwmqtt_unix_network_t *network);

lwmqtt_err_t lwmqtt_unix_network_peek(lwmqtt_client_t *client, lwmqtt_unix_network_t *network, int *available);

lwmqtt_err_t lwmqtt_unix_network_read(lwmqtt_client_t *client, void *ref, void *buf, int len, int *read, int timeout);
lwmqtt_err_t lwmqtt_unix_network_write(lwmqtt_client_t *client, void *ref, void *buf, int len, int *sent, int timeout);

#endif  // LWMQTT_UNIX_H
