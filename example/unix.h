#ifndef LWMQTT_UNIX_H
#define LWMQTT_UNIX_H

#include <sys/time.h>

#include "../src/client.h"

typedef struct { struct timeval end; } lwmqtt_unix_timer_t;

void lwmqtt_unix_timer_set(lwmqtt_client_t *c, void *ref, unsigned int);

int lwmqtt_unix_timer_get(lwmqtt_client_t *c, void *ref);

typedef struct { int socket; } lwmqtt_unix_network_t;

lwmqtt_err_t lwmqtt_unix_network_connect(lwmqtt_unix_network_t *n, char *host, int port);

void lwmqtt_unix_network_disconnect(lwmqtt_unix_network_t *n);

lwmqtt_err_t lwmqtt_unix_network_read(lwmqtt_client_t *c, void *ref, unsigned char *buf, int len, int *read,
                                      int timeout);
lwmqtt_err_t lwmqtt_unix_network_write(lwmqtt_client_t *c, void *ref, unsigned char *buf, int len, int *sent,
                                       int timeout);

#endif  // LWMQTT_PORT_H
