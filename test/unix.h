/*******************************************************************************
 * Copyright (c) 2014 IBM Corp.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *   http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    Allan Stockdill-Mander - initial API and implementation and/or initial documentation
 *******************************************************************************/

#ifndef LWMQTT_UNIX_H
#define LWMQTT_UNIX_H

#include <signal.h>
#include <sys/time.h>

#include "../src/client.h"

typedef struct { struct timeval end_time; } lwmqtt_unix_timer_t;

void lwmqtt_unix_timer_set(lwmqtt_client_t *c, void *ref, unsigned int);
int lwmqtt_unix_timer_get(lwmqtt_client_t *c, void *ref);

typedef struct { int socket; } lwmqtt_unix_network_t;

int lwmqtt_unix_network_read(lwmqtt_client_t *c, void *ref, unsigned char *buf, int len, int timeout);
int lwmqtt_unix_network_write(lwmqtt_client_t *c, void *ref, unsigned char *buf, int len, int timeout);

void lwmqtt_unix_network_init(lwmqtt_unix_network_t *n);
int lwmqtt_unix_network_connect(lwmqtt_unix_network_t *n, char *host, int port);
void lwmqtt_unix_network_disconnect(lwmqtt_unix_network_t *n);

#endif  // LWMQTT_PORT_H
