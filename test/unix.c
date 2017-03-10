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

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../src/client.h"
#include "unix.h"

void lwmqtt_unix_timer_set(lwmqtt_client_t *c, void *ref, unsigned int timeout) {
  lwmqtt_unix_timer_t *t = (lwmqtt_unix_timer_t *)ref;

  t->end_time = (struct timeval){0, 0};

  struct timeval now;
  gettimeofday(&now, NULL);
  struct timeval interval = {timeout / 1000, (timeout % 1000) * 1000};
  timeradd(&now, &interval, &t->end_time);
}

int lwmqtt_unix_timer_get(lwmqtt_client_t *c, void *ref) {
  lwmqtt_unix_timer_t *t = (lwmqtt_unix_timer_t *)ref;

  struct timeval now, res;
  gettimeofday(&now, NULL);
  timersub(&t->end_time, &now, &res);

  // printf("left %d ms\n", (res.tv_sec < 0) ? 0 : res.tv_sec * 1000 + res.tv_usec / 1000);
  return (res.tv_sec < 0) ? 0 : res.tv_sec * 1000 + res.tv_usec / 1000;
}

int lwmqtt_unix_network_connect(lwmqtt_unix_network_t *n, char *addr, int port) {
  if (n->socket) {
    close(n->socket);
    n->socket = 0;
  }

  int type = SOCK_STREAM;
  struct sockaddr_in address;
  int rc = -1;
  sa_family_t family = AF_INET;
  struct addrinfo *result = NULL;
  struct addrinfo hints = {0, AF_UNSPEC, SOCK_STREAM, IPPROTO_TCP, 0, NULL, NULL, NULL};

  if ((rc = getaddrinfo(addr, NULL, &hints, &result)) == 0) {
    struct addrinfo *res = result;

    /* prefer ip4 addresses */
    while (res) {
      if (res->ai_family == AF_INET) {
        result = res;
        break;
      }
      res = res->ai_next;
    }

    if (result->ai_family == AF_INET) {
      address.sin_port = htons(port);
      address.sin_family = family = AF_INET;
      address.sin_addr = ((struct sockaddr_in *)(result->ai_addr))->sin_addr;
    } else
      rc = -1;

    freeaddrinfo(result);
  }

  if (rc == 0) {
    n->socket = socket(family, type, 0);
    if (n->socket != -1) rc = connect(n->socket, (struct sockaddr *)&address, sizeof(address));
  }

  return rc;
}

void lwmqtt_unix_network_disconnect(lwmqtt_unix_network_t *n) {
  if (n->socket) {
    close(n->socket);
    n->socket = 0;
  }
}

int lwmqtt_unix_network_read(lwmqtt_client_t *c, void *ref, unsigned char *buffer, int len, int timeout) {
  lwmqtt_unix_network_t *n = (lwmqtt_unix_network_t *)ref;

  struct timeval interval = {timeout / 1000, (timeout % 1000) * 1000};
  if (interval.tv_sec < 0 || (interval.tv_sec == 0 && interval.tv_usec <= 0)) {
    interval.tv_sec = 0;
    interval.tv_usec = 100;
  }

  setsockopt(n->socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&interval, sizeof(struct timeval));

  int bytes = 0;
  while (bytes < len) {
    int rc = recv(n->socket, &buffer[bytes], (size_t)(len - bytes), 0);
    if (rc == -1) {
      if (errno != ENOTCONN && errno != ECONNRESET) {
        bytes = -1;
        break;
      }
    } else if (rc == 0) {
      bytes = 0;
      break;
    } else
      bytes += rc;
  }
  return bytes;
}

int lwmqtt_unix_network_write(lwmqtt_client_t *c, void *ref, unsigned char *buffer, int len, int timeout_ms) {
  lwmqtt_unix_network_t *n = (lwmqtt_unix_network_t *)ref;

  struct timeval tv;

  tv.tv_sec = 0;                   /* 30 Secs Timeout */
  tv.tv_usec = timeout_ms * 1000;  // Not init'ing this can cause strange errors

  setsockopt(n->socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));
  int rc = write(n->socket, buffer, len);
  return rc;
}
