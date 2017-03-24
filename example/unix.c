#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../src/client.h"
#include "unix.h"

void lwmqtt_unix_timer_set(lwmqtt_client_t *c, void *ref, unsigned int timeout) {
  // cast timer reference
  lwmqtt_unix_timer_t *t = (lwmqtt_unix_timer_t *)ref;

  // clear end time
  timerclear(&t->end);

  // get current time
  struct timeval now;
  gettimeofday(&now, NULL);

  // set future end time
  struct timeval interval = {timeout / 1000, (timeout % 1000) * 1000};
  timeradd(&now, &interval, &t->end);
}

int lwmqtt_unix_timer_get(lwmqtt_client_t *c, void *ref) {
  // cast timer reference
  lwmqtt_unix_timer_t *t = (lwmqtt_unix_timer_t *)ref;

  // get current time
  struct timeval now;
  gettimeofday(&now, NULL);

  // get difference to end time
  struct timeval res;
  timersub(&t->end, &now, &res);

  // convert to ms
  return res.tv_sec < 0 ? 0 : (int)(res.tv_sec * 1000 + res.tv_usec / 1000);
}

lwmqtt_err_t lwmqtt_unix_network_connect(lwmqtt_unix_network_t *n, char *host, int port) {
  // close any open socket
  lwmqtt_unix_network_disconnect(n);

  // prepare resolver data
  struct sockaddr_in address;
  struct addrinfo *result = NULL;
  struct addrinfo hints = {0, AF_UNSPEC, SOCK_STREAM, IPPROTO_TCP, 0, NULL, NULL, NULL};

  // resolve address
  int rc = getaddrinfo(host, NULL, &hints, &result);
  if (rc < 0) {
    return LWMQTT_FAILURE;
  }

  // prepare selected result
  struct addrinfo *current = result;
  struct addrinfo *selected = NULL;

  // traverse list and select first found ipv4 address
  while (current) {
    // check if ipv4 address
    if (current->ai_family == AF_INET) {
      selected = current;
      break;
    }

    // move one to next
    current = current->ai_next;
  }

  // free result
  freeaddrinfo(result);

  // return error if none found
  if (selected == NULL) {
    return LWMQTT_FAILURE;
  }

  // populate address struct
  address.sin_port = htons(port);
  address.sin_family = AF_INET;
  address.sin_addr = ((struct sockaddr_in *)(selected->ai_addr))->sin_addr;

  // create new socket
  n->socket = socket(AF_INET, SOCK_STREAM, 0);
  if (n->socket < 0) {
    return LWMQTT_FAILURE;
  }

  // connect socket
  rc = connect(n->socket, (struct sockaddr *)&address, sizeof(address));
  if (rc < 0) {
    printf("lwmqtt_unix_network_connect: %d\n", errno);
    return LWMQTT_FAILURE;
  }

  return LWMQTT_SUCCESS;
}

void lwmqtt_unix_network_disconnect(lwmqtt_unix_network_t *n) {
  // close socket if present
  if (n->socket) {
    close(n->socket);
    n->socket = 0;
  }
}

lwmqtt_err_t lwmqtt_unix_network_read(lwmqtt_client_t *c, void *ref, unsigned char *buffer, int len, int *read,
                                      int timeout) {
  // cast network reference
  lwmqtt_unix_network_t *n = (lwmqtt_unix_network_t *)ref;

  // convert timeout
  struct timeval t = {.tv_sec = timeout / 1000, .tv_usec = (timeout % 1000) * 1000};

  // set timeout
  int rc = setsockopt(n->socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&t, sizeof(t));
  if (rc < 0) {
    return LWMQTT_FAILURE;
  }

  // TODO: Move loop to calling function?

  // loop until buffer is full
  while (*read < len) {
    // read from socket
    rc = (int)recv(n->socket, &buffer[*read], (size_t)(len - *read), 0);
    if (rc == -1) {
      // finish current loop on timeout
      if (errno == EAGAIN) {
        break;
      }

      return LWMQTT_FAILURE;
    } else if (rc == 0) {
      // finish if no more data
      break;
    } else
      // increment counter
      *read += rc;
  }

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t lwmqtt_unix_network_write(lwmqtt_client_t *c, void *ref, unsigned char *buffer, int len, int *sent,
                                       int timeout) {
  // cast network reference
  lwmqtt_unix_network_t *n = (lwmqtt_unix_network_t *)ref;

  // convert timeout
  struct timeval t = {.tv_sec = timeout / 1000, .tv_usec = (timeout % 1000) * 1000};

  // set timeout
  int rc = setsockopt(n->socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&t, sizeof(t));
  if (rc < 0) {
    return LWMQTT_FAILURE;
  }

  // write to socket
  int bytes = (int)send(n->socket, buffer, (size_t)len, 0);
  if (bytes < 0) {
    printf("lwmqtt_unix_network_write: %d\n", errno);
    return LWMQTT_FAILURE;
  }

  // increment counter
  *sent += bytes;

  return LWMQTT_SUCCESS;
}
