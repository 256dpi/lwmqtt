#include <arpa/inet.h>
#include <errno.h>
#include <memory.h>
#include <netdb.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <lwmqtt/posix.h>

void lwmqtt_posix_timer_set(void *ref, uint32_t timeout) {
  // cast timer reference
  lwmqtt_posix_timer_t *t = (lwmqtt_posix_timer_t *)ref;

  // clear end time
  timerclear(&t->end);

  // get current time
  struct timeval now;
  gettimeofday(&now, NULL);

  // set future end time
  struct timeval interval = {timeout / 1000, (timeout % 1000) * 1000};
  timeradd(&now, &interval, &t->end);
}

int32_t lwmqtt_posix_timer_get(void *ref) {
  // cast timer reference
  lwmqtt_posix_timer_t *t = (lwmqtt_posix_timer_t *)ref;

  // get current time
  struct timeval now;
  gettimeofday(&now, NULL);

  // get difference to end time
  struct timeval res;
  timersub(&t->end, &now, &res);

  return (int32_t)((res.tv_sec * 1000) + (res.tv_usec / 1000));
}

lwmqtt_err_t lwmqtt_posix_network_connect(lwmqtt_posix_network_t *network, char *host, int port) {
  // close any open socket
  lwmqtt_posix_network_disconnect(network);

  // prepare resolver hints
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_flags = AI_ADDRCONFIG;
  hints.ai_socktype = SOCK_STREAM;

  // resolve address
  struct addrinfo *result = NULL;
  int rc = getaddrinfo(host, NULL, &hints, &result);
  if (rc < 0) {
    return LWMQTT_NETWORK_FAILED_CONNECT;
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

  // return error if none found
  if (selected == NULL) {
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  // populate address struct
  struct sockaddr_in address;
  address.sin_port = htons(port);
  address.sin_family = AF_INET;
  address.sin_addr = ((struct sockaddr_in *)(selected->ai_addr))->sin_addr;

  // free result
  freeaddrinfo(result);

  // create new socket
  network->socket = socket(AF_INET, SOCK_STREAM, 0);
  if (network->socket < 0) {
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  // connect socket
  rc = connect(network->socket, (struct sockaddr *)&address, sizeof(address));
  if (rc < 0) {
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  return LWMQTT_SUCCESS;
}

void lwmqtt_posix_network_disconnect(lwmqtt_posix_network_t *network) {
  // close socket if present
  if (network->socket) {
    close(network->socket);
    network->socket = 0;
  }
}

lwmqtt_err_t lwmqtt_posix_network_peek(lwmqtt_posix_network_t *network, size_t *available) {
  // check socket validity
  char ret;
  int bytes = (int)recv(network->socket, &ret, 1, MSG_PEEK | MSG_DONTWAIT);
  if (bytes <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // get the available bytes on the socket
  int rc = ioctl(network->socket, FIONREAD, available);
  if (rc < 0) {
    return LWMQTT_NETWORK_FAILED_READ;
  }

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t lwmqtt_posix_network_select(lwmqtt_posix_network_t *network, bool *available, uint32_t timeout) {
  // prepare set
  fd_set set;
  fd_set ex_set;
  FD_ZERO(&set);
  FD_ZERO(&ex_set);
  FD_SET(network->socket, &set);
  FD_SET(network->socket, &ex_set);

  // wait for data
  struct timeval t = {.tv_sec = timeout / 1000, .tv_usec = (timeout % 1000) * 1000};
  int result = select(network->socket + 1, &set, NULL, &ex_set, &t);
  if (result < 0 || FD_ISSET(network->socket, &ex_set)) {
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // set whether data is available
  *available = result > 0;

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t lwmqtt_posix_network_read(void *ref, uint8_t *buffer, size_t len, size_t *received, uint32_t timeout) {
  // cast network reference
  lwmqtt_posix_network_t *n = (lwmqtt_posix_network_t *)ref;

  // set timeout
  struct timeval t = {.tv_sec = timeout / 1000, .tv_usec = (timeout % 1000) * 1000};
  int rc = setsockopt(n->socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&t, sizeof(t));
  if (rc < 0) {
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // read from socket
  int bytes = (int)read(n->socket, buffer, len);
  if (bytes < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
    return LWMQTT_SUCCESS;
  } else if (bytes == 0) {
    return LWMQTT_NETWORK_FAILED_READ;
  } else if (bytes < 0) {
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // increment counter
  *received += bytes;

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t lwmqtt_posix_network_write(void *ref, uint8_t *buffer, size_t len, size_t *sent, uint32_t timeout) {
  // cast network reference
  lwmqtt_posix_network_t *n = (lwmqtt_posix_network_t *)ref;

  // set timeout
  struct timeval t = {.tv_sec = timeout / 1000, .tv_usec = (timeout % 1000) * 1000};
  int rc = setsockopt(n->socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&t, sizeof(t));
  if (rc < 0) {
    return LWMQTT_NETWORK_FAILED_WRITE;
  }

  // write to socket
  int bytes = (int)send(n->socket, buffer, len, 0);
  if (bytes < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
    return LWMQTT_SUCCESS;
  } else if (bytes < 0) {
    return LWMQTT_NETWORK_FAILED_WRITE;
  }

  // increment counter
  *sent += bytes;

  return LWMQTT_SUCCESS;
}
