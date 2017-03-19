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
 *******************************************************************************/

#ifndef LWMQTT_CONNECT_H
#define LWMQTT_CONNECT_H

#include <stdbool.h>

#include "packet.h"
#include "string.h"

/**
 * Defines the MQTT "Last Will and Testament" (LWT) settings for
 * the connect packet.
 */
typedef struct {
  lwmqtt_string_t topic;
  void *payload;
  int payload_len;
  unsigned char retained;
  lwmqtt_qos_t qos;
} lwmqtt_will_t;

#define lwmqtt_default_will \
  { {NULL, {0, NULL}}, NULL, 0, 0, LWMQTT_QOS0 }

typedef struct {
  lwmqtt_string_t client_id;
  unsigned short keep_alive;
  unsigned char clean_session;
  lwmqtt_string_t username;
  lwmqtt_string_t password;
} lwmqtt_options_t;

#define lwmqtt_default_options \
  { lwmqtt_default_string, 60, 1, lwmqtt_default_string, lwmqtt_default_string }

typedef enum {
  LWMQTT_CONNACK_CONNECTION_ACCEPTED = 0,
  LWMQTT_CONNACK_UNACCEPTABLE_PROTOCOL = 1,
  LWMQTT_CONNACK_IDENTIFIER_REJECTED = 2,
  LWMQTT_CONNACK_SERVER_UNAVAILABLE = 3,
  LWMQTT_CONNACK_BAD_USERNAME_OR_PASSWORD = 4,
  LWMQTT_CONNACK_NOT_AUTHORIZED = 5
} lwmqtt_connack_t;

/**
  * Serializes the connect options into the buffer.
  *
  * @param buf the buffer into which the packet will be serialized
  * @param len the length in bytes of the supplied buffer
  * @param options the options to be used to build the connect packet
  * @return serialized length, or error if 0
  */
lwmqtt_err_t lwmqtt_serialize_connect(unsigned char *buf, int buf_len, int *len, lwmqtt_options_t *options,
                                      lwmqtt_will_t *will);

/**
  * Deserializes the supplied (wire) buffer into connack data - return code
  *
  * @param session_present the session present flag returned (only for MQTT 3.1.1)
  * @param connack_rc returned integer value of the connack return code
  * @param buf the raw buffer data, of the correct length determined by the remaining length field
  * @param len the length in bytes of the data in the supplied buffer
  * @return error code.  1 is success, 0 is failure
  */
lwmqtt_err_t lwmqtt_deserialize_connack(bool *session_present, lwmqtt_connack_t *connack, unsigned char *buf,
                                        int buf_len);

/**
  * Serializes a disconnect packet into the supplied buffer, ready for writing to a socket
  *
  * @param buf The buffer into which the packet will be serialized.
  * @param buf_len The length in bytes of the supplied buffer, to avoid overruns.
  * @return Serialized length, or error if 0.
  */
lwmqtt_err_t lwmqtt_serialize_disconnect(unsigned char *buf, int buf_len, int *len);

/**
  * Serializes a disconnect packet into the supplied buffer, ready for writing to a socket
  *
  * @param buf The buffer into which the packet will be serialized.
  * @param buf_len The length in bytes of the supplied buffer, to avoid overruns.
  * @return Serialized length, or error if 0.
  */
lwmqtt_err_t lwmqtt_serialize_pingreq(unsigned char *buf, int buf_len, int *len);

#endif  // LWMQTT_CONNECT_H
