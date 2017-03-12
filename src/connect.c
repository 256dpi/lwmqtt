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
 *    Ian Craggs - initial API and implementation and/or initial documentation
 *******************************************************************************/

#include <string.h>

#include "connect.h"
#include "packet.h"

static int lwmqtt_serialize_connect_length(lwmqtt_connect_data_t *options) {
  int len = 4;

  len += lwmqtt_strlen(options->clientID) + 2;
  if (options->willFlag) len += lwmqtt_strlen(options->will.topicName) + 2 + lwmqtt_strlen(options->will.message) + 2;
  if (options->username.cstring || options->username.lenstring.data) len += lwmqtt_strlen(options->username) + 2;
  if (options->password.cstring || options->password.lenstring.data) len += lwmqtt_strlen(options->password) + 2;

  return len;
}

int lwmqtt_serialize_connect(unsigned char *buf, int buflen, lwmqtt_connect_data_t *options) {
  unsigned char *ptr = buf;
  lwmqtt_header_t header = {0};
  lwmqtt_connect_flags_t flags = {0};
  int len = 0;

  if (lwmqtt_packet_len(len = lwmqtt_serialize_connect_length(options)) > buflen) {
    return MQTTPACKET_BUFFER_TOO_SHORT;
  }

  header.byte = 0;
  header.bits.type = CONNECT;
  lwmqtt_write_char(&ptr, header.byte); /* write header */

  ptr += lwmqtt_packet_encode(ptr, len); /* write remaining length */

  lwmqtt_write_c_string(&ptr, "MQTT");
  lwmqtt_write_char(&ptr, (char)4);

  flags.all = 0;
  flags.bits.cleansession = options->cleansession;
  flags.bits.will = (options->willFlag) ? 1 : 0;
  if (flags.bits.will) {
    flags.bits.willQoS = options->will.qos;
    flags.bits.willRetain = options->will.retained;
  }

  if (options->username.cstring || options->username.lenstring.data) flags.bits.username = 1;
  if (options->password.cstring || options->password.lenstring.data) flags.bits.password = 1;

  lwmqtt_write_char(&ptr, flags.all);
  lwmqtt_write_int(&ptr, options->keepAliveInterval);
  lwmqtt_write_string(&ptr, options->clientID);
  if (options->willFlag) {
    lwmqtt_write_string(&ptr, options->will.topicName);
    lwmqtt_write_string(&ptr, options->will.message);
  }
  if (flags.bits.username) lwmqtt_write_string(&ptr, options->username);
  if (flags.bits.password) lwmqtt_write_string(&ptr, options->password);

  return ptr - buf;
}

int lwmqtt_deserialize_connack(unsigned char *sessionPresent, unsigned char *connack_rc, unsigned char *buf,
                               int buflen) {
  lwmqtt_header_t header = {0};
  unsigned char *curdata = buf;
  unsigned char *enddata = NULL;
  int rc = 0;
  int mylen;
  lwmqtt_connack_flags flags = {0};

  header.byte = lwmqtt_read_char(&curdata);
  if (header.bits.type != CONNACK) return rc;

  curdata += (rc = lwmqtt_packet_decode_buf(curdata, &mylen)); /* read remaining length */
  enddata = curdata + mylen;
  if (enddata - curdata < 2) return rc;

  flags.all = lwmqtt_read_char(&curdata);
  *sessionPresent = flags.bits.sessionpresent;
  *connack_rc = lwmqtt_read_char(&curdata);

  return 1;
}

static int lwmqtt_serialize_zero(unsigned char *buf, int buflen, unsigned char packettype) {
  lwmqtt_header_t header = {0};
  unsigned char *ptr = buf;

  if (buflen < 2) {
    return MQTTPACKET_BUFFER_TOO_SHORT;
  }

  header.byte = 0;
  header.bits.type = packettype;
  lwmqtt_write_char(&ptr, header.byte); /* write header */

  ptr += lwmqtt_packet_encode(ptr, 0); /* write remaining length */
  return ptr - buf;
}

int lwmqtt_serialize_disconnect(unsigned char *buf, int len) { return lwmqtt_serialize_zero(buf, len, DISCONNECT); }

int lwmqtt_serialize_pingreq(unsigned char *buf, int len) { return lwmqtt_serialize_zero(buf, len, PINGREQ); }
