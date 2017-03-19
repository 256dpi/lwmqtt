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

#include <string.h>

#include "helpers.h"
#include "identified.h"
#include "packet.h"
#include "publish.h"

int lwmqtt_deserialize_publish(unsigned char *dup, int *qos, unsigned char *retained, unsigned short *packet_id,
                               lwmqtt_string_t *topic, unsigned char **payload, int *payload_len, unsigned char *buf,
                               int buf_len) {
  lwmqtt_header_t header = {0};
  unsigned char *cur_ptr = buf;
  int rc = 0;
  int len = 0;

  header.byte = lwmqtt_read_char(&cur_ptr);
  if (header.bits.type != LWMQTT_PUBLISH_PACKET) {
    return rc;
  }

  *dup = (unsigned char)header.bits.dup;
  *qos = header.bits.qos;
  *retained = (unsigned char)header.bits.retain;

  cur_ptr += (rc = lwmqtt_header_decode(cur_ptr, &len));  // read remaining length
  unsigned char *end_ptr = cur_ptr + len;

  // do we have enough data to read the protocol version byte?
  if (!lwmqtt_read_lp_string(topic, &cur_ptr, end_ptr) || end_ptr - cur_ptr < 0) {
    return rc;
  }

  if (*qos > 0) {
    *packet_id = (unsigned short)lwmqtt_read_int(&cur_ptr);
  }

  *payload_len = (int)(end_ptr - cur_ptr);
  *payload = cur_ptr;
  rc = 1;

  return rc;
}

static int lwmqtt_serialize_publish_length(int qos, lwmqtt_string_t topicName, int payload_len) {
  int len = 0;

  len += 2 + lwmqtt_strlen(topicName) + payload_len;
  if (qos > 0) {
    len += 2;
  }  // packet id

  return len;
}

int lwmqtt_serialize_publish(unsigned char *buf, int buf_len, unsigned char dup, int qos, unsigned char retained,
                             unsigned short packet_id, lwmqtt_string_t topic, unsigned char *payload, int payload_len) {
  unsigned char *ptr = buf;

  int rem_len = lwmqtt_serialize_publish_length(qos, topic, payload_len);

  if (lwmqtt_header_len(rem_len) + rem_len > buf_len) {
    return LWMQTT_BUFFER_TOO_SHORT_ERROR;
  }

  lwmqtt_header_t header = {0};
  header.bits.type = LWMQTT_PUBLISH_PACKET;
  header.bits.dup = dup;
  header.bits.qos = (unsigned int)qos;
  header.bits.retain = retained;
  lwmqtt_write_char(&ptr, header.byte);  // write header

  ptr += lwmqtt_header_encode(ptr, rem_len);  // write remaining length

  lwmqtt_write_string(&ptr, topic);

  if (qos > 0) {
    lwmqtt_write_int(&ptr, packet_id);
  }

  memcpy(ptr, payload, payload_len);
  ptr += payload_len;

  return (int)(ptr - buf);
}

int lwmqtt_serialize_puback(unsigned char *buf, int buf_len, unsigned short packet_id) {
  return lwmqtt_serialize_identified(buf, buf_len, LWMQTT_PUBACK_PACKET, 0, packet_id);
}

int lwmqtt_serialize_pubrec(unsigned char *buf, int buf_len, unsigned short packet_id) {
  return lwmqtt_serialize_identified(buf, buf_len, LWMQTT_PUBREC_PACKET, 0, packet_id);
}

int lwmqtt_serialize_pubrel(unsigned char *buf, int buf_len, unsigned char dup, unsigned short packet_id) {
  return lwmqtt_serialize_identified(buf, buf_len, LWMQTT_PUBREL_PACKET, dup, packet_id);
}

int lwmqtt_serialize_pubcomp(unsigned char *buf, int buf_len, unsigned short packet_id) {
  return lwmqtt_serialize_identified(buf, buf_len, LWMQTT_PUBCOMP_PACKET, 0, packet_id);
}
