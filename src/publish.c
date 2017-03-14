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

#include "packet.h"
#include "publish.h"

int lwmqtt_deserialize_publish(unsigned char *dup, int *qos, unsigned char *retained, unsigned short *packet_id,
                               lwmqtt_string_t *topic, unsigned char **payload, int *payload_len, unsigned char *buf,
                               int buf_len) {
  lwmqtt_header_t header = {0};
  unsigned char *curdata = buf;
  unsigned char *enddata = NULL;
  int rc = 0;
  int mylen = 0;

  header.byte = lwmqtt_read_char(&curdata);
  if (header.bits.type != LWMQTT_PUBLISH_PACKET) {
    return rc;
  }

  *dup = header.bits.dup;
  *qos = header.bits.qos;
  *retained = header.bits.retain;

  curdata += (rc = lwmqtt_fixed_header_decode(curdata, &mylen));  // read remaining length
  enddata = curdata + mylen;

  // do we have enough data to read the protocol version byte?
  if (!lwmqtt_read_lp_string(topic, &curdata, enddata) || enddata - curdata < 0) {
    return rc;
  }

  if (*qos > 0) {
    *packet_id = lwmqtt_read_int(&curdata);
  }

  *payload_len = enddata - curdata;
  *payload = curdata;
  rc = 1;

  return rc;
}

int lwmqtt_deserialize_ack(unsigned char *packet_type, unsigned char *dup, unsigned short *packet_id,
                           unsigned char *buf, int buf_len) {
  lwmqtt_header_t header = {0};
  unsigned char *curdata = buf;
  unsigned char *enddata = NULL;
  int rc = 0;
  int mylen;

  header.byte = lwmqtt_read_char(&curdata);
  *dup = header.bits.dup;
  *packet_type = header.bits.type;

  curdata += (rc = lwmqtt_fixed_header_decode(curdata, &mylen));  // read remaining length
  enddata = curdata + mylen;

  if (enddata - curdata < 2) {
    return rc;
  }

  *packet_id = lwmqtt_read_int(&curdata);

  return 1;
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
  lwmqtt_header_t header = {0};
  int rem_len = 0;

  if (lwmqtt_fixed_header_len(rem_len = lwmqtt_serialize_publish_length(qos, topic, payload_len)) > buf_len) {
    return LWMQTT_BUFFER_TOO_SHORT;
  }

  header.bits.type = LWMQTT_PUBLISH_PACKET;
  header.bits.dup = dup;
  header.bits.qos = qos;
  header.bits.retain = retained;
  lwmqtt_write_char(&ptr, header.byte);  // write header

  ptr += lwmqtt_fixed_header_encode(ptr, rem_len);  // write remaining length

  lwmqtt_write_string(&ptr, topic);

  if (qos > 0) {
    lwmqtt_write_int(&ptr, packet_id);
  }

  memcpy(ptr, payload, payload_len);
  ptr += payload_len;

  return ptr - buf;
}

int lwmqtt_serialize_ack(unsigned char *buf, int buf_len, unsigned char packettype, unsigned char dup,
                         unsigned short packet_id) {
  lwmqtt_header_t header = {0};
  unsigned char *ptr = buf;

  if (buf_len < 4) {
    return LWMQTT_BUFFER_TOO_SHORT;
  }

  header.bits.type = packettype;
  header.bits.dup = dup;
  header.bits.qos = (packettype == LWMQTT_PUBREL_PACKET) ? 1 : 0;
  lwmqtt_write_char(&ptr, header.byte);  // write header

  ptr += lwmqtt_fixed_header_encode(ptr, 2);  // write remaining length
  lwmqtt_write_int(&ptr, packet_id);

  return ptr - buf;
}

int lwmqtt_serialize_puback(unsigned char *buf, int buf_len, unsigned short packet_id) {
  return lwmqtt_serialize_ack(buf, buf_len, LWMQTT_PUBACK_PACKET, 0, packet_id);
}

int lwmqtt_serialize_pubrel(unsigned char *buf, int buf_len, unsigned char dup, unsigned short packet_id) {
  return lwmqtt_serialize_ack(buf, buf_len, LWMQTT_PUBREL_PACKET, dup, packet_id);
}

int lwmqtt_serialize_pubcomp(unsigned char *buf, int buf_len, unsigned short packet_id) {
  return lwmqtt_serialize_ack(buf, buf_len, LWMQTT_PUBCOMP_PACKET, 0, packet_id);
}
