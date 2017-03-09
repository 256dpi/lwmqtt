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

int lwmqtt_deserialize_publish(unsigned char *dup, int *qos, unsigned char *retained, unsigned short *packetid,
                               lwmqtt_string_t *topicName, unsigned char **payload, int *payloadlen, unsigned char *buf,
                               int buflen) {
  lwmqtt_header_t header = {0};
  unsigned char *curdata = buf;
  unsigned char *enddata = NULL;
  int rc = 0;
  int mylen = 0;

  header.byte = lwmqtt_read_char(&curdata);
  if (header.bits.type != PUBLISH) return rc;
  *dup = header.bits.dup;
  *qos = header.bits.qos;
  *retained = header.bits.retain;

  curdata += (rc = lwmqtt_packet_decode_buf(curdata, &mylen)); /* read remaining length */
  enddata = curdata + mylen;

  if (!lwmqtt_read_lp_string(topicName, &curdata, enddata) ||
      enddata - curdata < 0) /* do we have enough data to read the protocol version byte? */
    return rc;

  if (*qos > 0) *packetid = lwmqtt_read_int(&curdata);

  *payloadlen = enddata - curdata;
  *payload = curdata;
  rc = 1;

  return rc;
}

int lwmqtt_deserialize_ack(unsigned char *packettype, unsigned char *dup, unsigned short *packetid, unsigned char *buf,
                           int buflen) {
  lwmqtt_header_t header = {0};
  unsigned char *curdata = buf;
  unsigned char *enddata = NULL;
  int rc = 0;
  int mylen;

  header.byte = lwmqtt_read_char(&curdata);
  *dup = header.bits.dup;
  *packettype = header.bits.type;

  curdata += (rc = lwmqtt_packet_decode_buf(curdata, &mylen)); /* read remaining length */
  enddata = curdata + mylen;

  if (enddata - curdata < 2) return rc;
  *packetid = lwmqtt_read_int(&curdata);

  return 1;
}

static int lwmqtt_serialize_publish_length(int qos, lwmqtt_string_t topicName, int payloadlen) {
  int len = 0;

  len += 2 + lwmqtt_strlen(topicName) + payloadlen;
  if (qos > 0) len += 2; /* packetid */
  return len;
}

int lwmqtt_serialize_publish(unsigned char *buf, int buflen, unsigned char dup, int qos, unsigned char retained,
                             unsigned short packetid, lwmqtt_string_t topicName, unsigned char *payload,
                             int payloadlen) {
  unsigned char *ptr = buf;
  lwmqtt_header_t header = {0};
  int rem_len = 0;
  int rc = 0;

  if (lwmqtt_packet_len(rem_len = lwmqtt_serialize_publish_length(qos, topicName, payloadlen)) > buflen) {
    return MQTTPACKET_BUFFER_TOO_SHORT;
  }

  header.bits.type = PUBLISH;
  header.bits.dup = dup;
  header.bits.qos = qos;
  header.bits.retain = retained;
  lwmqtt_write_char(&ptr, header.byte); /* write header */

  ptr += lwmqtt_packet_encode(ptr, rem_len); /* write remaining length */

  lwmqtt_write_string(&ptr, topicName);

  if (qos > 0) lwmqtt_write_int(&ptr, packetid);

  memcpy(ptr, payload, payloadlen);
  ptr += payloadlen;

  return ptr - buf;
}

int lwmqtt_serialize_ack(unsigned char *buf, int buflen, unsigned char packettype, unsigned char dup,
                         unsigned short packetid) {
  lwmqtt_header_t header = {0};
  int rc = 0;
  unsigned char *ptr = buf;

  if (buflen < 4) {
    return MQTTPACKET_BUFFER_TOO_SHORT;
  }
  header.bits.type = packettype;
  header.bits.dup = dup;
  header.bits.qos = (packettype == PUBREL) ? 1 : 0;
  lwmqtt_write_char(&ptr, header.byte); /* write header */

  ptr += lwmqtt_packet_encode(ptr, 2); /* write remaining length */
  lwmqtt_write_int(&ptr, packetid);

  return ptr - buf;
}

int lwmqtt_serialize_puback(unsigned char *buf, int buflen, unsigned short packetid) {
  return lwmqtt_serialize_ack(buf, buflen, PUBACK, 0, packetid);
}

int lwmqtt_serialize_pubrel(unsigned char *buf, int buflen, unsigned char dup, unsigned short packetid) {
  return lwmqtt_serialize_ack(buf, buflen, PUBREL, dup, packetid);
}

int lwmqtt_serialize_pubcomp(unsigned char *buf, int buflen, unsigned short packetid) {
  return lwmqtt_serialize_ack(buf, buflen, PUBCOMP, 0, packetid);
}
