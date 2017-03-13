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
#include "subscribe.h"

static int lwmqtt_serialize_subscribe_length(int count, lwmqtt_string_t *topicFilters) {
  int len = 2;  // packet id

  for (int i = 0; i < count; ++i) {
    len += 2 + lwmqtt_strlen(topicFilters[i]) + 1;  // length + topic + req_qos
  }

  return len;
}

int lwmqtt_serialize_subscribe(unsigned char *buf, int buf_len, unsigned char dup, unsigned short packet_id, int count,
                               lwmqtt_string_t *topic_filters, int *qos_levels) {
  unsigned char *ptr = buf;
  lwmqtt_header_t header = {0};
  int rem_len = 0;

  if (lwmqtt_packet_len(rem_len = lwmqtt_serialize_subscribe_length(count, topic_filters)) > buf_len) {
    return MQTTPACKET_BUFFER_TOO_SHORT;
  }

  header.byte = 0;
  header.bits.type = SUBSCRIBE;
  header.bits.dup = dup;
  header.bits.qos = 1;
  lwmqtt_write_char(&ptr, header.byte);  // write header

  ptr += lwmqtt_packet_encode(ptr, rem_len);  // write remaining length

  lwmqtt_write_int(&ptr, packet_id);

  for (int i = 0; i < count; ++i) {
    lwmqtt_write_string(&ptr, topic_filters[i]);
    lwmqtt_write_char(&ptr, qos_levels[i]);
  }

  return ptr - buf;
}

int lwmqtt_deserialize_suback(unsigned short *packet_id, int max_count, int *count, int *granted_qos_levels,
                              unsigned char *buf, int buf_len) {
  lwmqtt_header_t header = {0};
  unsigned char *curdata = buf;
  unsigned char *enddata = NULL;
  int rc = 0;
  int mylen;

  header.byte = lwmqtt_read_char(&curdata);
  if (header.bits.type != SUBACK) {
    return rc;
  }

  curdata += (rc = lwmqtt_packet_decode_buf(curdata, &mylen));  // read remaining length
  enddata = curdata + mylen;
  if (enddata - curdata < 2) {
    return rc;
  }

  *packet_id = lwmqtt_read_int(&curdata);

  *count = 0;
  while (curdata < enddata) {
    if (*count > max_count) {
      return -1;
    }

    granted_qos_levels[(*count)++] = lwmqtt_read_char(&curdata);
  }

  return 1;
}
