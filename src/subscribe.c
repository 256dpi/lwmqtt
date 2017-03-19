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

#include "subscribe.h"
#include "helpers.h"
#include "packet.h"

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

  int rem_len = lwmqtt_serialize_subscribe_length(count, topic_filters);

  if (lwmqtt_header_len(rem_len) + rem_len > buf_len) {
    return LWMQTT_BUFFER_TOO_SHORT_ERROR;
  }

  lwmqtt_header_t header = {0};
  header.bits.type = LWMQTT_SUBSCRIBE_PACKET;
  header.bits.dup = dup;
  header.bits.qos = 1;
  lwmqtt_write_char(&ptr, header.byte);  // write header

  ptr += lwmqtt_header_encode(ptr, rem_len);  // write remaining length

  lwmqtt_write_int(&ptr, packet_id);

  for (int i = 0; i < count; ++i) {
    lwmqtt_write_string(&ptr, topic_filters[i]);
    lwmqtt_write_char(&ptr, (unsigned char)qos_levels[i]);
  }

  return (int)(ptr - buf);
}

int lwmqtt_deserialize_suback(unsigned short *packet_id, int max_count, int *count, int *granted_qos_levels,
                              unsigned char *buf, int buf_len) {
  lwmqtt_header_t header = {0};
  unsigned char *cur_ptr = buf;
  int rc = 0;
  int len;

  header.byte = lwmqtt_read_char(&cur_ptr);
  if (header.bits.type != LWMQTT_SUBACK_PACKET) {
    return rc;
  }

  cur_ptr += (rc = lwmqtt_header_decode(cur_ptr, &len));  // read remaining length
  unsigned char *end_ptr = cur_ptr + len;
  if (end_ptr - cur_ptr < 2) {
    return rc;
  }

  *packet_id = (unsigned short)lwmqtt_read_int(&cur_ptr);

  *count = 0;
  while (cur_ptr < end_ptr) {
    if (*count > max_count) {
      return -1;
    }

    granted_qos_levels[(*count)++] = lwmqtt_read_char(&cur_ptr);
  }

  return 1;
}
