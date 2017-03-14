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

#include "unsubscribe.h"
#include "helpers.h"
#include "packet.h"

static int lwmqtt_serialize_unsubscribe_length(int count, lwmqtt_string_t *topicFilters) {
  int len = 2;  // packet id

  for (int i = 0; i < count; ++i) {
    len += 2 + lwmqtt_strlen(topicFilters[i]);  // length + topic
  }

  return len;
}

int lwmqtt_serialize_unsubscribe(unsigned char *buf, int buf_len, unsigned char dup, unsigned short packet_id,
                                 int count, lwmqtt_string_t *topic_filters) {
  unsigned char *ptr = buf;
  lwmqtt_header_t header = {0};
  int rem_len = 0;

  if (lwmqtt_header_len(rem_len = lwmqtt_serialize_unsubscribe_length(count, topic_filters)) > buf_len) {
    return LWMQTT_BUFFER_TOO_SHORT;
  }

  header.byte = 0;
  header.bits.type = LWMQTT_UNSUBSCRIBE_PACKET;
  header.bits.dup = dup;
  header.bits.qos = 1;
  lwmqtt_write_char(&ptr, header.byte);  // write header

  ptr += lwmqtt_header_encode(ptr, rem_len);  // write remaining length

  lwmqtt_write_int(&ptr, packet_id);

  for (int i = 0; i < count; ++i) {
    lwmqtt_write_string(&ptr, topic_filters[i]);
  }

  return ptr - buf;
}

int lwmqtt_deserialize_unsuback(unsigned short *packet_id, unsigned char *buf, int buf_len) {
  unsigned char type = 0;
  unsigned char dup = 0;

  int rc = lwmqtt_deserialize_ack(&type, &dup, packet_id, buf, buf_len);
  if (type == LWMQTT_UNSUBACK_PACKET) {
    rc = 1;
  }

  return rc;
}
