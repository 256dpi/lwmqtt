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
#include "packet.h"

static int lwmqtt_serialize_unsubscribe_length(int count, lwmqtt_string_t *topicFilters) {
  int i;
  int len = 2; /* packet id */

  for (i = 0; i < count; ++i) len += 2 + lwmqtt_strlen(topicFilters[i]); /* length + topic*/
  return len;
}

int lwmqtt_serialize_unsubscribe(unsigned char *buf, int buflen, unsigned char dup, unsigned short packetid, int count,
                                 lwmqtt_string_t *topicFilters) {
  unsigned char *ptr = buf;
  lwmqtt_header_t header = {0};
  int rem_len = 0;
  int i = 0;

  if (lwmqtt_packet_len(rem_len = lwmqtt_serialize_unsubscribe_length(count, topicFilters)) > buflen) {
    return MQTTPACKET_BUFFER_TOO_SHORT;
  }

  header.byte = 0;
  header.bits.type = UNSUBSCRIBE;
  header.bits.dup = dup;
  header.bits.qos = 1;
  lwmqtt_write_char(&ptr, header.byte); /* write header */

  ptr += lwmqtt_packet_encode(ptr, rem_len); /* write remaining length */
  ;

  lwmqtt_write_int(&ptr, packetid);

  for (i = 0; i < count; ++i) lwmqtt_write_string(&ptr, topicFilters[i]);

  return ptr - buf;
}

int lwmqtt_deserialize_unsuback(unsigned short *packetid, unsigned char *buf, int buflen) {
  unsigned char type = 0;
  unsigned char dup = 0;
  int rc = 0;

  rc = lwmqtt_deserialize_ack(&type, &dup, packetid, buf, buflen);
  if (type == UNSUBACK) rc = 1;

  return rc;
}
