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
  int i;
  int len = 2; /* packet id */

  for (i = 0; i < count; ++i) len += 2 + lwmqtt_strlen(topicFilters[i]) + 1; /* length + topic + req_qos */
  return len;
}

int lwmqtt_serialize_subscribe(unsigned char *buf, int buflen, unsigned char dup, unsigned short packetid, int count,
                               lwmqtt_string_t *topicFilters, int *requestedQoSs) {
  unsigned char *ptr = buf;
  lwmqtt_header_t header = {0};
  int rem_len = 0;
  int rc = 0;
  int i = 0;

  if (lwmqtt_packet_len(rem_len = lwmqtt_serialize_subscribe_length(count, topicFilters)) > buflen) {
    rc = MQTTPACKET_BUFFER_TOO_SHORT;
    return rc;
  }

  header.byte = 0;
  header.bits.type = SUBSCRIBE;
  header.bits.dup = dup;
  header.bits.qos = 1;
  lwmqtt_write_char(&ptr, header.byte); /* write header */

  ptr += lwmqtt_packet_encode(ptr, rem_len); /* write remaining length */
  ;

  lwmqtt_write_int(&ptr, packetid);

  for (i = 0; i < count; ++i) {
    lwmqtt_write_string(&ptr, topicFilters[i]);
    lwmqtt_write_char(&ptr, requestedQoSs[i]);
  }

  return ptr - buf;
}

int lwmqtt_deserialize_suback(unsigned short *packetid, int maxcount, int *count, int *grantedQoSs, unsigned char *buf,
                              int buflen) {
  lwmqtt_header_t header = {0};
  unsigned char *curdata = buf;
  unsigned char *enddata = NULL;
  int rc = 0;
  int mylen;

  header.byte = lwmqtt_read_char(&curdata);
  if (header.bits.type != SUBACK) return rc;

  curdata += (rc = lwmqtt_packet_decode_buf(curdata, &mylen)); /* read remaining length */
  enddata = curdata + mylen;
  if (enddata - curdata < 2) return rc;

  *packetid = lwmqtt_read_int(&curdata);

  *count = 0;
  while (curdata < enddata) {
    if (*count > maxcount) {
      return -1;
    }
    grantedQoSs[(*count)++] = lwmqtt_read_char(&curdata);
  }

  return 1;
}
