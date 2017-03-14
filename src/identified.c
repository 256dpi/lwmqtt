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

#include "helpers.h"
#include "packet.h"

int lwmqtt_deserialize_identified(unsigned char *packet_type, unsigned char *dup, unsigned short *packet_id,
                                  unsigned char *buf, int buf_len) {
  lwmqtt_header_t header = {0};
  unsigned char *cur_ptr = buf;
  int rc = 0;
  int len;

  header.byte = lwmqtt_read_char(&cur_ptr);
  *dup = (unsigned char)header.bits.dup;
  *packet_type = (unsigned char)header.bits.type;

  cur_ptr += (rc = lwmqtt_header_decode(cur_ptr, &len));  // read remaining length
  unsigned char *end_ptr = cur_ptr + len;

  if (end_ptr - cur_ptr < 2) {
    return rc;
  }

  *packet_id = (unsigned short)lwmqtt_read_int(&cur_ptr);

  return 1;
}

int lwmqtt_serialize_identified(unsigned char *buf, int buf_len, unsigned char packet_type, unsigned char dup,
                                unsigned short packet_id) {
  lwmqtt_header_t header = {0};
  unsigned char *ptr = buf;

  if (buf_len < 4) {
    return LWMQTT_BUFFER_TOO_SHORT;
  }

  header.bits.type = packet_type;
  header.bits.dup = dup;
  header.bits.qos = (packet_type == LWMQTT_PUBREL_PACKET) ? 1 : 0;
  lwmqtt_write_char(&ptr, header.byte);  // write header

  ptr += lwmqtt_header_encode(ptr, 2);  // write remaining length
  lwmqtt_write_int(&ptr, packet_id);

  return (int)(ptr - buf);
}
