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
  unsigned char *curdata = buf;
  int rc = 0;
  int mylen;

  header.byte = lwmqtt_read_char(&curdata);
  *dup = header.bits.dup;
  *packet_type = header.bits.type;

  curdata += (rc = lwmqtt_header_decode(curdata, &mylen));  // read remaining length
  unsigned char *enddata = curdata + mylen;

  if (enddata - curdata < 2) {
    return rc;
  }

  *packet_id = lwmqtt_read_int(&curdata);

  return 1;
}

int lwmqtt_serialize_identified(unsigned char *buf, int buf_len, unsigned char packettype, unsigned char dup,
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

  ptr += lwmqtt_header_encode(ptr, 2);  // write remaining length
  lwmqtt_write_int(&ptr, packet_id);

  return ptr - buf;
}
