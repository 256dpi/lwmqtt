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

#include "packet.h"

int lwmqtt_header_encode(unsigned char *buf, int rem_len) {
  int rc = 0;

  do {
    char d = rem_len % 128;
    rem_len /= 128;
    // if there are more digits to encode, set the top bit of this digit
    if (rem_len > 0) d |= 0x80;
    buf[rc++] = d;
  } while (rem_len > 0);

  return rc;
}

int lwmqtt_header_len(int rem_len) {
  int len = 1; // header byte

  if (rem_len < 128) {
    return len + 1;
  } else if (rem_len < 16384) {
    return len + 2;
  } else if (rem_len < 2097151) {
    return len + 3;
  } else {
    return len + 4;
  }
}

int lwmqtt_header_decode(unsigned char *buf, int *rem_len) {
  unsigned char c;
  int multiplier = 1;
  int len = 0;

  *rem_len = 0;
  do {
    len++;

    if (len > 4) {
      return LWMQTT_READ_ERROR;  // bad data
    }

    c = buf[len - 1];

    *rem_len += (c & 127) * multiplier;
    multiplier *= 128;
  } while ((c & 128) != 0);

  return len;
}
