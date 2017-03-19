#include "packet.h"

int lwmqtt_encode_remaining_length(unsigned char *buf, int rem_len) {
  int rc = 0;

  do {
    unsigned char d = (unsigned char)(rem_len % 128);
    rem_len /= 128;
    // if there are more digits to encode, set the top bit of this digit
    if (rem_len > 0) d |= 0x80;
    buf[rc++] = d;
  } while (rem_len > 0);

  return rc;
}

int lwmqtt_total_header_length(int rem_len) {
  int len = 1;  // header byte

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

// TODO: Increment pointer directly?
int lwmqtt_decode_remaining_length(unsigned char *buf, int *rem_len) {
  unsigned char c;
  int multiplier = 1;
  int len = 0;

  *rem_len = 0;
  do {
    len++;

    if (len > 4) {
      return LWMQTT_REMAINING_LENGTH_OVERFLOW;
    }

    c = buf[len - 1];

    *rem_len += (c & 127) * multiplier;
    multiplier *= 128;
  } while ((c & 128) != 0);

  return len;
}
