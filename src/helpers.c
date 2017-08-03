#include <string.h>

#include "helpers.h"

lwmqtt_string_t lwmqtt_str(const char *str) { return (lwmqtt_string_t){(int)strlen(str), (char *)str}; }

int lwmqtt_strcmp(lwmqtt_string_t *a, const char *b) {
  // get length of b
  size_t len = strlen(b);

  // otherwise check if length matches
  if (len != a->len) {
    return -1;
  }

  // compare memory
  return strncmp(a->data, b, len);
}

bool lwmqtt_read_string(lwmqtt_string_t *str, void **pptr, void *end_ptr) {
  // check if at lest 2 bytes
  if (end_ptr - (*pptr) <= 1) {
    return false;
  }

  // read length
  int len = lwmqtt_read_int(pptr);

  // check if string end is overflowing the end pointer
  if (&(*pptr)[len] > end_ptr) {
    return false;
  }

  // set string
  str->len = len;
  str->data = (char *)*pptr;

  // advance pointer
  *pptr += str->len;

  return true;
}

void lwmqtt_write_string(void **pptr, lwmqtt_string_t string) {
  // write length prefixed string if length is given
  if (string.len > 0) {
    lwmqtt_write_int(pptr, string.len);
    memcpy(*pptr, string.data, string.len);
    *pptr += string.len;
    return;
  }

  // write zero
  lwmqtt_write_int(pptr, 0);
}

int lwmqtt_read_int(void **pptr) {
  // get array
  unsigned char *ary = *pptr;

  // read two byte integer
  int num = 256 * ary[0] + ary[1];

  // adjust pointer
  *pptr += 2;

  return num;
}

void lwmqtt_write_int(void **pptr, int num) {
  // get array
  unsigned char *ary = *pptr;

  // write bytes
  ary[0] = (unsigned char)(num / 256);
  ary[1] = (unsigned char)(num % 256);

  // adjust pointer
  *pptr += 2;
}

unsigned char lwmqtt_read_char(void **pptr) {
  // get array
  unsigned char *ary = *pptr;

  // adjust pointer
  *pptr += 1;

  return ary[0];
}

void lwmqtt_write_char(void **pptr, unsigned char chr) {
  // get array
  unsigned char *ary = *pptr;

  // write single char
  *ary = chr;

  // adjust pointer
  *pptr += 1;
}

int lwmqtt_read_varnum(void **pptr, int size) {
  // get array
  unsigned char *ary = *pptr;

  // prepare last digit
  unsigned char digit;

  // prepare multiplier
  int multiplier = 1;

  // prepare length
  int len = 0;

  // initialize number
  int num = 0;

  // decode variadic number
  do {
    // increment length
    len++;

    // return error if buffer is to small
    if (size < len) {
      return -1;
    }

    // return error if the length has overflowed
    if (len > 4) {
      return -2;
    }

    // read digit
    digit = ary[len - 1];

    // add digit to number
    num += (digit & 127) * multiplier;

    // increase multiplier
    multiplier *= 128;
  } while ((digit & 128) != 0);

  // adjust pointer
  *pptr += len;

  return num;
}

int lwmqtt_write_varnum(void **pptr, int size, int num) {
  // get array
  unsigned char *ary = *pptr;

  // init len counter
  int len = 0;

  // encode variadic number
  do {
    // return error if buffer is to small
    if (size < len) {
      return -1;
    }

    // return error if the length has overflowed
    if (len > 4) {
      return -2;
    }

    // calculate current digit
    unsigned char digit = (unsigned char)(num % 128);

    // change remaining length
    num /= 128;

    // set the top bit of this digit if there are more to encode
    if (num > 0) {
      digit |= 0x80;
    }

    // write digit
    ary[len++] = digit;
  } while (num > 0);

  // adjust pointer
  *pptr += len;

  return 0;
}
