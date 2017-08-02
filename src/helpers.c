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
