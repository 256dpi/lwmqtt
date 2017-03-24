#include <string.h>

#include "helpers.h"

int lwmqtt_strlen(lwmqtt_string_t str) {
  // return string length id not null
  if (str.c_string != NULL) {
    return (int)strlen(str.c_string);
  }

  return str.lp_string.len;
}

int lwmqtt_strcmp(lwmqtt_string_t *a, char *b) {
  // check strings directly
  if (a->c_string != NULL) {
    return strcmp(a->c_string, b);
  }

  // get length of b
  int len = (int)strlen(b);

  // otherwise check if length matches
  if (len != a->lp_string.len) {
    return -1;
  }

  // compare memory
  return strncmp(a->lp_string.data, b, (size_t)len);
}

void lwmqtt_write_c_string(unsigned char **pptr, const char *string) {
  // get length
  int len = (int)strlen(string);

  // write prefix
  lwmqtt_write_int(pptr, len);

  // write string
  memcpy(*pptr, string, len);

  // advance pointer
  *pptr += len;
}

void lwmqtt_write_string(unsigned char **pptr, lwmqtt_string_t string) {
  // write length prefixed string if length is given
  if (string.lp_string.len > 0) {
    lwmqtt_write_int(pptr, string.lp_string.len);
    memcpy(*pptr, string.lp_string.data, string.lp_string.len);
    *pptr += string.lp_string.len;
    return;
  }

  // write ordinary string if given
  if (string.c_string != NULL) {
    lwmqtt_write_c_string(pptr, string.c_string);
    return;
  }

  // write zero
  lwmqtt_write_int(pptr, 0);
}

bool lwmqtt_read_lp_string(lwmqtt_string_t *str, unsigned char **pptr, unsigned char *end_ptr) {
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
  str->c_string = NULL;
  str->lp_string.len = len;
  str->lp_string.data = (char *)*pptr;

  // advance pointer
  *pptr += str->lp_string.len;

  return true;
}

int lwmqtt_read_int(unsigned char **pptr) {
  // get pointer
  unsigned char *ptr = *pptr;

  // read two byte integer
  int num = 256 * (*ptr) + (*(ptr + 1));

  // adjust pointer
  *pptr += 2;

  return num;
}

unsigned char lwmqtt_read_char(unsigned char **pptr) {
  // read single char
  unsigned char chr = **pptr;

  // adjust pointer
  (*pptr)++;

  return chr;
}

void lwmqtt_write_char(unsigned char **pptr, unsigned char chr) {
  // write single char
  **pptr = chr;

  // adjust pointer
  (*pptr)++;
}

void lwmqtt_write_int(unsigned char **pptr, int num) {
  // write first byte
  **pptr = (unsigned char)(num / 256);

  // adjust pointer
  (*pptr)++;

  // write second byte
  **pptr = (unsigned char)(num % 256);

  // adjust pointer
  (*pptr)++;
}
