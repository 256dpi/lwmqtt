#include <string.h>

#include "helpers.h"

int lwmqtt_strlen(lwmqtt_string_t str) {
  if (str.c_string) {
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
  return strncmp(a->lp_string.data, b, len);
}

void lwmqtt_write_c_string(unsigned char **pptr, const char *string) {
  int len = (int)strlen(string);
  lwmqtt_write_int(pptr, len);
  memcpy(*pptr, string, len);
  *pptr += len;
}

void lwmqtt_write_string(unsigned char **pptr, lwmqtt_string_t string) {
  if (string.lp_string.len > 0) {
    lwmqtt_write_int(pptr, string.lp_string.len);
    memcpy(*pptr, string.lp_string.data, string.lp_string.len);
    *pptr += string.lp_string.len;
  } else if (string.c_string) {
    lwmqtt_write_c_string(pptr, string.c_string);
  } else {
    lwmqtt_write_int(pptr, 0);
  }
}

int lwmqtt_read_lp_string(lwmqtt_string_t *str, unsigned char **pptr, unsigned char *end_ptr) {
  int rc = 0;

  // the first two bytes are the length of the string
  if (end_ptr - (*pptr) > 1) {                   // enough length to read the integer?
    str->lp_string.len = lwmqtt_read_int(pptr);  // increments pptr to point past length
    if (&(*pptr)[str->lp_string.len] <= end_ptr) {
      str->lp_string.data = (char *)*pptr;
      *pptr += str->lp_string.len;
      rc = 1;
    }
  }

  str->c_string = NULL;

  return rc;
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
