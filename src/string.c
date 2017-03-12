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

#include <string.h>

#include "packet.h"
#include "string.h"

int lwmqtt_strlen(lwmqtt_string_t str) {
  int rc = 0;

  if (str.c_string)
    rc = (int)strlen(str.c_string);
  else
    rc = str.lp_string.len;
  return rc;
}

int lwmqtt_strcmp(lwmqtt_string_t *a, char *b) {
  // check strings directly
  if (a->c_string != NULL) {
    return strcmp(a->c_string, b);
  }

  // get length of b
  size_t len = strlen(b);

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
  } else if (string.c_string)
    lwmqtt_write_c_string(pptr, string.c_string);
  else
    lwmqtt_write_int(pptr, 0);
}

int lwmqtt_read_lp_string(lwmqtt_string_t *str, unsigned char **pptr, unsigned char *enddata) {
  int rc = 0;

  /* the first two bytes are the length of the string */
  if (enddata - (*pptr) > 1) /* enough length to read the integer? */
  {
    str->lp_string.len = lwmqtt_read_int(pptr); /* increments pptr to point past length */
    if (&(*pptr)[str->lp_string.len] <= enddata) {
      str->lp_string.data = (char *)*pptr;
      *pptr += str->lp_string.len;
      rc = 1;
    }
  }
  str->c_string = NULL;

  return rc;
}
