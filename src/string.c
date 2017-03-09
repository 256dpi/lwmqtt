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

int lwmqtt_strlen(lwmqtt_string_t mqttstring) {
  int rc = 0;

  if (mqttstring.cstring)
    rc = (int)strlen(mqttstring.cstring);
  else
    rc = mqttstring.lenstring.len;
  return rc;
}

int lwmqtt_strcmp(lwmqtt_string_t *a, char *bptr) {
  int alen = 0, blen = 0;
  char *aptr;

  if (a->cstring) {
    aptr = a->cstring;
    alen = (int)strlen(a->cstring);
  } else {
    aptr = a->lenstring.data;
    alen = a->lenstring.len;
  }
  blen = (int)strlen(bptr);

  return (alen == blen) && (strncmp(aptr, bptr, alen) == 0);
}

void lwmqtt_write_c_string(unsigned char **pptr, const char *string) {
  int len = (int)strlen(string);
  lwmqtt_write_int(pptr, len);
  memcpy(*pptr, string, len);
  *pptr += len;
}

void lwmqtt_write_string(unsigned char **pptr, lwmqtt_string_t mqttstring) {
  if (mqttstring.lenstring.len > 0) {
    lwmqtt_write_int(pptr, mqttstring.lenstring.len);
    memcpy(*pptr, mqttstring.lenstring.data, mqttstring.lenstring.len);
    *pptr += mqttstring.lenstring.len;
  } else if (mqttstring.cstring)
    lwmqtt_write_c_string(pptr, mqttstring.cstring);
  else
    lwmqtt_write_int(pptr, 0);
}

int lwmqtt_read_lp_string(lwmqtt_string_t *mqttstring, unsigned char **pptr, unsigned char *enddata) {
  int rc = 0;

  /* the first two bytes are the length of the string */
  if (enddata - (*pptr) > 1) /* enough length to read the integer? */
  {
    mqttstring->lenstring.len = lwmqtt_read_int(pptr); /* increments pptr to point past length */
    if (&(*pptr)[mqttstring->lenstring.len] <= enddata) {
      mqttstring->lenstring.data = (char *)*pptr;
      *pptr += mqttstring->lenstring.len;
      rc = 1;
    }
  }
  mqttstring->cstring = NULL;

  return rc;
}
