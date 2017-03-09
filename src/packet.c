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
 *
 * Contributors:
 *    Ian Craggs - initial API and implementation and/or initial documentation
 *    Sergio R. Caprile - non-blocking packet read functions for stream transport
 *******************************************************************************/

#include <string.h>

#include "packet.h"

/**
 * Encodes the message length according to the MQTT algorithm
 * @param buf the buffer into which the encoded data is written
 * @param length the length to be encoded
 * @return the number of bytes written to buffer
 */
int lwmqtt_packet_encode(unsigned char *buf, int length) {
  int rc = 0;

  do {
    char d = length % 128;
    length /= 128;
    /* if there are more digits to encode, set the top bit of this digit */
    if (length > 0) d |= 0x80;
    buf[rc++] = d;
  } while (length > 0);

  return rc;
}

/**
 * Decodes the message length according to the MQTT algorithm
 * @param getcharfn pointer to function to read the next character from the data source
 * @param value the decoded length returned
 * @return the number of bytes read from the socket
 */
int lwmqtt_packet_decode(int (*getcharfn)(unsigned char *, int), int *value) {
  unsigned char c;
  int multiplier = 1;
  int len = 0;
#define MAX_NO_OF_REMAINING_LENGTH_BYTES 4

  *value = 0;
  do {
    int rc = MQTTPACKET_READ_ERROR;

    if (++len > MAX_NO_OF_REMAINING_LENGTH_BYTES) {
      rc = MQTTPACKET_READ_ERROR; /* bad data */
      goto exit;
    }
    rc = (*getcharfn)(&c, 1);
    if (rc != 1) goto exit;
    *value += (c & 127) * multiplier;
    multiplier *= 128;
  } while ((c & 128) != 0);
exit:
  return len;
}

int lwmqtt_packet_len(int rem_len) {
  rem_len += 1; /* header byte */

  /* now remaining_length field */
  if (rem_len < 128)
    rem_len += 1;
  else if (rem_len < 16384)
    rem_len += 2;
  else if (rem_len < 2097151)
    rem_len += 3;
  else
    rem_len += 4;
  return rem_len;
}

static unsigned char* bufptr;

int bufchar(unsigned char* c, int count) {
  int i;

  for (i = 0; i < count; ++i) *c = *bufptr++;
  return count;
}

int lwmqtt_packet_decode_buf(unsigned char *buf, int *value) {
  bufptr = buf;
  return lwmqtt_packet_decode(bufchar, value);
}

/**
 * Calculates an integer from two bytes read from the input buffer
 * @param pptr pointer to the input buffer - incremented by the number of bytes used & returned
 * @return the integer value calculated
 */
int lwmqtt_read_int(unsigned char **pptr) {
  unsigned char* ptr = *pptr;
  int len = 256 * (*ptr) + (*(ptr + 1));
  *pptr += 2;
  return len;
}

/**
 * Reads one character from the input buffer.
 * @param pptr pointer to the input buffer - incremented by the number of bytes used & returned
 * @return the character read
 */
char lwmqtt_read_char(unsigned char **pptr) {
  char c = **pptr;
  (*pptr)++;
  return c;
}

/**
 * Writes one character to an output buffer.
 * @param pptr pointer to the output buffer - incremented by the number of bytes used & returned
 * @param c the character to write
 */
void lwmqtt_write_char(unsigned char **pptr, char c) {
  **pptr = c;
  (*pptr)++;
}

/**
 * Writes an integer as 2 bytes to an output buffer.
 * @param pptr pointer to the output buffer - incremented by the number of bytes used & returned
 * @param anInt the integer to write
 */
void lwmqtt_write_int(unsigned char **pptr, int anInt) {
  **pptr = (unsigned char)(anInt / 256);
  (*pptr)++;
  **pptr = (unsigned char)(anInt % 256);
  (*pptr)++;
}

/**
 * Writes a "UTF" string to an output buffer.  Converts C string to length-delimited.
 * @param pptr pointer to the output buffer - incremented by the number of bytes used & returned
 * @param string the C string to write
 */
void lwmqtt_write_c_string(unsigned char **pptr, const char *string) {
  int len = strlen(string);
  lwmqtt_write_int(pptr, len);
  memcpy(*pptr, string, len);
  *pptr += len;
}

int getLenStringLen(char* ptr) {
  int len = 256 * ((unsigned char)(*ptr)) + (unsigned char)(*(ptr + 1));
  return len;
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

/**
 * @param mqttstring the MQTTString structure into which the data is to be read
 * @param pptr pointer to the output buffer - incremented by the number of bytes used & returned
 * @param enddata pointer to the end of the data: do not read beyond
 * @return 1 if successful, 0 if not
 */
int lwmqtt_read_lp_string(lwmqtt_string_t *mqttstring, unsigned char **pptr, unsigned char *enddata) {
  int rc = 0;

  /* the first two bytes are the length of the string */
  if (enddata - (*pptr) > 1) /* enough length to read the integer? */
  {
    mqttstring->lenstring.len = lwmqtt_read_int(pptr); /* increments pptr to point past length */
    if (&(*pptr)[mqttstring->lenstring.len] <= enddata) {
      mqttstring->lenstring.data = (char*)*pptr;
      *pptr += mqttstring->lenstring.len;
      rc = 1;
    }
  }
  mqttstring->cstring = NULL;

  return rc;
}

/**
 * Return the length of the MQTTstring - C string if there is one, otherwise the length delimited string
 * @param mqttstring the string to return the length of
 * @return the length of the string
 */
int lwmqtt_strlen(lwmqtt_string_t mqttstring) {
  int rc = 0;

  if (mqttstring.cstring)
    rc = strlen(mqttstring.cstring);
  else
    rc = mqttstring.lenstring.len;
  return rc;
}

/**
 * Compares an MQTTString to a C string
 * @param a the MQTTString to compare
 * @param bptr the C string to compare
 * @return boolean - equal or not
 */
int lwmqtt_strcmp(lwmqtt_string_t *a, char *bptr) {
  int alen = 0, blen = 0;
  char* aptr;

  if (a->cstring) {
    aptr = a->cstring;
    alen = strlen(a->cstring);
  } else {
    aptr = a->lenstring.data;
    alen = a->lenstring.len;
  }
  blen = strlen(bptr);

  return (alen == blen) && (strncmp(aptr, bptr, alen) == 0);
}
