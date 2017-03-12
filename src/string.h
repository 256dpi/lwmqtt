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

#ifndef LWMQTT_STRING_H
#define LWMQTT_STRING_H

typedef struct {
  int len;
  char *data;
} lwmqtt_lp_string_t;

typedef struct {
  char *c_string;
  lwmqtt_lp_string_t lp_string;
} lwmqtt_string_t;

#define lwmqtt_default_string \
  {                           \
    NULL, { 0, NULL }         \
  }

/**
 * Return the length of the MQTTstring - C string if there is one, otherwise the length delimited string
 *
 * @param str the string to return the length of
 * @return the length of the string
 */
int lwmqtt_strlen(lwmqtt_string_t str);

/**
 * Compares an MQTTString to a C string
 *
 * @param a the MQTTString to compare
 * @param b the C string to compare
 * @return boolean - equal or not
 */
int lwmqtt_strcmp(lwmqtt_string_t *a, char *b);

/**
 * ???
 *
 * @param str the MQTTString structure into which the data is to be read
 * @param pptr pointer to the output buffer - incremented by the number of bytes used & returned
 * @param enddata pointer to the end of the data: do not read beyond
 * @return 1 if successful, 0 if not
 */
int lwmqtt_read_lp_string(lwmqtt_string_t *str, unsigned char **pptr, unsigned char *enddata);

/**
 * Writes a "UTF" string to an output buffer.  Converts C string to length-delimited.
 *
 * @param pptr pointer to the output buffer - incremented by the number of bytes used & returned
 * @param string the C string to write
 */
void lwmqtt_write_c_string(unsigned char **pptr, const char *string);

void lwmqtt_write_string(unsigned char **pptr, lwmqtt_string_t string);

#endif  // LWMQTT_STRING_H
