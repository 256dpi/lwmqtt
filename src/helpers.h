#ifndef LWMQTT_HELPERS_H
#define LWMQTT_HELPERS_H

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
 * Return the length of the length prefixed string or C string if there is one, otherwise the length delimited string
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
 * @param str the length prefixed string structure into which the data is to be read
 * @param pptr pointer to the output buffer - incremented by the number of bytes used & returned
 * @param end_ptr pointer to the end of the data: do not read beyond
 * @return 1 if successful, 0 if not
 */
int lwmqtt_read_lp_string(lwmqtt_string_t *str, unsigned char **pptr, unsigned char *end_ptr);

/**
 * Writes a "UTF" string to an output buffer.  Converts C string to length-delimited.
 *
 * @param pptr pointer to the output buffer - incremented by the number of bytes used & returned
 * @param string the C string to write
 */
void lwmqtt_write_c_string(unsigned char **pptr, const char *string);

void lwmqtt_write_string(unsigned char **pptr, lwmqtt_string_t string);

/**
 * Calculates an integer from two bytes read from the input buffer
 *
 * @param pptr pointer to the input buffer - incremented by the number of bytes used & returned
 * @return the integer value calculated
 */
int lwmqtt_read_int(unsigned char **pptr);

/**
 * Reads one character from the input buffer.
 *
 * @param pptr pointer to the input buffer - incremented by the number of bytes used & returned
 * @return the character read
 */
unsigned char lwmqtt_read_char(unsigned char **pptr);

/**
 * Writes one character to an output buffer.
 *
 * @param pptr pointer to the output buffer - incremented by the number of bytes used & returned
 * @param chr the character to write
 */
void lwmqtt_write_char(unsigned char **pptr, unsigned char chr);

/**
 * Writes an integer as 2 bytes to an output buffer.
 *
 * @param pptr pointer to the output buffer - incremented by the number of bytes used & returned
 * @param num the integer to write
 */
void lwmqtt_write_int(unsigned char **pptr, int num);

#endif
