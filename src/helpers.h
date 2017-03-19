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
 * Returns the length of the string object.
 *
 * @param str - The string to return the length of.
 * @return The length of the string.
 */
int lwmqtt_strlen(lwmqtt_string_t str);

/**
 * Compares a string object to a c-string.
 *
 * @param a The string object to compare.
 * @param b The c string to compare.
 * @return Similarity e.g. strcmp().
 */
int lwmqtt_strcmp(lwmqtt_string_t *a, char *b);

/**
 * Reads a string object from the buffer and populates the passed structure.
 *
 * @param str The structure into which the data is to be read.
 * @param pptr Pointer to the output buffer - incremented by the number of bytes used & returned.
 * @param end_ptr Pointer to the end of the data: do not read beyond.
 * @return One if successful, zero if not.
 */
int lwmqtt_read_lp_string(lwmqtt_string_t *str, unsigned char **pptr, unsigned char *end_ptr);

/**
 * Writes a string to an output buffer.
 *
 * @param pptr Pointer to the output buffer - incremented by the number of bytes used & returned.
 * @param The c-string to write.
 */
void lwmqtt_write_c_string(unsigned char **pptr, const char *string);

/**
 * Writes a string to an output buffer.
 *
 * @param pptr Pointer to the output buffer - incremented by the number of bytes used & returned.
 * @param The c-string to write.
 */
void lwmqtt_write_string(unsigned char **pptr, lwmqtt_string_t string);

/**
 * Calculates an integer from two bytes read from the input buffer.
 *
 * @param pptr Pointer to the input buffer - incremented by the number of bytes used & returned.
 * @return The integer value calculated.
 */
int lwmqtt_read_int(unsigned char **pptr);

/**
 * Reads one character from the input buffer.
 *
 * @param pptr Pointer to the input buffer - incremented by the number of bytes used & returned.
 * @return The character read.
 */
unsigned char lwmqtt_read_char(unsigned char **pptr);

/**
 * Writes one character to an output buffer.
 *
 * @param pptr Pointer to the output buffer - incremented by the number of bytes used & returned.
 * @param chr The character to write
 */
void lwmqtt_write_char(unsigned char **pptr, unsigned char chr);

/**
 * Writes an integer as 2 bytes to an output buffer.
 *
 * @param pptr Pointer to the output buffer - incremented by the number of bytes used & returned.
 * @param num The integer to write.
 */
void lwmqtt_write_int(unsigned char **pptr, int num);

#endif
