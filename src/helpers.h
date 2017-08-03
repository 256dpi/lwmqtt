#ifndef LWMQTT_HELPERS_H
#define LWMQTT_HELPERS_H

#include <stdbool.h>

#include <lwmqtt.h>

/**
 * Reads a string object from the buffer and populates the passed object.
 *
 * @param str - The object into which the data is to be read.
 * @param pptr - Pointer to the output buffer - incremented by the number of bytes used & returned.
 * @param end_ptr - Pointer to the end of the data: do not read beyond.
 * @return One if successful, zero if not.
 */
bool lwmqtt_read_string(lwmqtt_string_t *str, void **pptr, void *end_ptr);

/**
 * Writes a string to an output buffer.
 *
 * @param pptr - Pointer to the output buffer - incremented by the number of bytes used & returned.
 * @param The string to write.
 */
void lwmqtt_write_string(void **pptr, lwmqtt_string_t string);

/**
 * Calculates an integer from two bytes read from the input buffer.
 *
 * @param pptr - Pointer to the input buffer - incremented by the number of bytes used & returned.
 * @return The integer value calculated.
 */
int lwmqtt_read_int(void **pptr);

/**
 * Writes an integer as 2 bytes to an output buffer.
 *
 * @param pptr - Pointer to the output buffer - incremented by the number of bytes used & returned.
 * @param The integer to write.
 */
void lwmqtt_write_int(void **pptr, int num);

/**
 * Reads one character from the input buffer.
 *
 * @param pptr - Pointer to the input buffer - incremented by the number of bytes used & returned.
 * @return The character read.
 */
unsigned char lwmqtt_read_char(void **pptr);

/**
 * Writes one character to an output buffer.
 *
 * @param pptr - Pointer to the output buffer - incremented by the number of bytes used & returned.
 * @param The character to write
 */
void lwmqtt_write_char(void **pptr, unsigned char chr);

/**
 * Reads a variable number from the input buffer.
 *
 * @param pptr - Pointer to the input buffer - incremented by the number of bytes used & returned.
 * @param size - The size of the referenced input buffer.
 * @return Length if successful, -1 if buffer is to short and -2 if overflowed.
 */
int lwmqtt_read_varnum(void **pptr, int size);

/**
 * Writes a variable number to an output buffer. The output buffer must be at least 4 bytes in size.
 *
 * @param pptr - Pointer to the output buffer - incremented by the number of bytes used & returned.
 * @param num The number to write.
 */
void lwmqtt_write_varnum(void **pptr, int num);

#endif
