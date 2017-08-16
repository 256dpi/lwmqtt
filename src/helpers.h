#ifndef LWMQTT_HELPERS_H
#define LWMQTT_HELPERS_H

#include <stdbool.h>

#include <lwmqtt.h>

/**
 * Reads a string from the specified buffer into the passed object. The pointer is incremented by the bytes read.
 *
 * @param str - The object into which the data is to be read.
 * @param buf - Pointer to the buffer.
 * @param buf_end - Pointer to the end of the buffer.
 * @return One if successful, zero if not.
 */
bool lwmqtt_read_string(lwmqtt_string_t *str, void **buf, void *buf_end);

/**
 * Writes a string to the specified buffer. The pointer is incremented by the bytes written.
 *
 * @param pptr - Pointer to the buffer.
 * @param The string to write.
 */
void lwmqtt_write_string(void **pptr, lwmqtt_string_t string);

/**
 * Reads a two bytes as a number from the specified buffer. The pointer is incremented by two.
 *
 * @param buf - Pointer to the buffer.
 * @return The read number.
 */
int lwmqtt_read_num(void **buf);

/**
 * Writes a number in two bytes to the specified buffer. The pointer is incremented by two.
 *
 * @param pptr - Pointer to the buffer.
 * @param The number to write.
 */
void lwmqtt_write_num(void **pptr, int num);

/**
 * Reads one byte from the buffer. The pointer is incremented by one.
 *
 * @param buf - Pointer to the buffer.
 * @return The read byte.
 */
unsigned char lwmqtt_read_byte(void **buf);

/**
 * Writes one byte to the specified buffer. The pointer is incremented by one.
 *
 * @param buf - Pointer to the buffer.
 * @param The byte to write.
 */
void lwmqtt_write_byte(void **buf, unsigned char chr);

/**
 * Reads a variable number from the specified buffer. The pointer is incremented by the bytes read.
 *
 * @param buf - Pointer to the buffer.
 * @param buf_len - The length of the buffer.
 * @return Length if successful, -1 if buffer is to short and -2 if overflowed.
 */
int lwmqtt_read_varnum(void **buf, int buf_len);

/**
 * Writes a variable number to the specified buffer. The pointer is incremented by the bytes written.
 *
 * @param buf - Pointer to the buffer.
 * @param buf_len - The length of the buffer.
 * @param num - The number to write.
 * @return Zero if successful, -1 if buffer is to short and -2 if overflowed.
 */
int lwmqtt_write_varnum(void **buf, int buf_len, int num);

#endif
