#ifndef LWMQTT_HELPERS_H
#define LWMQTT_HELPERS_H

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
