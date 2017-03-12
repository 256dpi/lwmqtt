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
 *    Xiang Rong - 442039 Add makefile to Embedded C client
 *******************************************************************************/

#ifndef LWMQTT_PACKET_H
#define LWMQTT_PACKET_H

enum errors { MQTTPACKET_BUFFER_TOO_SHORT = -2, MQTTPACKET_READ_ERROR = -1 };

enum msgTypes {
  CONNECT = 1,
  CONNACK,
  PUBLISH,
  PUBACK,
  PUBREC,
  PUBREL,
  PUBCOMP,
  SUBSCRIBE,
  SUBACK,
  UNSUBSCRIBE,
  UNSUBACK,
  PINGREQ,
  PINGRESP,
  DISCONNECT
};

/**
 * Bitfields for the MQTT header byte.
 */
typedef union {
  unsigned char byte; /**< the whole byte */
  struct {
    unsigned int retain : 1; /**< retained flag bit */
    unsigned int qos : 2;    /**< QoS value, 0, 1 or 2 */
    unsigned int dup : 1;    /**< DUP flag bit */
    unsigned int type : 4;   /**< message type nibble */
  } bits;
} lwmqtt_header_t;

/**
  * Serializes the ack packet into the supplied buffer.
  *
  * @param buf the buffer into which the packet will be serialized
  * @param buf_len the length in bytes of the supplied buffer
  * @param type the MQTT packet type
  * @param dup the MQTT dup flag
  * @param packet_id the MQTT packet identifier
  * @return serialized length, or error if 0
  */
int lwmqtt_serialize_ack(unsigned char *buf, int buf_len, unsigned char type, unsigned char dup,
                         unsigned short packet_id);

int lwmqtt_deserialize_ack(unsigned char *packet_type, unsigned char *dup, unsigned short *packet_id, unsigned char *buf,
                           int buf_len);

int lwmqtt_packet_len(int rem_len);

/**
 * Encodes the message length according to the MQTT algorithm
 *
 * @param buf the buffer into which the encoded data is written
 * @param length the length to be encoded
 * @return the number of bytes written to buffer
 */
int lwmqtt_packet_encode(unsigned char *buf, int length);

/**
 * Decodes the message length according to the MQTT algorithm
 *
 * @param get_char_fn pointer to function to read the next character from the data source
 * @param value the decoded length returned
 * @return the number of bytes read from the socket
 */
int lwmqtt_packet_decode(int (*get_char_fn)(unsigned char *, int), int *value);

int lwmqtt_packet_decode_buf(unsigned char *buf, int *value);

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
char lwmqtt_read_char(unsigned char **pptr);

/**
 * Writes one character to an output buffer.
 *
 * @param pptr pointer to the output buffer - incremented by the number of bytes used & returned
 * @param c the character to write
 */
void lwmqtt_write_char(unsigned char **pptr, char c);

/**
 * Writes an integer as 2 bytes to an output buffer.
 *
 * @param pptr pointer to the output buffer - incremented by the number of bytes used & returned
 * @param anInt the integer to write
 */
void lwmqtt_write_int(unsigned char **pptr, int anInt);

#endif  // LWMQTT_PACKET_H
