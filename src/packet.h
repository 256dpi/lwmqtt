#ifndef LWMQTT_PACKET_H
#define LWMQTT_PACKET_H

// TODO: Err should be returned by all functions.

// TODO: Make sure all functions properly propagate the errors.

typedef enum {
  LWMQTT_SUCCESS = 0,
  LWMQTT_FAILURE = -1,
  LWMQTT_BUFFER_TOO_SHORT_ERROR = -2,
  LWMQTT_REMAINING_LENGTH_OVERFLOW = -3,
  LWMQTT_LENGTH_MISMATCH = -4
} lwmqtt_err_t;

typedef enum { LWMQTT_QOS0, LWMQTT_QOS1, LWMQTT_QOS2 } lwmqtt_qos_t;

typedef enum {
  LWMQTT_CONNECT_PACKET = 1,
  LWMQTT_CONNACK_PACKET,
  LWMQTT_PUBLISH_PACKET,
  LWMQTT_PUBACK_PACKET,
  LWMQTT_PUBREC_PACKET,
  LWMQTT_PUBREL_PACKET,
  LWMQTT_PUBCOMP_PACKET,
  LWMQTT_SUBSCRIBE_PACKET,
  LWMQTT_SUBACK_PACKET,
  LWMQTT_UNSUBSCRIBE_PACKET,
  LWMQTT_UNSUBACK_PACKET,
  LWMQTT_PINGREQ_PACKET,
  LWMQTT_PINGRESP_PACKET,
  LWMQTT_DISCONNECT_PACKET,
} lwmqtt_packet_type_t;

/**
 * Bitfields for the MQTT header byte.
 */
typedef union {
  unsigned char byte;
  struct {
    unsigned int retain : 1;
    unsigned int qos : 2;
    unsigned int dup : 1;
    unsigned int type : 4;
  } bits;
} lwmqtt_header_t;

int lwmqtt_total_header_length(int rem_len);

/**
 * Encodes the message length according to the MQTT algorithm
 *
 * @param buf the buffer into which the encoded data is written
 * @param rem_len the length to be encoded
 * @return the number of bytes written to buffer
 */
int lwmqtt_encode_remaining_length(unsigned char *buf, int rem_len);

int lwmqtt_decode_remaining_length(unsigned char *buf, int *rem_len);

#endif  // LWMQTT_PACKET_H
