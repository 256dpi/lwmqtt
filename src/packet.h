#ifndef LWMQTT_PACKET_H
#define LWMQTT_PACKET_H

#include <stdbool.h>

#include "helpers.h"

/**
 * The used error codes.
 */
typedef enum {
  LWMQTT_SUCCESS = 0,
  LWMQTT_FAILURE = -1,
  LWMQTT_BUFFER_TOO_SHORT = -2,
  LWMQTT_REMAINING_LENGTH_OVERFLOW = -3,
  LWMQTT_LENGTH_MISMATCH = -4,
  LWMQTT_NO_DATA = -5,
  LWMQTT_NOT_ENOUGH_DATA = -6
} lwmqtt_err_t;

/**
 * The available QOS levels.
 */
typedef enum { LWMQTT_QOS0 = 0, LWMQTT_QOS1 = 1, LWMQTT_QOS2 = 2 } lwmqtt_qos_t;

/**
 * The available packet types.
 */
typedef enum {
  LWMQTT_NO_PACKET = -1,
  LWMQTT_INVALID_PACKET = 0,
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
  LWMQTT_DISCONNECT_PACKET
} lwmqtt_packet_t;

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

/**
 * Will detect the packet type from the at least one byte long buffer.
 *
 * If the packet cannot be received by a client, LWMQTT_INVALID_PACKET is returned instead.
 *
 * @param buf
 * @return
 */
lwmqtt_packet_t lwmqtt_detect_packet_type(unsigned char *buf);

/**
 * Will detect the remaining length form the at least on byte long buffer.
 *
 * It will return LWMQTT_BUFFER_TOO_SHORT_ERROR if the buffer is to short and an additional byte should be read from the
 * network. In case the remaining length is overflowed it will return LWMQTT_REMAINING_LENGTH_OVERFLOW.
 *
 * @param buf
 * @param buf_len
 * @return
 */
lwmqtt_err_t lwmqtt_detect_remaining_length(unsigned char *buf, int buf_len, int *rem_len);

/**
 * Defines the MQTT "Last Will and Testament" (LWT) settings for
 * the connect packet.
 */
typedef struct {
  lwmqtt_string_t topic;
  void *payload;
  int payload_len;
  bool retained;
  lwmqtt_qos_t qos;
} lwmqtt_will_t;

#define lwmqtt_default_will \
  { lwmqtt_default_string, NULL, 0, false, LWMQTT_QOS0 }

typedef struct {
  lwmqtt_string_t client_id;
  unsigned short keep_alive;
  bool clean_session;
  lwmqtt_string_t username;
  lwmqtt_string_t password;
} lwmqtt_options_t;

#define lwmqtt_default_options \
  { lwmqtt_default_string, 60, 1, lwmqtt_default_string, lwmqtt_default_string }

typedef enum {
  LWMQTT_CONNACK_CONNECTION_ACCEPTED = 0,
  LWMQTT_CONNACK_UNACCEPTABLE_PROTOCOL = 1,
  LWMQTT_CONNACK_IDENTIFIER_REJECTED = 2,
  LWMQTT_CONNACK_SERVER_UNAVAILABLE = 3,
  LWMQTT_CONNACK_BAD_USERNAME_OR_PASSWORD = 4,
  LWMQTT_CONNACK_NOT_AUTHORIZED = 5
} lwmqtt_connack_t;

/**
  * Encodes the connect options into the buffer.
  *
  * @param buf The buffer into which the packet will be encoded.
  * @param buf_len The length in bytes of the supplied buffer.
  * @param options The options to be used to build the connect packet.
  * @param will The last will and testament.
  * @return encoded length, or error if 0
  */
lwmqtt_err_t lwmqtt_encode_connect(unsigned char *buf, int buf_len, int *len, lwmqtt_options_t *options,
                                   lwmqtt_will_t *will);

/**
  * Decodes the supplied (wire) buffer into connack data - return code
  *
  * @param session_present the session present flag returned (only for MQTT 3.1.1)
  * @param connack_rc returned integer value of the connack return code
  * @param buf the raw buffer data, of the correct length determined by the remaining length field
  * @param len the length in bytes of the data in the supplied buffer
  * @return error code.  1 is success, 0 is failure
  */
lwmqtt_err_t lwmqtt_decode_connack(bool *session_present, lwmqtt_connack_t *connack, unsigned char *buf, int buf_len);

/**
  * Encodes a disconnect packet into the supplied buffer, ready for writing to a socket
  *
  * @param buf The buffer into which the packet will be encoded.
  * @param buf_len The length in bytes of the supplied buffer, to avoid overruns.
  * @return Encoded length, or error if 0.
  */
lwmqtt_err_t lwmqtt_encode_zero(unsigned char *buf, int buf_len, int *len, lwmqtt_packet_t packet);

/**
  * Decodes the supplied (wire) buffer into an ack
  *
  * @param packet_type returned integer - the MQTT packet type
  * @param dup returned integer - the MQTT dup flag
  * @param packet_id returned integer - the MQTT packet identifier
  * @param buf the raw buffer data, of the correct length determined by the remaining length field
  * @param buf_len the length in bytes of the data in the supplied buffer
  * @return error code.  1 is success, 0 is failure
  */
lwmqtt_err_t lwmqtt_decode_ack(lwmqtt_packet_t *packet, bool *dup, unsigned short *packet_id, unsigned char *buf,
                               int buf_len);

lwmqtt_err_t lwmqtt_encode_ack(unsigned char *buf, int buf_len, int *len, lwmqtt_packet_t packet, bool dup,
                               unsigned short packet_id);

/**
  * Decodes the supplied (wire) buffer into publish data
  *
  * @param dup returned integer - the MQTT dup flag
  * @param qos returned integer - the MQTT QoS value
  * @param retained returned integer - the MQTT retained flag
  * @param packet_id returned integer - the MQTT packet identifier
  * @param topic returned MQTTString - the MQTT topic in the publish
  * @param payload returned byte buffer - the MQTT publish payload
  * @param payload_len returned integer - the length of the MQTT payload
  * @param buf the raw buffer data, of the correct length determined by the remaining length field
  * @param buf_len the length in bytes of the data in the supplied buffer
  * @return error code.  1 is success
  */
lwmqtt_err_t lwmqtt_decode_publish(bool *dup, lwmqtt_qos_t *qos, bool *retained, unsigned short *packet_id,
                                   lwmqtt_string_t *topic, unsigned char **payload, int *payload_len,
                                   unsigned char *buf, int buf_len);

/**
  * Encodes the supplied publish data into the supplied buffer, ready for sending
  *
  * @param buf the buffer into which the packet will be encoded
  * @param buf_len the length in bytes of the supplied buffer
  * @param dup integer - the MQTT dup flag
  * @param qos integer - the MQTT QoS value
  * @param retained integer - the MQTT retained flag
  * @param packet_id integer - the MQTT packet identifier
  * @param topic MQTTString - the MQTT topic in the publish
  * @param payload byte buffer - the MQTT publish payload
  * @param payload_len integer - the length of the MQTT payload
  * @return the length of the encoded data.  <= 0 indicates error
  */
lwmqtt_err_t lwmqtt_encode_publish(unsigned char *buf, int buf_len, int *len, bool dup, lwmqtt_qos_t qos, bool retained,
                                   unsigned short packet_id, lwmqtt_string_t topic, unsigned char *payload,
                                   int payload_len);

/**
  * Encodes the supplied subscribe data into the supplied buffer, ready for sending
  *
  * @param buf the buffer into which the packet will be encoded
  * @param buf_len the length in bytes of the supplied buffer
  * @param dup integer - the MQTT dup flag
  * @param packet_id integer - the MQTT packet identifier
  * @param count - number of members in the topicFilters and reqQos arrays
  * @param topic_filters - array of topic filter names
  * @param qos_levels - array of requested QoS
  * @return the length of the encoded data.  <= 0 indicates error
  */
lwmqtt_err_t lwmqtt_encode_subscribe(unsigned char *buf, int buf_len, int *len, unsigned short packet_id, int count,
                                     lwmqtt_string_t *topic_filters, lwmqtt_qos_t *qos_levels);

/**
  * Decodes the supplied (wire) buffer into suback data
  *
  * @param packet_id returned integer - the MQTT packet identifier
  * @param max_count - the maximum number of members allowed in the grantedQoSs array
  * @param count returned integer - number of members in the grantedQoSs array
  * @param granted_qos_levels returned array of integers - the granted qualities of service
  * @param buf the raw buffer data, of the correct length determined by the remaining length field
  * @param buf_len the length in bytes of the data in the supplied buffer
  * @return error code.  1 is success, 0 is failure
  */
lwmqtt_err_t lwmqtt_decode_suback(unsigned short *packet_id, int max_count, int *count,
                                  lwmqtt_qos_t *granted_qos_levels, unsigned char *buf, int buf_len);

/**
  * Encodes the supplied unsubscribe data into the supplied buffer, ready for sending
  *
  * @param buf the raw buffer data, of the correct length determined by the remaining length field
  * @param buf_len the length in bytes of the data in the supplied buffer
  * @param dup integer - the MQTT dup flag
  * @param packet_id integer - the MQTT packet identifier
  * @param count - number of members in the topicFilters array
  * @param topic_filters - array of topic filter names
  * @return the length of the encoded data.  <= 0 indicates error
  */
lwmqtt_err_t lwmqtt_encode_unsubscribe(unsigned char *buf, int buf_len, int *len, unsigned short packet_id, int count,
                                       lwmqtt_string_t *topic_filters);

#endif  // LWMQTT_PACKET_H
