#ifndef LWMQTT_PUBLISH_H
#define LWMQTT_PUBLISH_H

#include <stdbool.h>

#include "string.h"

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
int lwmqtt_encode_publish(unsigned char *buf, int buf_len, unsigned char dup, int qos, unsigned char retained,
                          unsigned short packet_id, lwmqtt_string_t topic, unsigned char *payload, int payload_len);

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
int lwmqtt_decode_publish(bool *dup, int *qos, bool *retained, unsigned short *packet_id, lwmqtt_string_t *topic,
                          unsigned char **payload, int *payload_len, unsigned char *buf, int buf_len);

/**
  * Encodes a puback packet into the supplied buffer.
  *
  * @param buf the buffer into which the packet will be encoded
  * @param buf_len the length in bytes of the supplied buffer
  * @param packet_id integer - the MQTT packet identifier
  * @return encoded length, or error if 0
  */
int lwmqtt_encode_puback(unsigned char *buf, int buf_len, unsigned short packet_id);

/**
  * Encodes a pubrec packet into the supplied buffer.
  *
  * @param buf the buffer into which the packet will be encoded
  * @param buf_len the length in bytes of the supplied buffer
  * @param packet_id integer - the MQTT packet identifier
  * @return encoded length, or error if 0
  */
int lwmqtt_encode_pubrec(unsigned char *buf, int buf_len, unsigned short packet_id);

/**
  * Encodes a pubrel packet into the supplied buffer.
  *
  * @param buf the buffer into which the packet will be encoded
  * @param buf_len the length in bytes of the supplied buffer
  * @param dup integer - the MQTT dup flag
  * @param packet_id integer - the MQTT packet identifier
  * @return encoded length, or error if 0
  */
int lwmqtt_encode_pubrel(unsigned char *buf, int buf_len, unsigned char dup, unsigned short packet_id);

/**
  * Encodes a pubrel packet into the supplied buffer.
  *
  * @param buf the buffer into which the packet will be encoded
  * @param buf_len the length in bytes of the supplied buffer
  * @param packet_id integer - the MQTT packet identifier
  * @return encoded length, or error if 0
  */
int lwmqtt_encode_pubcomp(unsigned char *buf, int buf_len, unsigned short packet_id);

#endif  // LWMQTT_PUBLISH_H
