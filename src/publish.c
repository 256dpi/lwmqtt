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
 *******************************************************************************/

#include <string.h>

#include "packet.h"

/**
  * Deserializes the supplied (wire) buffer into publish data
  * @param dup returned integer - the MQTT dup flag
  * @param qos returned integer - the MQTT QoS value
  * @param retained returned integer - the MQTT retained flag
  * @param packetid returned integer - the MQTT packet identifier
  * @param topicName returned MQTTString - the MQTT topic in the publish
  * @param payload returned byte buffer - the MQTT publish payload
  * @param payloadlen returned integer - the length of the MQTT payload
  * @param buf the raw buffer data, of the correct length determined by the remaining length field
  * @param buflen the length in bytes of the data in the supplied buffer
  * @return error code.  1 is success
  */
int lwmqtt_deserialize_publish(unsigned char *dup, int *qos, unsigned char *retained, unsigned short *packetid,
                               lwmqtt_string_t *topicName, unsigned char **payload, int *payloadlen, unsigned char *buf,
                               int buflen) {
  lwmqtt_header_t header = {0};
  unsigned char* curdata = buf;
  unsigned char* enddata = NULL;
  int rc = 0;
  int mylen = 0;

  header.byte = lwmqtt_read_char(&curdata);
  if (header.bits.type != PUBLISH) goto exit;
  *dup = header.bits.dup;
  *qos = header.bits.qos;
  *retained = header.bits.retain;

  curdata += (rc = lwmqtt_packet_decode_buf(curdata, &mylen)); /* read remaining length */
  enddata = curdata + mylen;

  if (!lwmqtt_read_lp_string(topicName, &curdata, enddata) ||
      enddata - curdata < 0) /* do we have enough data to read the protocol version byte? */
    goto exit;

  if (*qos > 0) *packetid = lwmqtt_read_int(&curdata);

  *payloadlen = enddata - curdata;
  *payload = curdata;
  rc = 1;
exit:

  return rc;
}

/**
  * Deserializes the supplied (wire) buffer into an ack
  * @param packettype returned integer - the MQTT packet type
  * @param dup returned integer - the MQTT dup flag
  * @param packetid returned integer - the MQTT packet identifier
  * @param buf the raw buffer data, of the correct length determined by the remaining length field
  * @param buflen the length in bytes of the data in the supplied buffer
  * @return error code.  1 is success, 0 is failure
  */
int lwmqtt_deserialize_ack(unsigned char *packettype, unsigned char *dup, unsigned short *packetid, unsigned char *buf,
                           int buflen) {
  lwmqtt_header_t header = {0};
  unsigned char* curdata = buf;
  unsigned char* enddata = NULL;
  int rc = 0;
  int mylen;

  header.byte = lwmqtt_read_char(&curdata);
  *dup = header.bits.dup;
  *packettype = header.bits.type;

  curdata += (rc = lwmqtt_packet_decode_buf(curdata, &mylen)); /* read remaining length */
  enddata = curdata + mylen;

  if (enddata - curdata < 2) goto exit;
  *packetid = lwmqtt_read_int(&curdata);

  rc = 1;
exit:
  return rc;
}

/**
  * Determines the length of the MQTT publish packet that would be produced using the supplied parameters
  * @param qos the MQTT QoS of the publish (packetid is omitted for QoS 0)
  * @param topicName the topic name to be used in the publish
  * @param payloadlen the length of the payload to be sent
  * @return the length of buffer needed to contain the serialized version of the packet
  */
int MQTTSerialize_publishLength(int qos, lwmqtt_string_t topicName, int payloadlen) {
  int len = 0;

  len += 2 + lwmqtt_strlen(topicName) + payloadlen;
  if (qos > 0) len += 2; /* packetid */
  return len;
}

/**
  * Serializes the supplied publish data into the supplied buffer, ready for sending
  * @param buf the buffer into which the packet will be serialized
  * @param buflen the length in bytes of the supplied buffer
  * @param dup integer - the MQTT dup flag
  * @param qos integer - the MQTT QoS value
  * @param retained integer - the MQTT retained flag
  * @param packetid integer - the MQTT packet identifier
  * @param topicName MQTTString - the MQTT topic in the publish
  * @param payload byte buffer - the MQTT publish payload
  * @param payloadlen integer - the length of the MQTT payload
  * @return the length of the serialized data.  <= 0 indicates error
  */
int lwmqtt_serialize_publish(unsigned char *buf, int buflen, unsigned char dup, int qos, unsigned char retained,
                             unsigned short packetid, lwmqtt_string_t topicName, unsigned char *payload, int payloadlen) {
  unsigned char* ptr = buf;
  lwmqtt_header_t header = {0};
  int rem_len = 0;
  int rc = 0;

  if (lwmqtt_packet_len(rem_len = MQTTSerialize_publishLength(qos, topicName, payloadlen)) > buflen) {
    rc = MQTTPACKET_BUFFER_TOO_SHORT;
    goto exit;
  }

  header.bits.type = PUBLISH;
  header.bits.dup = dup;
  header.bits.qos = qos;
  header.bits.retain = retained;
  lwmqtt_write_char(&ptr, header.byte); /* write header */

  ptr += lwmqtt_packet_encode(ptr, rem_len); /* write remaining length */
  ;

  lwmqtt_write_string(&ptr, topicName);

  if (qos > 0) lwmqtt_write_int(&ptr, packetid);

  memcpy(ptr, payload, payloadlen);
  ptr += payloadlen;

  rc = ptr - buf;

exit:
  return rc;
}

/**
  * Serializes the ack packet into the supplied buffer.
  * @param buf the buffer into which the packet will be serialized
  * @param buflen the length in bytes of the supplied buffer
  * @param type the MQTT packet type
  * @param dup the MQTT dup flag
  * @param packetid the MQTT packet identifier
  * @return serialized length, or error if 0
  */
int lwmqtt_serialize_ack(unsigned char *buf, int buflen, unsigned char packettype, unsigned char dup,
                         unsigned short packetid) {
  lwmqtt_header_t header = {0};
  int rc = 0;
  unsigned char* ptr = buf;

  if (buflen < 4) {
    rc = MQTTPACKET_BUFFER_TOO_SHORT;
    goto exit;
  }
  header.bits.type = packettype;
  header.bits.dup = dup;
  header.bits.qos = (packettype == PUBREL) ? 1 : 0;
  lwmqtt_write_char(&ptr, header.byte); /* write header */

  ptr += lwmqtt_packet_encode(ptr, 2); /* write remaining length */
  lwmqtt_write_int(&ptr, packetid);
  rc = ptr - buf;
exit:

  return rc;
}

/**
  * Serializes a puback packet into the supplied buffer.
  * @param buf the buffer into which the packet will be serialized
  * @param buflen the length in bytes of the supplied buffer
  * @param packetid integer - the MQTT packet identifier
  * @return serialized length, or error if 0
  */
int lwmqtt_serialize_puback(unsigned char *buf, int buflen, unsigned short packetid) {
  return lwmqtt_serialize_ack(buf, buflen, PUBACK, 0, packetid);
}

/**
  * Serializes a pubrel packet into the supplied buffer.
  * @param buf the buffer into which the packet will be serialized
  * @param buflen the length in bytes of the supplied buffer
  * @param dup integer - the MQTT dup flag
  * @param packetid integer - the MQTT packet identifier
  * @return serialized length, or error if 0
  */
int lwmqtt_serialize_pubrel(unsigned char *buf, int buflen, unsigned char dup, unsigned short packetid) {
  return lwmqtt_serialize_ack(buf, buflen, PUBREL, dup, packetid);
}

/**
  * Serializes a pubrel packet into the supplied buffer.
  * @param buf the buffer into which the packet will be serialized
  * @param buflen the length in bytes of the supplied buffer
  * @param packetid integer - the MQTT packet identifier
  * @return serialized length, or error if 0
  */
int lwmqtt_serialize_pubcomp(unsigned char *buf, int buflen, unsigned short packetid) {
  return lwmqtt_serialize_ack(buf, buflen, PUBCOMP, 0, packetid);
}
