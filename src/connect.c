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
  * Determines the length of the MQTT connect packet that would be produced using the supplied connect options.
  *
  * @param options the options to be used to build the connect packet
  * @return the length of buffer needed to contain the serialized version of the packet
  */
int MQTTSerialize_connectLength(lwmqtt_connect_data* options) {
  int len = 0;

  if (options->MQTTVersion == 3)
    len = 12; /* variable depending on MQTT or MQIsdp */
  else if (options->MQTTVersion == 4)
    len = 10;

  len += lwmqtt_strlen(options->clientID) + 2;
  if (options->willFlag) len += lwmqtt_strlen(options->will.topicName) + 2 + lwmqtt_strlen(options->will.message) + 2;
  if (options->username.cstring || options->username.lenstring.data) len += lwmqtt_strlen(options->username) + 2;
  if (options->password.cstring || options->password.lenstring.data) len += lwmqtt_strlen(options->password) + 2;

  return len;
}

/**
  * Serializes the connect options into the buffer.
  * @param buf the buffer into which the packet will be serialized
  * @param len the length in bytes of the supplied buffer
  * @param options the options to be used to build the connect packet
  * @return serialized length, or error if 0
  */
int lwmqtt_serialize_connect(unsigned char *buf, int buflen, lwmqtt_connect_data *options) {
  unsigned char* ptr = buf;
  lwmqtt_header_t header = {0};
  lwmqtt_connect_flags_t flags = {0};
  int len = 0;
  int rc = -1;

  if (lwmqtt_packet_len(len = MQTTSerialize_connectLength(options)) > buflen) {
    rc = MQTTPACKET_BUFFER_TOO_SHORT;
    goto exit;
  }

  header.byte = 0;
  header.bits.type = CONNECT;
  lwmqtt_write_char(&ptr, header.byte); /* write header */

  ptr += lwmqtt_packet_encode(ptr, len); /* write remaining length */

  if (options->MQTTVersion == 4) {
    lwmqtt_write_c_string(&ptr, "MQTT");
    lwmqtt_write_char(&ptr, (char) 4);
  } else {
    lwmqtt_write_c_string(&ptr, "MQIsdp");
    lwmqtt_write_char(&ptr, (char) 3);
  }

  flags.all = 0;
  flags.bits.cleansession = options->cleansession;
  flags.bits.will = (options->willFlag) ? 1 : 0;
  if (flags.bits.will) {
    flags.bits.willQoS = options->will.qos;
    flags.bits.willRetain = options->will.retained;
  }

  if (options->username.cstring || options->username.lenstring.data) flags.bits.username = 1;
  if (options->password.cstring || options->password.lenstring.data) flags.bits.password = 1;

  lwmqtt_write_char(&ptr, flags.all);
  lwmqtt_write_int(&ptr, options->keepAliveInterval);
  lwmqtt_write_string(&ptr, options->clientID);
  if (options->willFlag) {
    lwmqtt_write_string(&ptr, options->will.topicName);
    lwmqtt_write_string(&ptr, options->will.message);
  }
  if (flags.bits.username) lwmqtt_write_string(&ptr, options->username);
  if (flags.bits.password) lwmqtt_write_string(&ptr, options->password);

  rc = ptr - buf;

exit:
  return rc;
}

/**
  * Deserializes the supplied (wire) buffer into connack data - return code
  * @param sessionPresent the session present flag returned (only for MQTT 3.1.1)
  * @param connack_rc returned integer value of the connack return code
  * @param buf the raw buffer data, of the correct length determined by the remaining length field
  * @param len the length in bytes of the data in the supplied buffer
  * @return error code.  1 is success, 0 is failure
  */
int lwmqtt_deserialize_connack(unsigned char *sessionPresent, unsigned char *connack_rc, unsigned char *buf, int buflen) {
  lwmqtt_header_t header = {0};
  unsigned char* curdata = buf;
  unsigned char* enddata = NULL;
  int rc = 0;
  int mylen;
  lwmqtt_connack_flags flags = {0};

  header.byte = lwmqtt_read_char(&curdata);
  if (header.bits.type != CONNACK) goto exit;

  curdata += (rc = lwmqtt_packet_decode_buf(curdata, &mylen)); /* read remaining length */
  enddata = curdata + mylen;
  if (enddata - curdata < 2) goto exit;

  flags.all = lwmqtt_read_char(&curdata);
  *sessionPresent = flags.bits.sessionpresent;
  *connack_rc = lwmqtt_read_char(&curdata);

  rc = 1;
exit:
  return rc;
}

/**
  * Serializes a 0-length packet into the supplied buffer, ready for writing to a socket
  * @param buf the buffer into which the packet will be serialized
  * @param buflen the length in bytes of the supplied buffer, to avoid overruns
  * @param packettype the message type
  * @return serialized length, or error if 0
  */
int MQTTSerialize_zero(unsigned char* buf, int buflen, unsigned char packettype) {
  lwmqtt_header_t header = {0};
  int rc = -1;
  unsigned char* ptr = buf;

  if (buflen < 2) {
    rc = MQTTPACKET_BUFFER_TOO_SHORT;
    goto exit;
  }
  header.byte = 0;
  header.bits.type = packettype;
  lwmqtt_write_char(&ptr, header.byte); /* write header */

  ptr += lwmqtt_packet_encode(ptr, 0); /* write remaining length */
  rc = ptr - buf;
exit:
  return rc;
}

/**
  * Serializes a disconnect packet into the supplied buffer, ready for writing to a socket
  *
  * @param buf The buffer into which the packet will be serialized.
  * @param len The length in bytes of the supplied buffer, to avoid overruns.
  * @return Serialized length, or error if 0.
  */
int lwmqtt_serialize_disconnect(unsigned char *buf, int len) { return MQTTSerialize_zero(buf, len, DISCONNECT); }

/**
  * Serializes a disconnect packet into the supplied buffer, ready for writing to a socket
  *
  * @param buf The buffer into which the packet will be serialized.
  * @param len The length in bytes of the supplied buffer, to avoid overruns.
  * @return Serialized length, or error if 0.
  */
int lwmqtt_serialize_pingreq(unsigned char *buf, int len) { return MQTTSerialize_zero(buf, len, PINGREQ); }
