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

#ifndef LWMQTT_CONNECT_H
#define LWMQTT_CONNECT_H

#include "string.h"

typedef union {
  unsigned char all; /**< all connect flags */

  struct {
    unsigned int _ : 1;            /**< unused */
    unsigned int cleansession : 1; /**< cleansession flag */
    unsigned int will : 1;         /**< will flag */
    unsigned int willQoS : 2;      /**< will QoS value */
    unsigned int willRetain : 1;   /**< will retain setting */
    unsigned int password : 1;     /**< 3.1 password */
    unsigned int username : 1;     /**< 3.1 user name */
  } bits;
} lwmqtt_connect_flags_t; /**< connect flags byte */

/**
 * Defines the MQTT "Last Will and Testament" (LWT) settings for
 * the connect packet.
 */
typedef struct {
  /** The eyecatcher for this structure.  must be MQTW. */
  char struct_id[4];
  /** The version number of this structure.  Must be 0 */
  int struct_version;
  /** The LWT topic to which the LWT message will be published. */
  lwmqtt_string_t topicName;
  /** The LWT payload. */
  lwmqtt_string_t message;
  /**
* The retained flag for the LWT message (see MQTTAsync_message.retained).
*/
  unsigned char retained;
  /**
* The quality of service setting for the LWT message (see
* MQTTAsync_message.qos and @ref qos).
*/
  char qos;
} lwmqtt_will_options_t;

#define lwmqtt_default_will_options \
  { {'M', 'Q', 'T', 'W'}, 0, {NULL, {0, NULL}}, {NULL, {0, NULL}}, 0, 0 }

typedef struct {
  /** The eyecatcher for this structure.  must be MQTC. */
  char struct_id[4];
  /** The version number of this structure.  Must be 0 */
  int struct_version;
  /** Version of MQTT to be used.  3 = 3.1 4 = 3.1.1
    */
  unsigned char MQTTVersion;
  lwmqtt_string_t clientID;
  unsigned short keepAliveInterval;
  unsigned char cleansession;
  unsigned char willFlag;
  lwmqtt_will_options_t will;
  lwmqtt_string_t username;
  lwmqtt_string_t password;
} lwmqtt_connect_data_t;

typedef union {
  unsigned char all; /**< all connack flags */

  struct {
    unsigned int _ : 7;              /**< unused */
    unsigned int sessionpresent : 1; /**< session present flag */
  } bits;
} lwmqtt_connack_flags; /**< connack flags byte */

#define lwmqtt_default_connect_data                                                                            \
  {                                                                                                            \
    {'M', 'Q', 'T', 'C'}, 0, 4, {NULL, {0, NULL}}, 60, 1, 0, lwmqtt_default_will_options, {NULL, {0, NULL}}, { \
      NULL, { 0, NULL }                                                                                        \
    }                                                                                                          \
  }

/**
  * Serializes the connect options into the buffer.
  * @param buf the buffer into which the packet will be serialized
  * @param len the length in bytes of the supplied buffer
  * @param options the options to be used to build the connect packet
  * @return serialized length, or error if 0
  */
int lwmqtt_serialize_connect(unsigned char *buf, int buflen, lwmqtt_connect_data_t *options);

/**
  * Deserializes the supplied (wire) buffer into connack data - return code
  * @param sessionPresent the session present flag returned (only for MQTT 3.1.1)
  * @param connack_rc returned integer value of the connack return code
  * @param buf the raw buffer data, of the correct length determined by the remaining length field
  * @param len the length in bytes of the data in the supplied buffer
  * @return error code.  1 is success, 0 is failure
  */
int lwmqtt_deserialize_connack(unsigned char *sessionPresent, unsigned char *connack_rc, unsigned char *buf,
                               int buflen);

/**
  * Serializes a disconnect packet into the supplied buffer, ready for writing to a socket
  *
  * @param buf The buffer into which the packet will be serialized.
  * @param len The length in bytes of the supplied buffer, to avoid overruns.
  * @return Serialized length, or error if 0.
  */
int lwmqtt_serialize_disconnect(unsigned char *buf, int len);

/**
  * Serializes a disconnect packet into the supplied buffer, ready for writing to a socket
  *
  * @param buf The buffer into which the packet will be serialized.
  * @param len The length in bytes of the supplied buffer, to avoid overruns.
  * @return Serialized length, or error if 0.
  */
int lwmqtt_serialize_pingreq(unsigned char *buf, int len);

#endif  // LWMQTT_CONNECT_H
