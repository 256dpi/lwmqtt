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

typedef union {
  unsigned char all; /**< all connect flags */

  struct {
    unsigned int : 1;              /**< unused */
    unsigned int cleansession : 1; /**< cleansession flag */
    unsigned int will : 1;         /**< will flag */
    unsigned int willQoS : 2;      /**< will QoS value */
    unsigned int willRetain : 1;   /**< will retain setting */
    unsigned int password : 1;     /**< 3.1 password */
    unsigned int username : 1;     /**< 3.1 user name */
  } bits;
} MQTTConnectFlags; /**< connect flags byte */

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
  MQTTString topicName;
  /** The LWT payload. */
  MQTTString message;
  /**
* The retained flag for the LWT message (see MQTTAsync_message.retained).
*/
  unsigned char retained;
  /**
* The quality of service setting for the LWT message (see
* MQTTAsync_message.qos and @ref qos).
*/
  char qos;
} MQTTPacket_willOptions;

#define MQTTPacket_willOptions_initializer \
  { {'M', 'Q', 'T', 'W'}, 0, {NULL, {0, NULL}}, {NULL, {0, NULL}}, 0, 0 }

typedef struct {
  /** The eyecatcher for this structure.  must be MQTC. */
  char struct_id[4];
  /** The version number of this structure.  Must be 0 */
  int struct_version;
  /** Version of MQTT to be used.  3 = 3.1 4 = 3.1.1
    */
  unsigned char MQTTVersion;
  MQTTString clientID;
  unsigned short keepAliveInterval;
  unsigned char cleansession;
  unsigned char willFlag;
  MQTTPacket_willOptions will;
  MQTTString username;
  MQTTString password;
} MQTTPacket_connectData;

typedef union {
  unsigned char all; /**< all connack flags */

  struct {
    unsigned int : 7;                /**< unused */
    unsigned int sessionpresent : 1; /**< session present flag */
  } bits;
} MQTTConnackFlags; /**< connack flags byte */

#define MQTTPacket_connectData_initializer                                                                            \
  {                                                                                                                   \
    {'M', 'Q', 'T', 'C'}, 0, 4, {NULL, {0, NULL}}, 60, 1, 0, MQTTPacket_willOptions_initializer, {NULL, {0, NULL}}, { \
      NULL, { 0, NULL }                                                                                               \
    }                                                                                                                 \
  }


int MQTTSerialize_connect(unsigned char* buf, int buflen, MQTTPacket_connectData* options);

int MQTTDeserialize_connack(unsigned char* sessionPresent, unsigned char* connack_rc, unsigned char* buf, int buflen);

int MQTTSerialize_disconnect(unsigned char* buf, int len);
int MQTTSerialize_pingreq(unsigned char* buf, int len);

#endif  // LWMQTT_CONNECT_H
