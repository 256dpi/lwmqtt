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
 *******************************************************************************/

#ifndef LWMQTT_UNSUBSCRIBE_H
#define LWMQTT_UNSUBSCRIBE_H

#include "string.h"

/**
  * Serializes the supplied unsubscribe data into the supplied buffer, ready for sending
  *
  * @param buf the raw buffer data, of the correct length determined by the remaining length field
  * @param buf_len the length in bytes of the data in the supplied buffer
  * @param dup integer - the MQTT dup flag
  * @param packet_id integer - the MQTT packet identifier
  * @param count - number of members in the topicFilters array
  * @param topic_filters - array of topic filter names
  * @return the length of the serialized data.  <= 0 indicates error
  */
int lwmqtt_serialize_unsubscribe(unsigned char *buf, int buf_len, unsigned char dup, unsigned short packet_id,
                                 int count, lwmqtt_string_t *topic_filters);

/**
  * Deserializes the supplied (wire) buffer into unsuback data
  *
  * @param packet_id returned integer - the MQTT packet identifier
  * @param buf the raw buffer data, of the correct length determined by the remaining length field
  * @param buf_len the length in bytes of the data in the supplied buffer
  * @return error code.  1 is success, 0 is failure
  */
int lwmqtt_deserialize_unsuback(unsigned short *packet_id, unsigned char *buf, int buf_len);

#endif  // LWMQTT_UNSUBSCRIBE_H
