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

#ifndef LWMQTT_IDENTIFIED_H
#define LWMQTT_IDENTIFIED_H

/**
  * Deserializes the supplied (wire) buffer into an ack
  *
  * @param packet_type returned integer - the MQTT packet type
  * @param dup returned integer - the MQTT dup flag
  * @param packet_id returned integer - the MQTT packet identifier
  * @param buf the raw buffer data, of the correct length determined by the remaining length field
  * @param buf_len the length in bytes of the data in the supplied buffer
  * @return error code.  1 is success, 0 is failure
  */
int lwmqtt_deserialize_identified(unsigned char *packet_type, unsigned char *dup, unsigned short *packet_id,
                                  unsigned char *buf, int buf_len);

int lwmqtt_serialize_identified(unsigned char *buf, int buf_len, unsigned char packettype, unsigned char dup,
                                unsigned short packet_id);

#endif
