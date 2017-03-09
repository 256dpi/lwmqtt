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

#ifndef LWMQTT_PUBLISH_H
#define LWMQTT_PUBLISH_H

#include "string.h"

int lwmqtt_serialize_publish(unsigned char *buf, int buflen, unsigned char dup, int qos, unsigned char retained,
                             unsigned short packetid, lwmqtt_string_t topicName, unsigned char *payload,
                             int payloadlen);

int lwmqtt_deserialize_publish(unsigned char *dup, int *qos, unsigned char *retained, unsigned short *packetid,
                               lwmqtt_string_t *topicName, unsigned char **payload, int *payloadlen, unsigned char *buf,
                               int len);

int lwmqtt_serialize_puback(unsigned char *buf, int buflen, unsigned short packetid);
int lwmqtt_serialize_pubrel(unsigned char *buf, int buflen, unsigned char dup, unsigned short packetid);
int lwmqtt_serialize_pubcomp(unsigned char *buf, int buflen, unsigned short packetid);

int lwmqtt_deserialize_ack(unsigned char *packettype, unsigned char *dup, unsigned short *packetid, unsigned char *buf,
                           int buflen);

#endif  // LWMQTT_PUBLISH_H
