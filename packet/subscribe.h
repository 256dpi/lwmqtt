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

#ifndef LWMQTT_SUBSCRIBE_H
#define LWMQTT_SUBSCRIBE_H

int MQTTSerialize_subscribe(unsigned char* buf, int buflen, unsigned char dup, unsigned short packetid, int count,
                            MQTTString topicFilters[], int requestedQoSs[]);

int MQTTDeserialize_suback(unsigned short* packetid, int maxcount, int* count, int grantedQoSs[], unsigned char* buf,
                           int len);

#endif  // LWMQTT_SUBSCRIBE_H
