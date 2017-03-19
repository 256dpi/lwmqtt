#include <gtest/gtest.h>

extern "C" {
#include "../src/client.h"
}

#include "macros.h"

TEST(ConnectTest, Encode1) {
  unsigned char pkt[62] = {
      LWMQTT_CONNECT_PACKET << 4,
      60,
      0,  // Protocol String MSB
      4,  // Protocol String LSB
      'M',
      'Q',
      'T',
      'T',
      4,    // Protocol level 4
      204,  // Connect Flags
      0,    // Keep Alive MSB
      10,   // Keep Alive LSB
      0,    // Client ID MSB
      7,    // Client ID LSB
      's',
      'u',
      'r',
      'g',
      'e',
      'm',
      'q',
      0,  // Will Topic MSB
      4,  // Will Topic LSB
      'w',
      'i',
      'l',
      'l',
      0,   // Will Message MSB
      12,  // Will Message LSB
      's',
      'e',
      'n',
      'd',
      ' ',
      'm',
      'e',
      ' ',
      'h',
      'o',
      'm',
      'e',
      0,  // Username ID MSB
      7,  // Username ID LSB
      's',
      'u',
      'r',
      'g',
      'e',
      'm',
      'q',
      0,   // Password ID MSB
      10,  // Password ID LSB
      'v',
      'e',
      'r',
      'y',
      's',
      'e',
      'c',
      'r',
      'e',
      't',
  };

  unsigned char buf[62];

  lwmqtt_will_t will = lwmqtt_default_will;
  will.topic.c_string = (char*)"will";
  will.payload = (void*)"send me home";
  will.payload_len = strlen((const char*)will.payload);
  will.qos = LWMQTT_QOS1;

  lwmqtt_options_t opts = lwmqtt_default_options;
  opts.clean_session = 0;
  opts.keep_alive = 10;
  opts.client_id.c_string = (char*)"surgemq";
  opts.username.c_string = (char*)"surgemq";
  opts.password.c_string = (char*)"verysecret";

  int len;
  lwmqtt_err_t r = lwmqtt_encode_connect(buf, 62, &len, &opts, &will);

  EXPECT_EQ(r, LWMQTT_SUCCESS);
  EXPECT_ARRAY_EQ(unsigned char, pkt, buf, len);
}

TEST(ConnectTest, Encode2) {
  unsigned char pkt[14] = {
      LWMQTT_CONNECT_PACKET << 4,
      12,
      0,  // Protocol String MSB
      4,  // Protocol String LSB
      'M',
      'Q',
      'T',
      'T',
      4,   // Protocol level 4
      2,   // Connect Flags
      0,   // Keep Alive MSB
      60,  // Keep Alive LSB
      0,   // Client ID MSB
      0,   // Client ID LSB
  };

  unsigned char buf[14];

  lwmqtt_options_t opts = lwmqtt_default_options;

  int len;
  lwmqtt_err_t r = lwmqtt_encode_connect(buf, 14, &len, &opts, NULL);

  EXPECT_EQ(r, LWMQTT_SUCCESS);
  EXPECT_ARRAY_EQ(unsigned char, pkt, buf, len);
}

TEST(ConnectTest, EncodeError1) {
  unsigned char buf[4];  // <- too small buffer

  lwmqtt_options_t opts = lwmqtt_default_options;

  int len;
  lwmqtt_err_t r = lwmqtt_encode_connect(buf, 4, &len, &opts, NULL);

  EXPECT_EQ(r, LWMQTT_BUFFER_TOO_SHORT_ERROR);
}

TEST(ConnackTest, decode1) {
  unsigned char pkt[4] = {
      LWMQTT_CONNACK_PACKET << 4, 2,
      0,  // session not present
      0,  // connection accepted
  };

  bool session_present;
  lwmqtt_connack_t connack;
  lwmqtt_err_t r = lwmqtt_decode_connack(&session_present, &connack, pkt, 4);

  EXPECT_EQ(r, LWMQTT_SUCCESS);
  EXPECT_EQ(session_present, 0);
  EXPECT_EQ(connack, 0);
}

TEST(ConnackTest, decodeError1) {
  unsigned char pkt[4] = {
      LWMQTT_CONNACK_PACKET << 4,
      3,  // <-- wrong size
      0,  // session not present
      0,  // connection accepted
  };

  bool session_present;
  lwmqtt_connack_t connack;
  lwmqtt_err_t r = lwmqtt_decode_connack(&session_present, &connack, pkt, 4);

  EXPECT_EQ(r, LWMQTT_LENGTH_MISMATCH);
}

TEST(ConnackTest, decodeError2) {
  unsigned char pkt[3] = {
      LWMQTT_CONNACK_PACKET << 4, 3,
      0,  // session not present
          // <- missing packet size
  };

  bool session_present;
  lwmqtt_connack_t connack;
  lwmqtt_err_t r = lwmqtt_decode_connack(&session_present, &connack, pkt, 3);

  EXPECT_EQ(r, LWMQTT_LENGTH_MISMATCH);
}

TEST(DisconnectTest, Encode1) {
  unsigned char pkt[2] = {LWMQTT_DISCONNECT_PACKET << 4, 0};

  unsigned char buf[2];

  int len;
  lwmqtt_err_t r = lwmqtt_encode_disconnect(buf, 2, &len);

  EXPECT_EQ(r, LWMQTT_SUCCESS);
  EXPECT_ARRAY_EQ(unsigned char, pkt, buf, len);
}

TEST(PingreqTest, Encode1) {
  unsigned char pkt[2] = {LWMQTT_PINGREQ_PACKET << 4, 0};

  unsigned char buf[2];

  int len;
  lwmqtt_err_t r = lwmqtt_encode_pingreq(buf, 2, &len);

  EXPECT_EQ(r, LWMQTT_SUCCESS);
  EXPECT_ARRAY_EQ(unsigned char, pkt, buf, len);
}
