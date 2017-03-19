#include <gtest/gtest.h>

extern "C" {
#include "../src/client.h"
#include "../src/packet.h"
}

#include "macros.h"

TEST(ConnectTest, IsEqual) {
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

  unsigned char buf[256];

  lwmqtt_will_t will = lwmqtt_default_will;
  will.topic.c_string = (char*)"will";
  will.message.c_string = (char*)"send me home";
  will.qos = LWMQTT_QOS1;

  lwmqtt_options_t opts = lwmqtt_default_options;
  opts.clean_session = 0;
  opts.keep_alive = 10;
  opts.client_id.c_string = (char*)"surgemq";
  opts.username.c_string = (char*)"surgemq";
  opts.password.c_string = (char*)"verysecret";

  int l = lwmqtt_serialize_connect(buf, 256, &opts, &will);

  EXPECT_ARRAY_EQ(unsigned char, pkt, buf, l);
}
