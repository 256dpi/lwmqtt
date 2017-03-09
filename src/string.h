#ifndef LWMQTT_STRING_H
#define LWMQTT_STRING_H

typedef struct {
  int len;
  char *data;
} lwmqtt_lp_string_t;

typedef struct {
  char *cstring;
  lwmqtt_lp_string_t lenstring;
} lwmqtt_string_t;

#define lwmqtt_default_string { NULL, { 0, NULL } }

int lwmqtt_strlen(lwmqtt_string_t mqttstring);

int lwmqtt_strcmp(lwmqtt_string_t *a, char *b);

int lwmqtt_read_lp_string(lwmqtt_string_t *mqttstring, unsigned char **pptr, unsigned char *enddata);

void lwmqtt_write_c_string(unsigned char **pptr, const char *string);

void lwmqtt_write_string(unsigned char **pptr, lwmqtt_string_t mqttstring);

#endif  // LWMQTT_STRING_H
