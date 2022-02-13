
#include "MQTTClientTLS.h"
#include "config.h"


MQTSClientTLS::MQTSClientTLS(string mqttHost,
                int mqttHostPort,
                bool validateMqttHostCert,
                string deviceCertPath,
                string deviceKeyPath,
                string caCertPath,
                string onboardingCaCertPath,
                OnConnectCallbackPtr onConnectCallback,
                OnDisconnectCallbackPtr onDisconnectCallback,
                OnMessageCallbackPtr onMessageCallback) : 
                MQTTClient(mqttHost,
                 mqttHostPort,
                 validateMqttHostCert,
                 deviceCertPath,
                 deviceKeyPath,
                 caCertPath,
                 onboardingCaCertPath,
                 onConnectCallback,
                 onDisconnectCallback,
                 onMessageCallback)
{
    GLINFO_MQTTCLIENT("MQTSClientTLS +++-------------------------------");
    GLINFO_MQTTCLIENT("%s, %d, %d, %s, %s, %s", mqttHost.c_str(), mqttHostPort, validateMqttHostCert, deviceCertPath.c_str(), deviceKeyPath.c_str(), caCertPath.c_str());
    GLINFO_MQTTCLIENT("MQTSClientTLS +++-------------------------------");

    NetworkInit(mqttHost, mqttHostPort, validateMqttHostCert, deviceCertPath, deviceKeyPath, caCertPath);

    InitLWMQTTTClient();
    InitTimer();

    Start();
}

void MQTSClientTLS::NetworkDisconnect()
{
    //lwmqtt_mbedtls_network_disconnect(&mMqttNetworkConnection);
    GLINFO_MQTTCLIENT("NetworkDisconnect +++-------------------------------");
}


bool MQTSClientTLS::NetworkIsConnected()
{
    GLINFO_MQTTCLIENT("NetworkIsConnected +++-------------------------------");
    return mMqttNetworkConnection.is_connected;
}

extern "C" {
extern lwmqtt_err_t lwmqtt_network_read(void *ref, uint8_t *buf, size_t len, size_t *read, uint32_t timeout);
extern lwmqtt_err_t lwmqtt_network_write(void *ref, uint8_t *buf, size_t len, size_t *sent, uint32_t timeout);
} // extern "C" {


void MQTSClientTLS::NetworkInit(string mqttHost,
                   int mqttHostPort,
                   bool validateMqttHostCert,
                   string deviceCertPath,
                   string deviceKeyPath,
                   string caCertPath)
{
    GLINFO_MQTTCLIENT("NetworkInit Start +++-------------------------------");
    // Initialize the MQTT network connection info.
    struct mosquitto *network = &mMqttNetworkConnection;
    memset(network, 0, sizeof(*network));
    network->port = mqttHostPort;
    strncpy(network->host, mqttHost.c_str(), sizeof(network->host));
    strncpy(network->tls_cafile, caCertPath.c_str(), sizeof(network->tls_cafile));
    strncpy(network->tls_certfile, deviceCertPath.c_str(), sizeof(network->tls_certfile));
    strncpy(network->tls_keyfile, deviceKeyPath.c_str(), sizeof(network->tls_keyfile));
    network->tls_cert_reqs = validateMqttHostCert;
    network->tls_alpn = (char*)"x-amzn-mqtt-ca";
    GLINFO_MQTTCLIENT("%s, %d, %d, %s, %s, %s", network->host, network->port, network->tls_cert_reqs,
     network->tls_certfile, network->tls_keyfile, network->tls_cafile);

    // Configure the MQTT client.
    lwmqtt_set_network(&mMqttClient, network, lwmqtt_network_read, lwmqtt_network_write);
    GLINFO_MQTTCLIENT("NetworkInit End +++-------------------------------");
}

extern "C" {
int net__socket_connect(struct mosquitto *mosq, const char *host, uint16_t port, const char *bind_address, bool blocking);
lwmqtt_err_t lwmqtt_network_peek(void *ref, size_t *read);
}
lwmqtt_err_t MQTSClientTLS::ConnectingToBroker(int *fd)
{
    lwmqtt_err_t rc = LWMQTT_SUCCESS;
    net__socket_connect(&mMqttNetworkConnection, mMqttNetworkConnection.host, mMqttNetworkConnection.port, 0, false);
    *fd = mMqttNetworkConnection.sock;
    GLINFO_MQTTCLIENT("ConnectingToBroker +++-------------------------------");
    return rc;
}



lwmqtt_err_t MQTSClientTLS::NetworkPeek(size_t *available)
{
    lwmqtt_err_t rc = LWMQTT_SUCCESS;
    
    rc = lwmqtt_network_peek(&mMqttNetworkConnection, available);
    GLINFO_MQTTCLIENT("lwmqtt_mbedtls_network_peek return error code %d, and available %lu", rc, *available);
    return rc;
}
