#include "MQTTClientMbed.h"
#include "lwmqtt_mbedtls_network.h"
#include "lwmqtt_unix_timer.h"
#include <aruba/util/grouplog_cloudconnect.h>


MQTTClientMbed::MQTTClientMbed(string mqttHost,
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
    GLINFO_MQTTCLIENT("MQTTClientMbed +++-------------------------------");
    GLINFO_MQTTCLIENT("%s, %d, %d, %s, %s, %s", mqttHost.c_str(), mqttHostPort, validateMqttHostCert, deviceCertPath.c_str(), deviceKeyPath.c_str(), caCertPath.c_str());
    GLINFO_MQTTCLIENT("MQTTClientMbed +++-------------------------------");

    NetworkInit(mqttHost, mqttHostPort, validateMqttHostCert, deviceCertPath, deviceKeyPath, caCertPath);

    InitLWMQTTTClient();
    InitTimer();

}

void MQTTClientMbed::NetworkDisconnect()
{
    lwmqtt_mbedtls_network_disconnect(&mMqttNetworkConnection);
    GLINFO_MQTTCLIENT("NetworkDisconnect +++-------------------------------");
}


bool MQTTClientMbed::NetworkIsConnected()
{
    GLINFO_MQTTCLIENT("NetworkIsConnected +++-------------------------------");
    return mMqttNetworkConnection.is_connected;
}

void MQTTClientMbed::NetworkInit(string mqttHost,
                   int mqttHostPort,
                   bool validateMqttHostCert,
                   string deviceCertPath,
                   string deviceKeyPath,
                   string caCertPath)
{
    GLINFO_MQTTCLIENT("NetworkInit Start +++-------------------------------");
    // Initialize the MQTT network connection info.
    lwmqtt_mbedtls_network_t *network = &mMqttNetworkConnection;
    memset(network, 0, sizeof(*network));
    network->endpoint_port = mqttHostPort;
    strlcpy(network->endpoint, mqttHost.c_str(), sizeof(network->endpoint));
    strlcpy(network->root_ca_location, caCertPath.c_str(), sizeof(network->root_ca_location));
    strlcpy(network->device_cert_location, deviceCertPath.c_str(), sizeof(network->device_cert_location));
    strlcpy(network->device_private_key_location, deviceKeyPath.c_str(), sizeof(network->device_private_key_location));
    network->server_verification_flag = validateMqttHostCert;
    network->tls_handshake_timeout = MQTT_NETWORK_CONNECTION_HANDSHAKE_TIMEOUT_MSECS;
    network->tls_read_timeout = MQTT_NETWORK_CONNECTION_READ_TIMEOUT_MSECS;
    network->tls_write_timeout = MQTT_NETWORK_CONNECTION_WRITE_TIMEOUT_MSECS;
    network->alpn_protocol_list[0] = "x-amzn-mqtt-ca";
    GLINFO_MQTTCLIENT("%s, %d, %d, %s, %s, %s", network->endpoint, network->endpoint_port, network->server_verification_flag,
     network->device_cert_location, network->device_private_key_location, network->root_ca_location);

    // Configure the MQTT client.
    lwmqtt_set_network(&mMqttClient, network, lwmqtt_mbedtls_network_read, lwmqtt_mbedtls_network_write);
    GLINFO_MQTTCLIENT("NetworkInit End +++-------------------------------");
}

lwmqtt_err_t MQTTClientMbed::ConnectingToBroker(int *fd)
{
    lwmqtt_err_t rc = lwmqtt_mbedtls_network_connect(&mMqttNetworkConnection, mMqttNetworkConnection.endpoint, mMqttNetworkConnection.endpoint_port);
    *fd = mMqttNetworkConnection.server_fd.fd;
    GLINFO_MQTTCLIENT("ConnectingToBroker +++-------------------------------");
    return rc;
}


lwmqtt_err_t MQTTClientMbed::NetworkPeek(size_t *available)
{
    lwmqtt_err_t rc;

    rc = lwmqtt_mbedtls_network_peek(&mMqttNetworkConnection, available);
    GLINFO_MQTTCLIENT("lwmqtt_mbedtls_network_peek return error code %d, and available %u", rc, *available);
    return rc;
}

