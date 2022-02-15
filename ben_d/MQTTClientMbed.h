#ifndef __MQTTClientMbed_h__
#define __MQTTClientMbed_h__

#include "MQTTClient.h"

#include "lwmqtt_mbedtls_network.h"
#include "lwmqtt_unix_timer.h"

/**
 * @brief Class implementing the MQTT client using Mbedtls (derived from MQTTCLient)
 */

class MQTTClientMbed : public MQTTClient
{
    public:

        MQTTClientMbed(string mqttHost,
                   int mqttHostPort,
                   bool validateMqttHostCert,
                   string deviceCertPath,
                   string deviceKeyPath,
                   string caCertPath,
                   string onboardingCaCertPath,
                   OnConnectCallbackPtr onConnectCallback=nullptr,
                   OnDisconnectCallbackPtr onDisconnectCallback=nullptr,
                   OnMessageCallbackPtr onMessageCallback=nullptr);

    protected:

    private:
        /** @brief MQTT client object. */
        lwmqtt_mbedtls_network_t mMqttNetworkConnection;

        /**
         *  TODO:Benoit  Initiliaze MQTT Client parameters and Tls/Socket
        */            
        void NetworkInit(string mqttHost,
                   int mqttHostPort,
                   bool validateMqttHostCert,
                   string deviceCertPath,
                   string deviceKeyPath,
                   string caCertPath);

        lwmqtt_err_t ConnectingToBroker(int *fd);

        void NetworkDisconnect();

        bool NetworkIsConnected();

        lwmqtt_err_t NetworkPeek(size_t*);

};

#endif // #ifndef __MQTTClientMbed_h__