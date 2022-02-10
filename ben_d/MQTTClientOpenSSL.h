#ifndef __MQTTClientOpenSSL_h__
#define __MQTTClientOpenSSL_h__



#include "MQTTClient.h"
#include "SSLConnection.h"
#include "Socket.h"


/**
 * @brief Class implementing the MQTT client using OpenSSL (derived from MQTTCLient)
 */


typedef std::function<lwmqtt_err_t(uint8_t *buffer, size_t len, size_t *read, uint32_t timeout, bool rdwr)> lwmqttReadWriteCallbackFunc;
typedef std::function<lwmqtt_err_t(uint8_t *buffer, size_t len, size_t *sent, uint32_t timeout, bool rdwr)> lwmqttWriteCallbackFunc;


class MQTTClientOpenSSL : public MQTTClient
{
    public:

        MQTTClientOpenSSL(string mqttHost,
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

        Socket mSock;
        TLS mTls;
        TlsData_S mTlsData;

        /**
         *  Initialize Tls/Socket network interface
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

        lwmqttReadWriteCallbackFunc mLwmqttReadWriteCallbackFunc;
        lwmqtt_err_t ReadWrite(uint8_t *buffer, size_t len, size_t *read, uint32_t timeout, bool rdwr);
        lwmqtt_err_t Read(uint8_t *buffer, size_t len, size_t *read, uint32_t timeout);
        lwmqtt_err_t Write(uint8_t *buffer, size_t len, size_t *read, uint32_t timeout);

};

#endif // #ifndef __MQTTClientOpenSSL_h__
