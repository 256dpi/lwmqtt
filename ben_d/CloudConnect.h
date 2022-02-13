#ifndef __CLOUD_CONNECT_H__
#define __CLOUD_CONNECT_H__

//#include <awsiotsdk/mqtt/Client.hpp>

#include <ev++.h>
#if AP
#include <gsm_schema.h>
#include <gsm_apps.h>
#include <aruba/libwebsockethelper/WebSocketServer.h>
#endif // #if AP

        #define TEST_MBED
        #define TEST_OPENSSL
        #define TEST_TLS
        #undef TEST_MBED
        #undef TEST_OPENSSL
        //#undef TEST_TLS
        #if defined(TEST_MBED)
        #include "MQTTClientMbed.h"
        #elif defined(TEST_OPENSSL)
        #include "MQTTClientOpenSSL.h"
        #elif defined(TEST_TLS)
        #include "MQTTClientTLS.h"
        #else
        #include "MQTTClient1883.h"
        #endif // #ifdef TEST_MBED

#if AP
#include "SyslogServer.h"
#else // #if AP
#include "config.h"
#endif // #if AP

#define CLOUD_CONNECT_LOG_ID "CloudConnect"

/**
 * @brief Class representing the cloud connect daemon.
 */
class CloudConnect {
    public:
        /**
         * @brief Constructor of the class.
         *
         * @param[in] loop Reference to the event loop.
         * @param[in] mqttHost The target endpoint to connect to.
         * @param[in] mqttPort The port on the target to connect to.
         * @param[in] validateMqttHostCert Used to decide whether server verification is needed or not.
         * @param[in] deviceCertPath Path to the location of the device certificate.
         * @param[in] deviceKeyPath Path to the location of the device private key.
         * @param[in] caCertPath Path to the location of the CA certificate used
         *                       to connect to the MQTT host.
         * @param[in] onboardingCACertPath Path to the location of the CA
         *                                 certificate used to connect to the
         *                                 onboarding service.
         * @param[in] forceMqttConnStart Decide if the MQTT connection should
         *                               be started immediately, instead of
         *                               waiting for WebSocket clients to
         *                               connect.
         */
        CloudConnect(ev::loop_ref loop,
                     string mqttHost,
                     int mqttHostPort,
                     bool validateMqttHostCert,
                     string deviceCertPath,
                     string deviceKeyPath,
                     string caCertPath,
                     string onboardingCACertPath,
#if AP
                     int websocketServerPort,
                     int syslogServerPort,
#endif // #if AP
                     bool forceMqttConnStart);

        /**
         * @brief Destructor of the class.
         */
        ~CloudConnect();

    protected:

    private:
        /** @brief Reference to the event loop. */
        ev::loop_ref mLoop;
#if AP
        /** @brief WebSocket server instance. */
        WebSocketServer mWebSocketServer;

        /** @brief Number of WebSocket clients per protocol. */
        map<string, vector<int>> mWsClients;
#endif // #if AP
        /** @brief MQTT client instance. */
        #if 1
                #ifdef TEST_MBED
                MQTTClientMbed mMQTTClient;
                #elif defined(TEST_OPENSSL)
                MQTTClientOpenSSL mMQTTClient;
                #elif defined(TEST_TLS)
                MQTSClientTLS mMQTTClient;
                #else // #ifdef TEST_OPEN
                MQTTClient1883 mMQTTClient;
                #endif //#ifdef TEST_MBED
        #else
                MQTSClientTLS mMQTTClient;
        #endif 

#if AP
        SyslogServer mSyslogServer;
#endif // #if AP
        /**
          * @brief Indicate if the MQTT connection should be started
          *        immediately, instead of waiting for WebSocket clients to
          *        connect.
          */
        bool mForceMQTTConnStart;

        /** @brief Indicate if reset of all connections has been requested. */
        bool mConnectionsResetRequested;

        /** @brief Timer used to schedule the reset of all connections. */
        ev::timer mResetAllConnectionsTimer;

        /**
         * @brief Callback invoked when it's time to reset connections.
         */
        void ResetAllConnectionsTimerCallback(ev::timer &watcher, int revents);

        /**
         * @brief Request the reset of all connections.
         *
         * This function re-establish the MQTT connection and all connections
         * with WebSocket clients.  This is performed when a connection is lost
         * (either the MQTT connection or a WebSocket connection) in order to
         * force a re-synchronization between the cloud the components
         * interacting with it.
         */
        void RequestConnectionsReset();

        /**
         * @brief Callback invoked when the MQTT connection is established.
         */
        void HandleMQTTConnect();

        /**
         * @brief Callback invoked when the MQTT connection is lost.
         */
        void HandleMQTTDisconnect();

        /**
         * @brief Callback invoked when a message a received from the MQTT
         *                 connection.
         *
         * @param[in] message Message received from the MQTT connection.
         */
        void HandleMQTTMessage(const string& topicName, const vector<byte>& message);
#if AP
        /**
         * Handle syslog message.
         *
         * @param[in] application Application of the message.
         * @param[in] facility Syslog facility of the message.
         * @param[in] severity Syslog level of the message.
         * @param[in] message Message.
         */
        void HandleSyslogMessage(const std::string& application, const std::string& facility, const std::string& severity, const std::string& message);

        /**
         * @brief Callback invoked when a new WebSocket client is connected.
         */
        void HandleWsClientConnect(int connectionID, const string& protocol);

        /**
         * @brief Callback invoked when a WebSocket client is disconnected.
         */
        void HandleWsClientDisconnect(int connectionID);

        /**
         * @brief Callback invoked when a message is received from a WebSocket
         *        client.
         *
         * @param[in] message Message received from the WebSocket.
         */
        void HandleWsClientMessage(int connectionID, const string& protocol, const vector<byte>& message);
#endif // #if AP
};
#endif /* __CLOUD_CONNECT_H__ */
