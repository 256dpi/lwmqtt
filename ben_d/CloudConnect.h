#ifndef __CLOUD_CONNECT_H__
#define __CLOUD_CONNECT_H__

//#include <awsiotsdk/mqtt/Client.hpp>

#include <ev++.h>

#include "MQTTClient.h"
#include "config.h"

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
                     bool forceMqttConnStart);

        /**
         * @brief Destructor of the class.
         */
        ~CloudConnect();

    protected:

    private:
        /** @brief Reference to the event loop. */
        ev::loop_ref mLoop;

        /** @brief MQTT client instance. */
        MQTTClient mMQTTClient;

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

};

#endif /* __CLOUD_CONNECT_H__ */
