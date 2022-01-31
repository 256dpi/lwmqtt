#include <iostream>
#include <cassert>
#include <chrono>


#include "CloudConnect.h"
#include "config.h"

#define MAX_WS_BUFFER_SIZE (128 * 1024)

CloudConnect::CloudConnect(ev::loop_ref loop,
                           std::string mqttHost,
                           int mqttHostPort=443,
                           bool validateMqttHostCert=true,
                           std::string deviceCertPath="/tmp/device.pem",
                           std::string deviceKeyPath="/tmp/device.key",
                           std::string caCert="/aruba/conf/AmazonRootCA.pem",
                           std::string onboardingCACert="./ca/smb_ca_certificate.pem",
                           bool forceMqttConnStart=false)
    : mLoop(loop),
      mMQTTClient(mqttHost,
                  mqttHostPort,
                  validateMqttHostCert,
                  deviceCertPath,
                  deviceKeyPath,
                  caCert,
                  onboardingCACert),
      mForceMQTTConnStart(forceMqttConnStart),
      mConnectionsResetRequested(false)
{
    GLINFO_DEFAULT("CloudConnect +++-------------------------------");
    GLINFO_DEFAULT("%s, %d, %d, %s, %s, %s", 
        mqttHost.c_str(),
        mqttHostPort,
        validateMqttHostCert,
        deviceCertPath.c_str(),
        deviceKeyPath.c_str(),
        caCert.c_str());
    GLINFO_DEFAULT("CloudConnect +++-------------------------------");

    // Setup MQTT client callbacks.
    MQTTClient::OnConnectCallbackPtr mqttConnectCallback =
        std::bind(&CloudConnect::HandleMQTTConnect, this);
    mMQTTClient.SetOnConnectCallback(mqttConnectCallback);

    MQTTClient::OnDisconnectCallbackPtr mqttDisconnectCallback =
        std::bind(&CloudConnect::HandleMQTTDisconnect, this);
    mMQTTClient.SetOnDisconnectCallback(mqttDisconnectCallback);

    MQTTClient::OnMessageCallbackPtr mqttMessageCallback =
        std::bind(&CloudConnect::HandleMQTTMessage,
                  this,
                  std::placeholders::_1,
                  std::placeholders::_2);
    mMQTTClient.SetOnMessageCallback(mqttMessageCallback);


    // Setup the timer used to reset all connections.
    mResetAllConnectionsTimer.set<CloudConnect, &CloudConnect::ResetAllConnectionsTimerCallback>(this);

    if (mForceMQTTConnStart) {
        mMQTTClient.Start();
    }

}

CloudConnect::~CloudConnect()
{
}

void CloudConnect::ResetAllConnectionsTimerCallback(ev::timer &watcher, int revents)
{
    BTraceIn;
    GLINFO_DEFAULT("Forcing re-establishment of WebSocket and MQTT connections.");

    mMQTTClient.Stop();
    mResetAllConnectionsTimer.stop();
    mConnectionsResetRequested = false;
}

void CloudConnect::RequestConnectionsReset()
{
    BTraceIn;
    if (!mConnectionsResetRequested) {
        mConnectionsResetRequested = true;
        mResetAllConnectionsTimer.start(0.0, 0.0);
    }
}

void CloudConnect::HandleMQTTConnect()
{
    GLINFO_DEFAULT("Connected to MQTT gateway.");
}

void CloudConnect::HandleMQTTDisconnect()
{
    BTraceIn;
    GLINFO_DEFAULT("MQTT connection lost.");

    // We lost the MQTT connection.  Re-syncronize everyone by disconnecting
    // all WebSocket clients and restarting the MQTT connection process.
    RequestConnectionsReset();
}

void CloudConnect::HandleMQTTMessage(const string& topicName, const vector<byte>& message)
{
    BTraceIn;
    string prefix = mMQTTClient.GetSubscribeTopicBase() + "/script/";
    if (topicName.compare(0, prefix.length(), prefix) == 0) {
        GLDEBUG_DEFAULT("Forwarding message of %ld bytes to luad...",
                        message.size());

        // We received a message from device/<device-id>/script/<script-id>
        // Convert it to a message readable by luad
        string scriptId = topicName.substr(prefix.length(), topicName.length() - prefix.length());
        return;
    }

    GLDEBUG_DEFAULT("Forwarding message of %ld bytes to configd and telemetryd...",
                    message.size());

}


