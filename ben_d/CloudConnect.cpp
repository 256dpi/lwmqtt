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
#if AP
      mSyslogServer(mLoop, syslogServerPort),
#endif // #if AP
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
#if AP
    // Setup WebSocket server callbacks.
    WebSocketServer::OnConnectCallbackPtr wsConnectCallback =
        std::bind(&CloudConnect::HandleWsClientConnect,
                  this,
                  std::placeholders::_1,
                  std::placeholders::_2);
    mWebSocketServer.SetOnConnectCallback(wsConnectCallback);
    WebSocketServer::OnDisconnectCallbackPtr wsDisconnectCallback =
        std::bind(&CloudConnect::HandleWsClientDisconnect,
                  this,
                  std::placeholders::_1);
    mWebSocketServer.SetOnDisconnectCallback(wsDisconnectCallback);
    WebSocketServer::OnMessageCallbackPtr wsMessageCallback =
        std::bind(&CloudConnect::HandleWsClientMessage,
                  this,
                  std::placeholders::_1,
                  std::placeholders::_2,
                  std::placeholders::_3);
    mWebSocketServer.SetOnMessageCallback(wsMessageCallback);
#endif // #if AP
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
#if AP
    // Setup the syslog server callback.
    mSyslogServer.SetOnMessageCallback(
        std::bind(&CloudConnect::HandleSyslogMessage,
                  this,
                  std::placeholders::_1,
                  std::placeholders::_2,
                  std::placeholders::_3,
                  std::placeholders::_4)
    );

    // Initialize map of WebSocket clients.
    // NOTE: All clients initialized here will have to be connected before
    //       the MQTT connection can start.
    mWsClients[TELEMETRY_WS_PROTOCOL] = vector<int>();
    mWsClients[CONFIG_WS_PROTOCOL] = vector<int>();
    mWsClients[LUAD_SCRIPT_WS_PROTOCOL] = vector<int>();
#endif // #if AP
    // Setup the timer used to reset all connections.
    mResetAllConnectionsTimer.set<CloudConnect, &CloudConnect::ResetAllConnectionsTimerCallback>(this);
#if AP
    // Starts components.
    mWebSocketServer.Start();
#endif // #if AP
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
#if AP
    mWebSocketServer.Stop();
#endif // #if AP
    mResetAllConnectionsTimer.stop();
#if AP
    mWebSocketServer.Start();
#endif // #if AP
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
#if AP
        internal_messages::LuadScriptMessage luaScriptMessage;
        luaScriptMessage.set_script_id(scriptId);
        luaScriptMessage.set_payload(string(message.begin(), message.end()));

        std::string luaScriptMessageString;
        luaScriptMessage.SerializeToString(&luaScriptMessageString);
        mWebSocketServer.BroadcastToProtocol(vector<byte>(luaScriptMessageString.begin(), luaScriptMessageString.end()), LUAD_SCRIPT_WS_PROTOCOL);
#endif // #if AP
        return;
    }

    GLDEBUG_DEFAULT("Forwarding message of %ld bytes to configd and telemetryd...",
                    message.size());

#if AP
    mWebSocketServer.BroadcastToProtocol(message, TELEMETRY_WS_PROTOCOL);
    mWebSocketServer.BroadcastToProtocol(message, CONFIG_WS_PROTOCOL);
#endif // #if AP
}
#if AP
void CloudConnect::HandleSyslogMessage(const std::string& application, const std::string& facility, const std::string& severity, const std::string& message)
{
    mMQTTClient.SendMessage("log/" + application + "/" + facility + "/" + severity,
                            vector<byte>(message.begin(), message.end()), "");
}

void CloudConnect::HandleWsClientConnect(int clientID, const string& protocol)
{
    GLINFO_DEFAULT("New WebSocket client (ID %d, protocol '%s').",
                   clientID,
                   protocol.c_str());

    if (mWsClients.count(protocol) == 0) {
        GLERROR_DEFAULT("WebSocket client (ID %d) connected with unsupported protocol '%s'.",
                        clientID,
                        protocol.c_str());
        mWebSocketServer.Disconnect(clientID, "unknown protocol");
        return;
    }

    mWsClients.at(protocol).push_back(clientID);

    // Check if MQTT connection needs to be started.  This is the case when
    // there is a connected client on each WebSocket connection.
    if (!mMQTTClient.Started()) {
        bool startMQTT = true;

        for (const auto &wsClient : mWsClients) {
            if (wsClient.second.size() == 0) {
                GLINFO_DEFAULT("Not starting MQTT connection: "
                               "no WebSocket client connected on '%s' yet.",
                               wsClient.first.c_str());
                startMQTT = false;
                break;
            }
        }

        if (startMQTT) {
            GLINFO_DEFAULT("All WebSocket clients connected, starting MQTT connection.");
            mMQTTClient.Start();
        }
    }
}

void CloudConnect::HandleWsClientDisconnect(int clientID)
{
    bool found = false;

    for (auto &wsClient : mWsClients) {
        vector<int>& clientIDs = wsClient.second;
        for (unsigned int i = 0; i < clientIDs.size(); i++) {
            if (clientIDs[i] == clientID) {
                GLINFO_DEFAULT("WebSocket client disconnected (ID %d, protocol '%s').",
                               clientID,
                               wsClient.first.c_str());
                found = true;
                clientIDs.erase(clientIDs.begin() + i);
                break;
            }
        }
    }

    if (!found) {
        GLINFO_DEFAULT("Unknown WebSocket client disconnected (ID %d).", clientID);
    }

    // We lost connection with a WebSocket client.  Re-syncronize everyone by
    // disconnecting all WebSocket clients and restarting the MQTT connection
    // process.
    RequestConnectionsReset();
}

void CloudConnect::HandleWsClientMessage(int clientID, const string& protocol, const vector<byte>& message)
{
    GLDEBUG_DEFAULT("Received message from WebSocket client (ID %d, protocol '%s').",
                    clientID,
                    protocol.c_str());

    if (protocol == LUAD_SCRIPT_WS_PROTOCOL) {
        internal_messages::LuadScriptMessage luaScriptMessage;
        if (!luaScriptMessage.ParseFromArray(message.data(), message.size())) {
            GLERROR_DEFAULT("LuadScriptMessage message could not be parsed!");
            return;
        }

        if (!luaScriptMessage.has_script_id()) {
            GLERROR_DEFAULT("LuadScriptMessage message has no script_id!");
            return;
        }

        if (!luaScriptMessage.has_payload()) {
            GLERROR_DEFAULT("LuadScriptMessage message has no payload!");
            return;
        }

        std::string messageTag;
        if (luaScriptMessage.has_payload_type()) {
            messageTag = luaScriptMessage.payload_type();
        }

        std::vector<byte> payload(luaScriptMessage.payload().cbegin(), luaScriptMessage.payload().cend());
        mMQTTClient.SendMessage("script/" + luaScriptMessage.script_id(), payload, messageTag);
        return;
    }

    GLDEBUG_DEFAULT("Forwarding message from WebSocket client (ID %d) on MQTT connection.",
             clientID);
    mMQTTClient.SendMessage("devconf", message, "");
}
#endif // #if AP