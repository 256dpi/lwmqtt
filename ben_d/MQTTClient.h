#ifndef __MQTT_CLIENT_H__
#define __MQTT_CLIENT_H__

#include <functional>
#include <string>
#include <vector>
#include <utility>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
using std::string;
using std::vector;

#include "Socket.h"

typedef uint8_t byte;

#include "mosq.h"
extern "C" {
#include <lwmqtt.h>
#include <lwmqtt/unix.h>
}

#include "SSLConnection.h"
#include <ev++.h>

/**
 * @brief Maximum number of times we try to get the cloud session sequence
 *        before giving up.
 */
#define MAX_CLOUD_SESSION_SEQUENCE_FETCH_TRIES 3

/** @brief Delay (in seconds) between MQTT connection attempts. */
#define MQTT_CONNECTION_SM_TIMER_PERIOD_SECS (15.0)

/** @brief Timeout of handshake operation in milliseconds. */
#define MQTT_NETWORK_CONNECTION_HANDSHAKE_TIMEOUT_MSECS 60000

/** @brief Timeout of read operation in milliseconds. */
#define MQTT_NETWORK_CONNECTION_READ_TIMEOUT_MSECS 2000

/** @brief Timeout of write operation in milliseconds. */
#define MQTT_NETWORK_CONNECTION_WRITE_TIMEOUT_MSECS 2000

#define MAX_BUFFER_SIZE (256 * 1024)

#define MQTT_COMMAND_TIMEOUT_MSEC 10000

typedef std::function<void(lwmqtt_client_t *client, void *ref, lwmqtt_string_t topic, lwmqtt_message_t msg)> lwmqttMessageCallbackFunc;

template<typename T>
class IterativeMean {
    public:
        IterativeMean() {
            mCount = 0;
            mAverage = 0;
        }

        void add(T val) {
            if (mCount == UINT_MAX) reset();
            mAverage += (val - mAverage) / ++mCount;
        }

        void reset() {
            mCount = 0;
            mAverage = 0;
        }

        T get() {
            return (T)mAverage;
        }
    private:
        unsigned int mCount;
        double mAverage;
};

struct MQTTConnectionInfo
{
    enum class State {
        INACTIVE,
        DISCONNECTED,
        GETTING_CLOUD_SESSION_SEQUENCE,
        CONNECTING_TO_BROKER,
        CONNECTING_TO_MQTT,
        SENDING_HELLO,
        SUBSCRIBING,
        CONNECTED,
    };

    // MQTT state.
    struct {
        State mState;
        uint32_t mUptime;
        lwmqtt_err_t mCode;
        unsigned int mRetries;
    } mState;

    // MQTT connection duration.
    IterativeMean<uint32_t> mAverageConnectionDuration; /* Average duration of the MQTT connection, in seconds */
    uint32_t mLastConnectionDuration; /* Duration of the last MQTT connection, in seconds */
    uint32_t mCurrentConnectionUptime; /* Uptime in seconds at which the current MQTT connection started. */

    // MQTT ack times.
    struct {
        IterativeMean<uint32_t> mSinceBeginning; /* Average MQTT ack time (in milliseconds) since the beginning. */
        uint32_t mPeakSinceBeginning; /* Peak MQTT ack time (in milliseconds) since the beginning. */
        IterativeMean<uint32_t> mCurrentConnection; /* Average MQTT ack time (un milliseconds) during the current connection. */
        uint32_t mPeakCurrentConnection; /* Peak MQTT ack time (un milliseconds) during the current connection. */
        uint32_t mLastConnection; /* Average MQTT ack time (un milliseconds) during the last connection. */
        uint32_t mPeakLastConnection; /* Peak MQTT ack time (un milliseconds) during the last connection. */
        uint32_t mLastMessage; /* MQTT ack time (un milliseconds) of the last message. */
        std::vector<std::pair<std::chrono::time_point<std::chrono::steady_clock>, uint32_t>> mHistoricalData; /* List of recent MQTT ack times (un milliseconds). */
    } mAckTimes;

    // MQTT messages.
    struct {
        int64_t mTxTotal; /* Total number of MQTT messages sent. */
        int64_t mTxCurrentConnection /* Number of MQTT messages send during the current connection. */;
        int64_t mTxLastConnection /* Number of MQTT message send during the last connection. */;
        uint64_t mTxDroppedTotal; /* Total number of MQTT messages that have not been transmitted. */
        uint64_t mTxDroppedLastDisconnection; /* Number of MQTT messages that have not been transmitted during the last disconnection. */
        uint32_t mTxSizePeak; /* Biggest transmitted MQTT payload size. */
        uint32_t mTxSizeLast; /* Last transmitted MQTT payload size. */
        uint32_t mRxSizePeak; /* Biggest received MQTT payload size. */
        uint32_t mRxSizeLast; /* Last received MQTT payload size. */
    } mMessages;

    // Misc.
    uint32_t mDisconnects; /* Number of time we lost the MQTT connection. */
    int mLastDisconnectionError; /* Error code associated to the last MQTT disconnection. */
    string mLastDisconnectionErrorStr; /* Description of the error code associated to the last MQTT disconnection. */
    in_addr_t mBrokerIpAddr; /* IP address of the MQTT broker. */
};
extern void lwmqtt_message_callback_c_wrapper(lwmqtt_client_t *client, void *ref, lwmqtt_string_t topic, lwmqtt_message_t msg);

/**
 * @brief Class implementing the MQTT client.
 */
class MQTTClient {
    public:

        typedef std::function<void()> OnConnectCallbackPtr;
        typedef std::function<void()> OnDisconnectCallbackPtr;
        typedef std::function<void(const string& topicName, const vector<byte>&)> OnMessageCallbackPtr;

        /**
         * @brief Constructor of the class.
         *
         * @param[in] mqttHost The target endpoint to connect to.
         * @param[in] mqttPort The port on the target to connect to.
         * @param[in] validateMqttHostCert Used to decide whether server
         *                                 verification is needed or not.
         * @param[in] deviceCertPath Path to the location of the device certificate.
         * @param[in] deviceKeyPath Path to the location of the device private key.
         * @param[in] caCertPath Path to the location of the CA certificate used
         *                       to connect to the MQTT host.
         * @param[in] onboardingCaCertPath Path to the location of the CA
         *                                 certificate used to connect to the
         *                                 onboarding service.
         * @param[in] onConnectCallback Function to call when the MQTT
         *                              connection is established.
         * @param[in] onDisconnectCallback Function to call when the MQTT
         *                                 connection is lost.
         * @param[in] onMessageCallback Function to call when a message is
         *                              received from the MQTT connection.
         */
        MQTTClient(string mqttHost,
                   int mqttHostPort,
                   bool validateMqttHostCert,
                   string deviceCertPath,
                   string deviceKeyPath,
                   string caCertPath,
                   string onboardingCaCertPath,
                   OnConnectCallbackPtr onConnectCallback=nullptr,
                   OnDisconnectCallbackPtr onDisconnectCallback=nullptr,
                   OnMessageCallbackPtr onMessageCallback=nullptr);

        /**
         * @brief Destructor of the class.
         */
        ~MQTTClient();

        void PrintParameters();

        /** @brief Start the MQTT client, i.e. start the connection. */
        void Start();

        /** @brief Stop the MQTT client, i.e. drop the connection. */
        void Stop();

        /**
         * @brief Check if the MQTT client is started.
         *
         * @return true if the MQTT client is started, false otherwise.
         */
        bool Started() { return mStarted; }

        /**
         * @brief Send a message on the MQTT connection.
         *
         * @param[in] topic Topic to send message on. Will be prefixed by device
         *                  topic.  If "devconf" is given, the message will be
         *                  published on "<PREFIX>pm/<DEVICE_ID>/devconf"
         * @param[in] message Message to be sent.
         * @param[in] messageTag Tag associated to the message.  This is used
         *                       by the receiver and provide hint to interpret
         *                       the message.
         */
        void SendMessage(const std::string& topic, const vector<byte>& message, const std::string messageTag);

        /**
         * @brief Set the function to call when the MQTT connection is
         *        established.
         *
         * @param[in] onConnectCallback Pointer to the function to call.
         */
        void SetOnConnectCallback(OnConnectCallbackPtr onConnectCallback) {
            mOnConnectCallback = onConnectCallback;
        }

        /**
         * @brief Set the function to call when the MQTT connection is
         *        dropped.
         *
         * @param[in] onDisconnectCallback Pointer to the function to call.
         */
        void SetOnDisconnectCallback(OnDisconnectCallbackPtr onDisconnectCallback) {
            mOnDisconnectCallback = onDisconnectCallback;
        }

        /**
         * @brief Set the function to call when a message is received from the
         *        MQTT connection.
         *
         * @param[in] onMessageCallback Pointer to the function to call.
         */
        void SetOnMessageCallback(OnMessageCallbackPtr onMessageCallback) {
            mOnMessageCallback = onMessageCallback;
        }

        inline string GetSubscribeTopicBase() {
            return mSubscribeTopicBase;
        }

    protected:

        /** @brief MQTT network connection object. */
        lwmqtt_client_t mMqttClient;

        /** @brief Timer used to determine if it's time to send the MQTT keepalive. */
        lwmqtt_unix_timer_t mMqttKeepAliveTimer;

        /** @brief Timer used to detect command timeout. */
        lwmqtt_unix_timer_t mMqttCommandTimer;

        /** @brief Function object used to invoke the LWMQTT callback. */
        lwmqttMessageCallbackFunc mLwmqttMessageCallbackFunc;

        void InitLWMQTTTClient();

        void InitTimer();

    private:
        /** @brief Indicate if we are started or not. */
        bool mStarted;

        /** @brief Device information. */
        //gsm_channel_device_info_struct_t mDeviceInfo;

        /** @brief BLE device information. */
        std::string mBleMacAddress;

        /** @brief DRT device information. */
        std::string mDrtVersion;

#ifdef GSM_CHANNEL_MESH_UPLINK_SUPPORTED
        gsm_section_mesh_uplink_state_struct_t mMeshUplinkState;
#endif

        /** @brief Onboarding global state. */
        //gsm_section_onboarding_global_state_struct_t mOnboardingGlobalState;

        /** @brief Onboarding URL. */
        std::string mOnboardingUrl;

        /** @brief Path to the CA certificate used to connect to the onboarding service. */
        std::string mOnboardingCaCertPath;

        /** @brief Device of the ID. */
        std::string mDeviceID;

        /** @brief Session sequence to use when sending MQTT messages. */
        uint64_t mCloudSessionSequence;

        /** @brief Error message when fetching of cloud session sequence fails. */
        std::string mCloudSessionSequenceError;

        /** @brief State of the MQTT connection. */
        MQTTConnectionInfo mConnectionInfo;

        /** @brief Timer used to establish the MQTT connection. */
        ev::timer mConnectionSMTimer;

        /** @brief Timer used to receive data from the MQTT connection. */
        ev::timer mNetworkTimer;

        /** @brief Timer used to dump statistics to GSM. */
        ev::timer mGSMTimer;

        /** @brief Base namespace to which we publish */
        string mPublishTopicBase;

        /** @brief MQTT topic on which the HELLO message is published. */
        string mHelloTopic;

        /** @brief Base namespace to which we subscribe */
        string mSubscribeTopicBase;

        /** @brief MQTT topic to which we subscribe. */
        string mSubscribeTopic;

        /** @brief MQTT topic to which we publich devconf messages. */
        string mDevconfTopic;

        /** @brief Function to call when MQTT connection is established. */
        OnConnectCallbackPtr mOnConnectCallback;

        /** @brief Function to call when a MQTT connection is dropped. */
        OnDisconnectCallbackPtr mOnDisconnectCallback;

        /** @brief Function to call when a message is received from the MQTT
                   connection. */
        OnMessageCallbackPtr mOnMessageCallback;

        /** @brief Function called by the MQTT connection timer. */
        void ConnectionSMTimerCallback(ev::timer &watcher, int revents);

        /** @brief Function called by the MQTT network timer. */
        void NetworkTimerCallback(ev::timer &watcher, int revents);

        /** @brief Function called by the GSM timer. */
        void GSMTimerCallback(ev::timer &watcher, int revents);

        /** @brief Function called when a message is received on a subscribed
                   topic. */
        void SubscribeCallback(lwmqtt_client_t *client, void *ref, lwmqtt_string_t topic, lwmqtt_message_t msg);

        /**
         * @brief Trigger a MQTT disconnect.
         *
         * @param[in] rc Code that caused the disconnect.
         */        
        void TriggerDisconnect(lwmqtt_err_t rc);

        /**
         * @brief Encapsulate message.
         *
         * @param[in] message Message to be encapsulated.
         * @param[in[ messageTag Tag associated to the message that allows the
         *                       receiver to interpret the message.
         * @param[out] outBuffer Pointer to the buffer where to store the
         *                       encapsulated message.
         *
         * @return true on success, false otherhise.
         */
        bool EncapsulateMessage(const vector<byte>& message, const std::string messageTag, std::string *outBuffer);

        /**
         * @brief Encapsulate message.
         *
         * @param[in] message Message to be encapsulated.
         * @param[in[ messageTag Tag associated to the message that allows the
         *                       receiver to interpret the message.
         * @param[out] outBuffer Pointer to the buffer where to store the
         *                       encapsulated message.
         *
         * @return true on success, false otherhise.
         */
        bool EncapsulateMessage(const char *message, const std::string messageTag, std::string *outBuffer);

        /** @brief Send the HELLO message. */
        lwmqtt_err_t SendHelloMessage();

        /** @brief Subscribe to required topic. */
        lwmqtt_err_t Subscribe();

        /**
         * @brief Update the MQTT connection state.
         *
         * @param[in] state State of the MQTT connection.
         * @param[in] code Error code associated to the state.
         */
        void UpdateConnectionState(MQTTConnectionInfo::State state, const lwmqtt_err_t code=LWMQTT_SUCCESS);

        /**
         * @brief Update the MQTT broker IP address.
         *
         * @param[in] fd File descriptor of the MQTT connection.
         */
        void UpdateBrokerIpAddr(int fd);

        /**
         * @brief Update MQTT ack statistics with a new duration.
         *
         * @param[in] duration Time to receive the MQTT ack.
         */
        void UpdateMqttAckTime(std::chrono::duration<double> duration);

        /**
         *  TODO:Benoit  Initiliaze MQTT Client parameters and Tls/Socket
        */            

        virtual lwmqtt_err_t ConnectingToBroker(int *fd) = 0;

        virtual void NetworkInit(string mqttHost,
                   int mqttHostPort,
                   bool validateMqttHostCert,
                   string deviceCertPath,
                   string deviceKeyPath,
                   string caCertPath)  {};

        virtual void NetworkDisconnect() = 0;

        virtual bool NetworkIsConnected() = 0;

        virtual lwmqtt_err_t NetworkPeek(size_t*) = 0;

        void PrintDebugVariable();
        
};

#endif /* __MQTT_CLIENT_H__ */
