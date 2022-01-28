#include <stdio.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/vfs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <linux/rtc.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <assert.h>
#include <dirent.h>
#include <libgen.h>
#include <linux/i2c-dev.h>
#include <sys/sem.h>
#include <sys/ipc.h>
#include <sys/syscall.h> 

#include "Socket.h"
#include "config.h"
extern "C" {
#include <lwmqtt.h>
#include <lwmqtt/unix.h>
}

#include <iostream>
using namespace std;
#include <cpr/cpr.h>

extern int
getSysUptime(void)
{
   	FILE *fd;
	char buf[256];

	fd = fopen ("/proc/uptime", "r");
	if(fd==NULL){
		perror("fopen");
		return -1;
	}
    if( fread( buf, sizeof(buf), 1, fd) <= 0 && ferror(fd)){
		fclose(fd);
		perror("fread");
		return -1;
	}
	fclose(fd);
	return atoi(buf);
}


#include "MQTTClient.h"


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

/**
 * @brief MQTT keepalive interval.
 *
 * Will send out a Ping request at the specified Keepalive interval and
 * expect a response to be received before that same period passes again.
 */
#define MQTT_WIRED_DEVICE_KEEPALIVE_INTERVAL_SECS 30

/* Mesh devices need a little more grace. */
#ifdef CONFIG_GLENLIVET
/* Broadcom AP's radio can flap down and then up on VAP add/delete (amongst
 * other events) causing a temporary loss of connection.
 * Increasing the interval to 2 minutes to take into account the possibility
 * of the channel changing to a DFS and needing to wait for the 60
 * second CAC plus additional scan time connect time.
 */
#define MQTT_WIRELESS_DEVICE_KEEPALIVE_INTERVAL_SECS 150
#else
#define MQTT_WIRELESS_DEVICE_KEEPALIVE_INTERVAL_SECS 90
#endif

#define MAC_IS_ZERO(mac) (              \
    !((((__u16 *)(mac))[0] ^ 0x0000 ) | \
      (((__u16 *)(mac))[1] ^ 0x0000 ) | \
      (((__u16 *)(mac))[2] ^ 0x0000 )))  \

static const char *lwmqtt_strerr(lwmqtt_err_t err)
{
    switch (err) {
        case LWMQTT_SUCCESS:
            return "SUCCESS";
        case LWMQTT_BUFFER_TOO_SHORT:
            return "BUFFER_TOO_SHORT";
        case LWMQTT_VARNUM_OVERFLOW:
            return "VARNUM_OVERFLOW";
        case LWMQTT_NETWORK_FAILED_CONNECT:
            return "NETWORK_FAILED_CONNECT";
        case LWMQTT_NETWORK_TIMEOUT:
            return "NETWORK_TIMEOUT";
        case LWMQTT_NETWORK_FAILED_READ:
            return "NETWORK_FAILED_READ";
        case LWMQTT_NETWORK_FAILED_WRITE:
            return "NETWORK_FAILED_WRITE";
        case LWMQTT_REMAINING_LENGTH_OVERFLOW:
            return "REMAINING_LENGTH_OVERFLOW";
        case LWMQTT_REMAINING_LENGTH_MISMATCH:
            return "REMAINING_LENGTH_MISMATCH";
        case LWMQTT_MISSING_OR_WRONG_PACKET:
            return "MISSING_OR_WRONG_PACKET";
        case LWMQTT_CONNECTION_DENIED:
            return "CONNECTION_DENIED";
        case LWMQTT_FAILED_SUBSCRIPTION:
            return "FAILED_SUBSCRIPTION";
        case LWMQTT_SUBACK_ARRAY_OVERFLOW:
            return "SUBACK_ARRAY_OVERFLOW";
        case LWMQTT_PONG_TIMEOUT:
            return "PONG_TIMEOUT";
        case LWMQTT_INTERNAL_ERROR:
            return "INTERNAL_ERROR";
    }

    return "unknown error";
}

void lwmqtt_message_callback_c_wrapper(lwmqtt_client_t *client, void *ref, lwmqtt_string_t topic, lwmqtt_message_t msg)
{
    auto& callback = *reinterpret_cast<lwmqttMessageCallbackFunc*>(ref);
    callback(client, NULL, topic, msg);
}
#if NOUV
static bool isCloudSessionSequenceValid(const std::string &cloudSessionSequence)
{
    if (cloudSessionSequence.empty()) {
        return false;
    }

    // The string should be a number.
    return std::find_if(cloudSessionSequence.begin(),
            cloudSessionSequence.end(),
            [](unsigned char c) { return !std::isdigit(c); }) == cloudSessionSequence.end();
}
#endif // if NOUV
void MQTTClient::PrintParameters()
{
    cout << "---    Parametres    ---" << endl;
    cout << mStarted << endl;;
    cout << mCloudSessionSequence << endl;
    cout << mOnboardingCaCertPath << endl;

    cout << mDeviceID << endl;
    cout << mPublishTopicBase << endl;
    
    // IMPORTANT: Benoit Donnees prises dans le AP11D

    // Set the device ID.
    cout << mDeviceID << endl; 

    // Set the base MQTT topic.
    cout << mPublishTopicBase << endl;
    cout << "---                  ---" << endl;

}


MQTTClient::MQTTClient(string mqttHost,
                       int mqttHostPort,
                       bool validateMqttHostCert,
                       string deviceCertPath,
                       string deviceKeyPath,
                       string caCertPath,
                       string onboardingCaCertPath,
                       OnConnectCallbackPtr onConnectCallback,
                       OnDisconnectCallbackPtr onDisconnectCallback,
                       OnMessageCallbackPtr onMessageCallback)
{
    mStarted = false;
    mCloudSessionSequence = 0;
    mOnboardingCaCertPath = onboardingCaCertPath;
    mOnConnectCallback = onConnectCallback;
    mOnDisconnectCallback = onDisconnectCallback;
    mOnMessageCallback = onMessageCallback;

    memset((char*)&mConnectionInfo, 0, sizeof(mConnectionInfo));  // Benoit j'avais commenté pourquoi ? A cause de l'erreur de pointeur
    mConnectionInfo.mState.mState = MQTTConnectionInfo::State::INACTIVE;
    mConnectionInfo.mState.mUptime = getSysUptime();

    mDeviceID = "20:4c:03:90:e0:56";  // Mon AP11D
    mPublishTopicBase = "DevStackSSO/";
    mPublishTopicBase += "pm/" + mDeviceID + "/v2/";

    // IMPORTANT: Benoit Donnees prises dans le AP11D
#if AP
    // Get device info.
    gsm_channel_device_info_key_t device_info_key;
    gsm_channel_onboarding_key_t onboarding_key;

    GSM_CHANNEL_DEVICE_INFO_KEY_DEFAULT_INIT(&device_info_key);
    GSM_CHANNEL_ONBOARDING_KEY_DEFAULT_INIT(&onboarding_key);

    gsm_result_t result = gsm_object_lookup(GSM_CHANNEL_DEVICE_INFO,
                                            &device_info_key,
                                            &mDeviceInfo);
    if (result != GSM_RESULT_SUCCESS) {
        throw std::runtime_error("Failed to get device info from GSM: " +
                                 string(gsm_result_names[result]) +
                                 " (" +
                                 std::to_string(result) +
                                 ").");
    }

#ifdef GSM_SECTION_DEVICE_INFO_BLE_SUPPORTED
    {
        gsm_section_device_info_ble_struct_t ble;
        result = gsm_section_lookup(GSM_CHANNEL_DEVICE_INFO,
            GSM_SECTION_BLE,
            &device_info_key,
            sizeof(ble),
            &ble);
        if (result == GSM_RESULT_SUCCESS) {
            mBleMacAddress = mac_to_str(ble.mac.addr);
        }
        else {
            throw std::runtime_error("Failed to get device info ble from GSM: " +
                                     string(gsm_result_names[result]) +
                                     " (" +
                                     std::to_string(result) +
                                     ").");
        }
    }
#endif

#ifdef GSM_SECTION_DEVICE_INFO_DRT_SUPPORTED
    {
        gsm_section_device_info_drt_struct_t drt;
        result = gsm_section_lookup(GSM_CHANNEL_DEVICE_INFO,
            GSM_SECTION_DRT,
            &device_info_key,
            sizeof(drt),
            &drt);
        if (result == GSM_RESULT_SUCCESS) {
            mDrtVersion = drt.version;
        }
        else {
            throw std::runtime_error("Failed to get device info drt from GSM: " +
                                     string(gsm_result_names[result]) +
                                     " (" +
                                     std::to_string(result) +
                                     ").");
        }
    }
#endif

    // Get onboarding global state.
    result = gsm_section_lookup(GSM_CHANNEL_ONBOARDING,
                                GSM_SECTION_GLOBAL_STATE,
                                &onboarding_key,
                                sizeof(mOnboardingGlobalState),
                                &mOnboardingGlobalState);
    if (result != GSM_RESULT_SUCCESS) {
        throw std::runtime_error("Failed to get onboarding global state from GSM: " +
                                 string(gsm_result_names[result]) +
                                 " (" +
                                 std::to_string(result) +
                                 ").");
    }

    // Get onboarding URL.
    {
        gsm_section_onboarding_config_struct_t cfg;

        result = gsm_section_lookup(GSM_CHANNEL_ONBOARDING,
            GSM_SECTION_CONFIG,
            &onboarding_key,
            sizeof(cfg),
            &cfg);
        if (result == GSM_RESULT_SUCCESS) {
            mOnboardingUrl = cfg.server_url;
        }
        else {
            throw std::runtime_error("Failed to get onboarding URL from GSM: " +
                                 string(gsm_result_names[result]) +
                                 " (" +
                                 std::to_string(result) +
                                 ").");
        }
    }

    // Get the MQTT prefix from GSM.
    char mqtt_topic_prefix_buf[GSM_ONBOARDING_FIELD_MQTT_TOPIC_PREFIX_ARRAY_SIZE];
    result = gsm_section_field_lookup(GSM_CHANNEL_ONBOARDING,
                                      GSM_SECTION_STATE,
                                      GSM_FIELD_MQTT_TOPIC_PREFIX,
                                      &onboarding_key,
                                      sizeof(mqtt_topic_prefix_buf),
                                      mqtt_topic_prefix_buf);

    if (result != GSM_RESULT_SUCCESS) {
        throw std::runtime_error("Failed to get MQTT topic prefix from GSM: " +
                                 string(gsm_result_names[result]) +
                                 " (" +
                                 std::to_string(result) +
                                 ").");
    }
#endif // #if AP
    std::string mqtt_topic_prefix = "DevStackSSO/"; // mqtt_topic_prefix_buf;

    // Set the device ID.
    mDeviceID = "DevStackSSO/"; // mac_to_str(mDeviceInfo.base_mac.addr); 

    // Set the base MQTT topic.
    mPublishTopicBase = mqtt_topic_prefix + "pm/" + mDeviceID + "/v2/";

    // Set the topic for the HELLO message.
    mHelloTopic = mPublishTopicBase + "hello";

    // Set the topic to which we subscribe.
    mSubscribeTopicBase = "device/" + mDeviceID;
    mSubscribeTopic = mSubscribeTopicBase + "/#";

    // Set the topic to which we publish devconf messages.
    mDevconfTopic = mPublishTopicBase + "devconf";

    // Initialize the MQTT client.
    lwmqtt_init(&mMqttClient,  // Benoit Buffer seulement
                (uint8_t*)malloc(MAX_BUFFER_SIZE),
                MAX_BUFFER_SIZE,
                (uint8_t*)malloc(MAX_BUFFER_SIZE),
                MAX_BUFFER_SIZE);

    // Create a function object encapsulating the message callback.  Pointer
    // to this object is passed to the c-callback wrapper.
    mLwmqttMessageCallbackFunc = std::bind(&MQTTClient::SubscribeCallback,
                                           this,
                                           std::placeholders::_1,
                                           std::placeholders::_2,
                                           std::placeholders::_3,
                                           std::placeholders::_4);

   NetworkInit(mqttHost, mqttHostPort, validateMqttHostCert, deviceCertPath, deviceKeyPath, caCertPath);

    InitTimer();

    PrintParameters();
    cout << "Start()" << endl;
    Start();
}

MQTTClient::~MQTTClient()
{
    Stop();
}


void MQTTClient::ConnectionSMTimerCallback(ev::timer &watcher, int revents)
{
    MQTTConnectionInfo::State origState = mConnectionInfo.mState.mState;

    /*
     * INACTIVE
     */
    if (mConnectionInfo.mState.mState == MQTTConnectionInfo::State::INACTIVE) {
        std::cout << "(mConnectionInfo.mState.mState == MQTTConnectionInfo::State::INACTIVE) \n"; 
        UpdateConnectionState(MQTTConnectionInfo::State::DISCONNECTED);

    }

    /*
     * DISCONNECTED
     */
    if (mConnectionInfo.mState.mState == MQTTConnectionInfo::State::DISCONNECTED) {
        std::cout << "(mConnectionInfo.mState.mState == MQTTConnectionInfo::State::DISCONNECTED)\n"; 
        UpdateConnectionState(MQTTConnectionInfo::State::GETTING_CLOUD_SESSION_SEQUENCE);
    }

    /*
     * GETTING_CLOUD_SESSION_SEQUENCE
     */
    if (mConnectionInfo.mState.mState == MQTTConnectionInfo::State::GETTING_CLOUD_SESSION_SEQUENCE) {
        std::cout << "(mConnectionInfo.mState.mState == MQTTConnectionInfo::State::GETTING_CLOUD_SESSION_SEQUENCE)\n"; 
        static unsigned int numTries = 0;
        mCloudSessionSequence = 0;
        mCloudSessionSequenceError.clear();

        lwmqtt_err_t rc = LWMQTT_INTERNAL_ERROR;

        printf("Fetching cloud session sequence...\n");
        {
            PrintParameters();
            mOnboardingUrl =  "https://devstacksso-nb.isb.arubanetworks.com/onboard";
            cpr::SslOptions sslOpts = cpr::Ssl(cpr::ssl::CaInfo{mOnboardingCaCertPath.c_str()});
            cpr::Response r = cpr::Get(cpr::Url{mOnboardingUrl},
                                       cpr::Timeout{5000},
                                       cpr::VerifySsl{true},
                                       sslOpts);
            printf("iot.isb.arubanetworks.com -- %s\n", mOnboardingUrl.c_str());
            if (r.error) {
                if (r.error.code == cpr::ErrorCode::OPERATION_TIMEDOUT) {
                    rc = LWMQTT_NETWORK_TIMEOUT;
                    printf("LWMQTT_NETWORK_TIMEOUT\n");
                }
                else if (r.error.code == cpr::ErrorCode::NETWORK_RECEIVE_ERROR) {
                    rc = LWMQTT_NETWORK_FAILED_READ;
                    printf("LWMQTT_NETWORK_FAILED_READ\n");
                }
                else if (r.error.code == cpr::ErrorCode::INTERNAL_ERROR) {
                    rc = LWMQTT_INTERNAL_ERROR;
                    printf("LWMQTT_INTERNAL_ERROR\n");
                }
                else {
                    rc = LWMQTT_NETWORK_FAILED_CONNECT;
                    printf("LWMQTT_NETWORK_FAILED_CONNECT\n");
                }
                
                mCloudSessionSequenceError = "HTTP GET failure: " + r.error.message;
                printf("Could not fetch cloud session sequence: %s\n",
                        r.error.message.c_str());
            }
            else if (r.status_code != 200) {
                rc = LWMQTT_NETWORK_FAILED_CONNECT;
                mCloudSessionSequenceError = "HTTP GET failure: HTTP code " + std::to_string(r.status_code);
                printf("Could not fetch cloud session sequence: HTTP code %ld\n",
                        r.status_code);
            }
            else if (r.header.count("date") == 0) {
                rc = LWMQTT_INTERNAL_ERROR;
                mCloudSessionSequenceError = "HTTP date header missing";
                printf("Could not fetch cloud session sequence: "
                        "no HTTP 'date' header received.\n");
            }
            else {
                // Convert to seconds since Epoch.
                time_t timestamp = curl_getdate(r.header["date"].c_str(), NULL);
                if (timestamp != -1) {
                    mCloudSessionSequence = timestamp;
                    printf("Cloud session sequence fetched successfully: %lu\n", mCloudSessionSequence);
                }
                else {
                    rc = LWMQTT_INTERNAL_ERROR;
                    mCloudSessionSequenceError = "Invalid HTTP date: " + r.header.count("date");
                    printf("Could not fetch cloud session sequence: "
                            "error converting time '%s'.",
                            r.header["date"].c_str());
                }
            }
        }

        numTries++;
        if (mCloudSessionSequence > 0) {
            // Got it.
            UpdateConnectionState(MQTTConnectionInfo::State::CONNECTING_TO_BROKER);
            numTries = 0;
        }
        else if (numTries == MAX_CLOUD_SESSION_SEQUENCE_FETCH_TRIES) {
            // Give up.
            printf("Could not fetch cloud session sequence, giving up.\n");
            UpdateConnectionState(MQTTConnectionInfo::State::CONNECTING_TO_BROKER);
            numTries = 0;
        }
        else {
            TriggerDisconnect(rc);
        }
    }

    /*
     * CONNECTING_TO_BROKER
     */
    if (mConnectionInfo.mState.mState == MQTTConnectionInfo::State::CONNECTING_TO_BROKER) {
        printf("Starting connection to broker...\n");

        lwmqtt_err_t rc;
        int fd;
        rc =  ConnectingToBroker(&fd);
        if (rc == LWMQTT_SUCCESS) {
            printf("Connection to broker succeeded.\n");
            UpdateConnectionState(MQTTConnectionInfo::State::CONNECTING_TO_MQTT);
            UpdateBrokerIpAddr(fd);
        }
        else {
            printf("Connection to broker failed: %s.\n", lwmqtt_strerr(rc));
            //UpdateConnectionState(mConnectionInfo.mState.mState, &rc);
            TriggerDisconnect(rc);
        }
        
    }

    /*
     * CONNECTING_TO_MQTT
     */
    if (mConnectionInfo.mState.mState == MQTTConnectionInfo::State::CONNECTING_TO_MQTT) {
        printf("Sending MQTT connect...\n");

        lwmqtt_err_t rc;
        lwmqtt_return_code_t return_code;
        lwmqtt_options_t options = lwmqtt_default_options;

        options.client_id = lwmqtt_string(mDeviceID.c_str());
        options.keep_alive = MQTT_WIRED_DEVICE_KEEPALIVE_INTERVAL_SECS*6;

#ifdef GSM_CHANNEL_MESH_UPLINK_SUPPORTED
        gsm_channel_mesh_uplink_key_t key;

        GSM_CHANNEL_MESH_UPLINK_KEY_DEFAULT_INIT(&key);
        key.radio_index = 0;

        GSM_SECTION_MESH_UPLINK_STATE_DEFAULT_INIT(&mMeshUplinkState);

        if (gsm_section_lookup(GSM_CHANNEL_MESH_UPLINK,
                                GSM_SECTION_STATE,
                                &key,
                                sizeof(gsm_section_mesh_uplink_state_struct_t),
                                &mMeshUplinkState) == GSM_RESULT_SUCCESS) {
            // Mesh Point - increase the connection timeout
            options.keep_alive = MQTT_WIRELESS_DEVICE_KEEPALIVE_INTERVAL_SECS;
            printf("Mesh Point: increasing MQTT Timeout to %u", MQTT_WIRELESS_DEVICE_KEEPALIVE_INTERVAL_SECS);
        }
#endif
    // sleep(2);  // Benoit ?

        rc = lwmqtt_connect(&mMqttClient, options, NULL, &return_code, MQTT_COMMAND_TIMEOUT_MSEC);
        if (rc == LWMQTT_SUCCESS) {
            printf("MQTT connect succeeded.\n");
            UpdateConnectionState(MQTTConnectionInfo::State::SUBSCRIBING);
        }
        else {
            printf("MQTT connect failed: %s (%d).\n", lwmqtt_strerr(rc), return_code);
            //UpdateConnectionState(mConnectionInfo.mState.mState, &rc);
            TriggerDisconnect(rc);
        }
    }
    // sleep(2); // Benoit ?
    /*
     * SUBSCRIBING
     */
    if (mConnectionInfo.mState.mState == MQTTConnectionInfo::State::SUBSCRIBING) {
        printf("Subscribing to topic '%s'...\n", mSubscribeTopic.c_str());

        lwmqtt_err_t rc = Subscribe();
        if (rc == LWMQTT_SUCCESS) {
            printf("Subscribed to topic '%s' successfully.\n",
                              mSubscribeTopic.c_str());
            UpdateConnectionState(MQTTConnectionInfo::State::SENDING_HELLO);
        }
        else {
            printf("Failed to subscribe to topic '%s'", lwmqtt_strerr(rc));
            //UpdateConnectionState(mConnectionInfo.mState.mState, &rc);
            TriggerDisconnect(rc);
        }
    }

    /*
     * SENDING_HELLO
     */
    if (mConnectionInfo.mState.mState == MQTTConnectionInfo::State::SENDING_HELLO) {
        printf("Publishing HELLO message on topic '%s'...\n", mHelloTopic.c_str());

        lwmqtt_err_t rc = LWMQTT_SUCCESS; //SendHelloMessage();
        if (rc == LWMQTT_SUCCESS) {
            printf("Published HELLO message on topic '%s' successfully.\n",
                              mHelloTopic.c_str());
            mConnectionInfo.mState.mState = MQTTConnectionInfo::State::CONNECTED;
            UpdateConnectionState(MQTTConnectionInfo::State::CONNECTED);
        }
        else {
            printf("Failed to publish HELLO message on topic '%s'\n", lwmqtt_strerr(rc));
            //UpdateConnectionState(mConnectionInfo.mState.mState, &rc);
            TriggerDisconnect(rc);
        }
    }

    /*
     * CONNECTED
     */
    if (mConnectionInfo.mState.mState == MQTTConnectionInfo::State::CONNECTED) {
        // Adjust stats.
        if (origState != MQTTConnectionInfo::State::CONNECTED) {
            mConnectionInfo.mCurrentConnectionUptime = getSysUptime();
        }

        // Start the network timer.
        if (origState != MQTTConnectionInfo::State::CONNECTED) {
            mNetworkTimer.start(0.25, 0.25);
        }

        // Invoke the registered callback.
        if (origState != MQTTConnectionInfo::State::CONNECTED && mOnConnectCallback) {
            mOnConnectCallback();
        }
    }
}

void MQTTClient::NetworkTimerCallback(ev::timer &watcher, int revents)
{
    lwmqtt_err_t rc;
    size_t available = 0;

    if (mConnectionInfo.mState.mState != MQTTConnectionInfo::State::CONNECTED) {
        return;
    }

    // Check if data is available.
    rc = NetworkPeek(&available);
    if (rc != LWMQTT_SUCCESS) {
        printf("Failed to check available data: %s.", lwmqtt_strerr(rc));
        TriggerDisconnect(rc);
        return;
    }
    // Process data if available.
    else if (available > 0) {
        rc = lwmqtt_yield(&mMqttClient, available, MQTT_COMMAND_TIMEOUT_MSEC);
        if (rc != LWMQTT_SUCCESS) {
            printf("Failed to process available data: %s.", lwmqtt_strerr(rc));
            TriggerDisconnect(rc);
            return;
        }
    }

    // Keep connection alive.
    rc = lwmqtt_keep_alive(&mMqttClient, MQTT_COMMAND_TIMEOUT_MSEC);
    if (rc != LWMQTT_SUCCESS) {
        printf("Keepalive failed: %s.", lwmqtt_strerr(rc));
        TriggerDisconnect(rc);
        return;
    }
}
 #if AP
void MQTTClient::GSMTimerCallback(ev::timer &watcher, int revents)
{
    gsm_result_t result;
    gsm_channel_cloudconnect_key_t gsmKey;

    GSM_CHANNEL_CLOUDCONNECT_KEY_DEFAULT_INIT(&gsmKey);

    // MQTT connection state.
    {
        gsm_section_cloudconnect_mqtt_client_state_struct_t obj;
        gsm_mqtt_client_state_t gsmState = GSM_NUM_MQTT_CLIENT_STATES;

        GSM_SECTION_CLOUDCONNECT_MQTT_CLIENT_STATE_DEFAULT_INIT(&obj);

        // Convert the state.
        switch(mConnectionInfo.mState.mState) {
            case MQTTConnectionInfo::State::INACTIVE:
                gsmState = GSM_MQTT_CLIENT_STATE_INACTIVE;
                break;
            case MQTTConnectionInfo::State::DISCONNECTED:
            case MQTTConnectionInfo::State::GETTING_CLOUD_SESSION_SEQUENCE:
            case MQTTConnectionInfo::State::CONNECTING_TO_BROKER:
            case MQTTConnectionInfo::State::CONNECTING_TO_MQTT:
                gsmState = GSM_MQTT_CLIENT_STATE_CONNECTING;
                break;
            case MQTTConnectionInfo::State::SUBSCRIBING:
                gsmState = GSM_MQTT_CLIENT_STATE_SUBSCRIBING;
                break;
            case MQTTConnectionInfo::State::SENDING_HELLO:
                gsmState = GSM_MQTT_CLIENT_STATE_SENDING_HELLO_MSG;
                break;
            case MQTTConnectionInfo::State::CONNECTED:
                gsmState = GSM_MQTT_CLIENT_STATE_CONNECTED;
                break;
        }

        GSM_SET_FIELD_CLOUDCONNECT_MQTT_CLIENT_STATE_STATE(&obj, gsmState);
        GSM_SET_FIELD_CLOUDCONNECT_MQTT_CLIENT_STATE_UPTIME(&obj, mConnectionInfo.mState.mUptime);
        GSM_SET_FIELD_CLOUDCONNECT_MQTT_CLIENT_STATE_RETRIES(&obj, mConnectionInfo.mState.mRetries);
        if (mConnectionInfo.mState.mCode != LWMQTT_SUCCESS) {
            GSM_SET_FIELD_CLOUDCONNECT_MQTT_CLIENT_STATE_CODE(&obj, mConnectionInfo.mState.mCode);
            GSM_SET_FIELD_CLOUDCONNECT_MQTT_CLIENT_STATE_CODE_DESC(&obj, lwmqtt_strerr(mConnectionInfo.mState.mCode));
        }

        result = gsm_section_update(GSM_CHANNEL_CLOUDCONNECT,
                                    GSM_SECTION_MQTT_CLIENT_STATE,
                                    &gsmKey,
                                    sizeof(obj),
                                    &obj);

        if (result != GSM_RESULT_SUCCESS) {
            GLERROR_MQTTCLIENT("Failed to update MQTT connection state in GSM: %s.",
                               gsm_result_names[result]);
        }
    }

    // MQTT connection stats.
    {
        gsm_section_cloudconnect_mqtt_connection_struct_t obj;

        GSM_SECTION_CLOUDCONNECT_MQTT_CONNECTION_DEFAULT_INIT(&obj);

        GSM_SET_FIELD_CLOUDCONNECT_MQTT_CONNECTION_NUM_DISCONNECTIONS(&obj, mConnectionInfo.mDisconnects);
        if (mConnectionInfo.mLastDisconnectionError != LWMQTT_SUCCESS) {
            GSM_SET_FIELD_CLOUDCONNECT_MQTT_CONNECTION_LAST_DISCONNECTION_CODE(&obj, mConnectionInfo.mLastDisconnectionError);
            GSM_SET_FIELD_CLOUDCONNECT_MQTT_CONNECTION_LAST_DISCONNECTION_CODE_DESC(&obj, mConnectionInfo.mLastDisconnectionErrorStr.c_str());
        }
        if (mConnectionInfo.mLastConnectionDuration > 0) {
            GSM_SET_FIELD_CLOUDCONNECT_MQTT_CONNECTION_LAST_CONNECTION_DURATION(&obj, mConnectionInfo.mLastConnectionDuration);
        }
        if (mConnectionInfo.mAverageConnectionDuration.get() > 0) {
            GSM_SET_FIELD_CLOUDCONNECT_MQTT_CONNECTION_AVERAGE_CONNECTION_DURATION(&obj, mConnectionInfo.mAverageConnectionDuration.get());
        }
        if (mConnectionInfo.mCurrentConnectionUptime > 0) {
            GSM_SET_FIELD_CLOUDCONNECT_MQTT_CONNECTION_CURRENT_CONNECTION_UPTIME(&obj, mConnectionInfo.mCurrentConnectionUptime);
        }
        if (IS_V4(mConnectionInfo.mBrokerIpAddr) || IS_V6(mConnectionInfo.mBrokerIpAddr)) {
            GSM_SET_FIELD_CLOUDCONNECT_MQTT_CONNECTION_BROKER_IP(&obj, mConnectionInfo.mBrokerIpAddr);
        }

        result = gsm_section_update(GSM_CHANNEL_CLOUDCONNECT,
                                    GSM_SECTION_MQTT_CONNECTION,
                                    &gsmKey,
                                    sizeof(obj),
                                    &obj);

        if (result != GSM_RESULT_SUCCESS) {
            GLERROR_MQTTCLIENT("Failed to update MQTT connection stats in GSM: %s.",
                               gsm_result_names[result]);
        }
    }

    // MQTT ack stats.
    {
        gsm_section_cloudconnect_mqtt_ack_time_struct_t obj;

        GSM_SECTION_CLOUDCONNECT_MQTT_ACK_TIME_DEFAULT_INIT(&obj);

        if (mConnectionInfo.mAckTimes.mSinceBeginning.get() > 0) {
            GSM_SET_FIELD_CLOUDCONNECT_MQTT_ACK_TIME_SINCE_BEGINNING(&obj, mConnectionInfo.mAckTimes.mSinceBeginning.get());
        }
        if (mConnectionInfo.mAckTimes.mPeakSinceBeginning > 0) {
            GSM_SET_FIELD_CLOUDCONNECT_MQTT_ACK_TIME_PEAK_SINCE_BEGINNING(&obj, mConnectionInfo.mAckTimes.mPeakSinceBeginning);
        }
        if (mConnectionInfo.mAckTimes.mCurrentConnection.get() > 0) {
            GSM_SET_FIELD_CLOUDCONNECT_MQTT_ACK_TIME_CURRENT_CONNECTION(&obj, mConnectionInfo.mAckTimes.mCurrentConnection.get());
        }
        if (mConnectionInfo.mAckTimes.mPeakCurrentConnection > 0) {
            GSM_SET_FIELD_CLOUDCONNECT_MQTT_ACK_TIME_PEAK_CURRENT_CONNECTION(&obj, mConnectionInfo.mAckTimes.mPeakCurrentConnection);
        }
        if (mConnectionInfo.mAckTimes.mLastConnection > 0) {
            GSM_SET_FIELD_CLOUDCONNECT_MQTT_ACK_TIME_LAST_CONNECTION(&obj, mConnectionInfo.mAckTimes.mLastConnection);
        }
        if (mConnectionInfo.mAckTimes.mPeakLastConnection > 0) {
            GSM_SET_FIELD_CLOUDCONNECT_MQTT_ACK_TIME_PEAK_LAST_CONNECTION(&obj, mConnectionInfo.mAckTimes.mPeakLastConnection);
        }
        UpdateMqttAckTime(std::chrono::milliseconds(0)); // Clean historical data.
        if (mConnectionInfo.mAckTimes.mHistoricalData.size() > 0) {
            // Calculate the average and peak.
            uint32_t peak = 0;
            IterativeMean<uint32_t> average;
            for (const auto &e : mConnectionInfo.mAckTimes.mHistoricalData) {
                if (e.second > peak) {
                    peak = e.second;
                }
                average.add(e.second);
            }
            GSM_SET_FIELD_CLOUDCONNECT_MQTT_ACK_TIME_LAST_5_MIN(&obj, average.get());
            GSM_SET_FIELD_CLOUDCONNECT_MQTT_ACK_TIME_PEAK_LAST_5_MIN(&obj, peak);
        }
        if (mConnectionInfo.mAckTimes.mLastMessage > 0) {
            GSM_SET_FIELD_CLOUDCONNECT_MQTT_ACK_TIME_LAST_MESSAGE(&obj, mConnectionInfo.mAckTimes.mLastMessage);
        }

        result = gsm_section_update(GSM_CHANNEL_CLOUDCONNECT,
                                    GSM_SECTION_MQTT_ACK_TIME,
                                    &gsmKey,
                                    sizeof(obj),
                                    &obj);

        if (result != GSM_RESULT_SUCCESS) {
            GLERROR_MQTTCLIENT("Failed to update MQTT ack stats in GSM: %s.",
                               gsm_result_names[result]);
        }
    }

    // MQTT messages.
    {
        gsm_section_cloudconnect_mqtt_message_struct_t obj;

        GSM_SECTION_CLOUDCONNECT_MQTT_MESSAGE_DEFAULT_INIT(&obj);

        GSM_SET_FIELD_CLOUDCONNECT_MQTT_MESSAGE_TX_TOTAL(&obj, mConnectionInfo.mMessages.mTxTotal);
        GSM_SET_FIELD_CLOUDCONNECT_MQTT_MESSAGE_TX_CURRENT_CONNECTION(&obj, mConnectionInfo.mMessages.mTxCurrentConnection);
        GSM_SET_FIELD_CLOUDCONNECT_MQTT_MESSAGE_TX_LAST_CONNECTION(&obj, mConnectionInfo.mMessages.mTxLastConnection);
        GSM_SET_FIELD_CLOUDCONNECT_MQTT_MESSAGE_TX_DROPPED_TOTAL(&obj, mConnectionInfo.mMessages.mTxDroppedTotal);
        GSM_SET_FIELD_CLOUDCONNECT_MQTT_MESSAGE_TX_DROPPED_LAST_DISCONNECTION(&obj, mConnectionInfo.mMessages.mTxDroppedLastDisconnection);
        GSM_SET_FIELD_CLOUDCONNECT_MQTT_MESSAGE_TX_LAST_SIZE(&obj, mConnectionInfo.mMessages.mTxSizeLast);
        GSM_SET_FIELD_CLOUDCONNECT_MQTT_MESSAGE_TX_PEAK_SIZE(&obj, mConnectionInfo.mMessages.mTxSizePeak);
        GSM_SET_FIELD_CLOUDCONNECT_MQTT_MESSAGE_RX_LAST_SIZE(&obj, mConnectionInfo.mMessages.mRxSizeLast);
        GSM_SET_FIELD_CLOUDCONNECT_MQTT_MESSAGE_RX_PEAK_SIZE(&obj, mConnectionInfo.mMessages.mRxSizePeak);

        result = gsm_section_update(GSM_CHANNEL_CLOUDCONNECT,
                                    GSM_SECTION_MQTT_MESSAGE,
                                    &gsmKey,
                                    sizeof(obj),
                                    &obj);

        if (result != GSM_RESULT_SUCCESS) {
            GLERROR_MQTTCLIENT("Failed to update MQTT messgage stats in GSM: %s.",
                               gsm_result_names[result]);
        }
    }

    // Update the timestamp.
    {
        gsm_section_cloudconnect_state_struct_t obj;

        GSM_SECTION_CLOUDCONNECT_STATE_DEFAULT_INIT(&obj);

        GSM_SET_FIELD_CLOUDCONNECT_STATE_UPTIME(&obj, getSysUptimeMillisec());

        result = gsm_section_update(GSM_CHANNEL_CLOUDCONNECT,
                                    GSM_SECTION_STATE,
                                    &gsmKey,
                                    sizeof(obj),
                                    &obj);

        if (result != GSM_RESULT_SUCCESS) {
            GLERROR_MQTTCLIENT("Failed to update state in GSM: %s.",
                               gsm_result_names[result]);
        }
    }
}
#endif // #if AP
void MQTTClient::TriggerDisconnect(lwmqtt_err_t rc)
{
    BTraceIn
    bool wasConnected = (mConnectionInfo.mState.mState == MQTTConnectionInfo::State::CONNECTED);
    
    printf("Triggering MQTT disconnect (%s), was %s.", lwmqtt_strerr(rc), wasConnected ? "conneceted" : "unconnected");

    NetworkDisconnect();

    mNetworkTimer.stop();

    UpdateConnectionState(MQTTConnectionInfo::State::DISCONNECTED, rc);
    if (wasConnected) {
        uint32_t now = getSysUptime();

        mConnectionInfo.mDisconnects++;
        mConnectionInfo.mLastDisconnectionError = rc;
        mConnectionInfo.mLastDisconnectionErrorStr = lwmqtt_strerr(rc);
        mConnectionInfo.mLastConnectionDuration = now - mConnectionInfo.mCurrentConnectionUptime;
        mConnectionInfo.mAverageConnectionDuration.add(mConnectionInfo.mLastConnectionDuration);
        mConnectionInfo.mCurrentConnectionUptime = 0;
        mConnectionInfo.mAckTimes.mLastConnection = mConnectionInfo.mAckTimes.mCurrentConnection.get();
        mConnectionInfo.mAckTimes.mPeakLastConnection = mConnectionInfo.mAckTimes.mPeakCurrentConnection;
        mConnectionInfo.mAckTimes.mCurrentConnection.reset();
        mConnectionInfo.mAckTimes.mPeakCurrentConnection = 0;
        mConnectionInfo.mMessages.mTxLastConnection = mConnectionInfo.mMessages.mTxCurrentConnection;
        mConnectionInfo.mMessages.mTxCurrentConnection = 0;
        mConnectionInfo.mMessages.mTxDroppedLastDisconnection = 0;

        // Invoke the registered callback.
        if (mOnDisconnectCallback) {
            mOnDisconnectCallback();
        }
    }
}

bool MQTTClient::EncapsulateMessage(const vector<byte>& message, const std::string messageTag, std::string *outBuffer)
{
#if AP
    std::string payload;

    // Encapsulate the original message.
    cloud_message::CloudMessage cloudMessage;
    if (mCloudSessionSequence > 0) {
        cloudMessage.set_cloudsessionsequence(mCloudSessionSequence);
    }
    cloudMessage.set_deviceuptimeinmilliseconds(getSysUptimeMillisec());
    cloudMessage.set_payload((char *)message.data(), message.size());
    if (!messageTag.empty()) {
        cloudMessage.set_payloadtype(messageTag);
    }

    if (!cloudMessage.SerializeToString(outBuffer)) {
        return false;
    }
    else {
        return true;
    }
#else
	return true;
#endif // #if AP
	
}

bool MQTTClient::EncapsulateMessage(const char *message, const std::string messageTag, std::string *outBuffer)
{
    vector<byte> msg(message, message + strlen(message));
    return EncapsulateMessage(msg, messageTag, outBuffer);
}
#if AP
lwmqtt_err_t MQTTClient::SendHelloMessage()
{
    // Build the payload.
    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> writer(s);

    writer.StartObject();
    writer.Key("deviceId");
    writer.String(mDeviceID.c_str());
    writer.Key("deviceModel");
    writer.String(mDeviceInfo.device_model);
    writer.Key("partition0FirmwareVersion");
    writer.String(mDeviceInfo.partition_0_firmware_version);
    writer.Key("partition0BuildNumber");
    writer.String(mDeviceInfo.partition_0_build_number);
    writer.Key("partition1FirmwareVersion");
    writer.String(mDeviceInfo.partition_1_firmware_version);
    writer.Key("partition1BuildNumber");
    writer.String(mDeviceInfo.partition_1_build_number);
    writer.Key("activeFirmwarePartition");
    writer.Uint(mDeviceInfo.active_firmware_partition);
#ifdef ION_SWITCH_PLATFORM
    if (strlen(mDeviceInfo.active_cloud_agent_version)) {
        //Used in switches only
        writer.Key("cloudAgentVersion");
        writer.String(mDeviceInfo.active_cloud_agent_version);
    }
#endif
    if (!mDrtVersion.empty()) {
        writer.Key("drtVersion");
        writer.String(mDrtVersion.c_str());
    }
    writer.Key("serialNumber");
    writer.String(mDeviceInfo.serial_number);

#ifdef GSM_CHANNEL_MESH_UPLINK_SUPPORTED
    bool fieldPresent = false;

    if (gsm_get_channel_num_objects(GSM_CHANNEL_MESH_UPLINK) != 0) {
        writer.Key("meshUplink");

        rapidjson::StringBuffer meshUplinkStringBuffer;
        rapidjson::Writer<rapidjson::StringBuffer> meshUplinkWriter(meshUplinkStringBuffer);

        writer.StartObject();

        writer.Key("recovery");
        writer.Bool(mMeshUplinkState.recovery);
        writer.Key("connected");
        writer.Bool(mMeshUplinkState.connected);
        writer.Key("uptime");
        writer.Uint(mMeshUplinkState.uptime);
        writer.Key("connectedPortalBssid");

        std::string portalMacAddress = mac_to_str(mMeshUplinkState.connected_portal_bssid.addr);
        writer.String(portalMacAddress.c_str());

        writer.Key("avgSnr");
        writer.Uint(mMeshUplinkState.avg_snr);
        writer.Key("pathCost");
        writer.Uint(mMeshUplinkState.path_cost);

        writer.EndObject();
    }
#endif

    writer.Key("macAddress");
    writer.String(mDeviceID.c_str());
    if (!mBleMacAddress.empty()) {
        writer.Key("bleMacAddress");
        writer.String(mBleMacAddress.c_str());
    }
    {
        gsm_result_t result;
        gsm_channel_device_info_key_t device_info_key;
        gsm_section_device_info_ip_struct_t device_info_ip;

        GSM_CHANNEL_DEVICE_INFO_KEY_DEFAULT_INIT(&device_info_key);

        // Get the IP address from GSM.
        result = gsm_section_lookup(GSM_CHANNEL_DEVICE_INFO,
                                    GSM_SECTION_IP,
                                    &device_info_key,
                                    sizeof(device_info_ip),
                                    &device_info_ip);

        if (result == GSM_RESULT_SUCCESS) {
            ip_addr_t ipAddr;
            __u8 plen;
            const char *ipAddrPtr;

            // Choose IPv4 if exists, else IPv6.
            if (!ZEROIP(device_info_ip.management_ipv4_address)) {
                ipAddr = device_info_ip.management_ipv4_address;
                plen = device_info_ip.management_ipv4_prefix_length;
            }
            else {
                ipAddr = device_info_ip.management_ipv6_address;
                plen = device_info_ip.management_ipv6_prefix_length;
            }

            // Convert the IP address to string.
            ipAddrPtr = aruba_ip_to_str(ipAddr);

            // Write it.
            if (ipAddrPtr) {
                string ipAddrStr = ipAddrPtr;
                ipAddrStr += "/";
                ipAddrStr += std::to_string(plen);

                writer.Key("ipAddress");
                writer.String(ipAddrStr.c_str());
            }
            else {
                GLERROR_MQTTCLIENT("Failed to convert device IP address.");
            }
        }
        else {
            GLERROR_MQTTCLIENT("Failed to get device info IP from GSM: %s.",
                               gsm_result_names[result]);
        }
    }
    writer.Key("hostname");
    writer.String("myap.local");
    writer.Key("uptimeInSeconds");
    writer.Uint(getSysUptime());
    if (mCloudSessionSequence == 0) {
        writer.Key("errors");
        writer.StartArray();
        writer.StartObject();
        writer.Key("errorType");
        writer.String("cloudSessionSequence");
        writer.Key("errorMessage");
        if (mCloudSessionSequenceError.empty()) {
            writer.String("unkown error");
        }
        else {
            writer.String(mCloudSessionSequenceError.c_str());
        }
        writer.EndObject();
        writer.EndArray();
    }
    if (mOnboardingGlobalState.onboarded) {
        //
        // The configurationVersionTag requires special handling.  In case of
        // error, we cannot just skip this field.  The device is considered, by
        // the cloud, as in factory state when this field is missing or empty.
        //
        // Thus, when a failure prevents us to properly determine the configuration
        // version tag, this function either returns a dummy tag or exits with
        // an error, without sending the HELLO message.  This will cause the
        // MQTT connection to be restarted.
        //

        gsm_result_t result;
        gsm_channel_system_key_t system_key;
        gsm_section_system_config_struct_t system_config;

        const char *cfgTag = NULL;

        GSM_CHANNEL_SYSTEM_KEY_DEFAULT_INIT(&system_key);
        GSM_SECTION_SYSTEM_CONFIG_DEFAULT_INIT(&system_config);

        // Get the configuration version tag.
        result = gsm_section_lookup(GSM_CHANNEL_SYSTEM,
                                    GSM_SECTION_CONFIG,
                                    &system_key,
                                    sizeof(system_config),
                                    &system_config);

        if (result == GSM_RESULT_SUCCESS) {
            bool fieldPresent = false;
            result = gsm_is_field_present(GSM_CHANNEL_SYSTEM,
                                          GSM_SECTION_CONFIG,
                                          GSM_FIELD_CONFIGURATION_VERSION_TAG,
                                          &system_config,
                                          &fieldPresent);
            assert(result == GSM_RESULT_SUCCESS);

            if (fieldPresent && strlen(system_config.configuration_version_tag) > 0) {
                cfgTag = system_config.configuration_version_tag;
            }
        }
        else if (result == GSM_RESULT_ERROR_HTBL_KEY_NOT_FOUND) {
            GLDEBUG_MQTTCLIENT("GSM system table entry not created yet.");
        }
        else if (result == GSM_RESULT_ERROR_SECTION_NOT_INITIALIZED) {
            GLDEBUG_MQTTCLIENT("GSM system config section not created yet.");
        }
        else {
            GLERROR_MQTTCLIENT("Failed to get system config from GSM: %s.",
                               gsm_result_names[result]);
            return LWMQTT_INTERNAL_ERROR;
        }

        // If there is no tag, we need to return a dummy tag.  Check configd
        // status to return something meaningful.
        if (!cfgTag) {
            gsm_channel_configd_key_t configd_key;
            gsm_section_configd_cfg_restore_struct_t cfg_restore;

            GSM_CHANNEL_CONFIGD_KEY_DEFAULT_INIT(&configd_key);
            GSM_SECTION_CONFIGD_CFG_RESTORE_DEFAULT_INIT(&cfg_restore);

            // Get the config restore result.
            result = gsm_section_lookup(GSM_CHANNEL_CONFIGD,
                                        GSM_SECTION_CFG_RESTORE,
                                        &configd_key,
                                        sizeof(cfg_restore),
                                        &cfg_restore);
            if (result != GSM_RESULT_SUCCESS) {
                GLERROR_MQTTCLIENT("Failed to get config restore result from GSM: %s.",
                                   gsm_result_names[result]);
                return LWMQTT_INTERNAL_ERROR;
            }

            switch (cfg_restore.result) {
                case GSM_CFG_RESTORE_RESULT_SUCCESS:
                    // This means we restored a config without a tag inside it.
                    // This can happen when configd also handles the
                    // provisioning config of the device.
                    cfgTag = "ConfigRestoreSuccess";
                    break;
                case GSM_CFG_RESTORE_RESULT_FAILURE:
                    // This can happen after a firmware upgrade, if the YANG
                    // model changed in a way that make the persistent config
                    // invalid against the new model.
                    cfgTag = "ConfigRestoreFailed";
                    break;
                case GSM_CFG_RESTORE_RESULT_CFG_DOES_NOT_EXIST:
                    // The device is connecting to the cloud for the first time
                    // after the onboarding or we lost our config file...
                    cfgTag = "ConfigRestoreNoFile";
                    break;
                case GSM_CFG_RESTORE_RESULT_NO_CFG_TO_RESTORE:
                    // This should never occur.  This means that configd has been
                    // started with wrong parameters.
                    cfgTag = "ConfigRestoreDisabled";
                    break;
                case GSM_NUM_CFG_RESTORE_RESULTS:
                    assert(cfg_restore.result != GSM_NUM_CFG_RESTORE_RESULTS);
                    break;
            }
        }

        assert(cfgTag);

        GLDEBUG_MQTTCLIENT("Including configurationVersionTag with value '%s'.",
                           cfgTag);
        writer.Key("configurationVersionTag");
        writer.String(cfgTag);
    }
    else {
        GLDEBUG_MQTTCLIENT("Device not onboarded, not including configurationVersionTag.");
    }
    writer.EndObject();

    GLDEBUG_MQTTCLIENT("Sending HELLO message: %s",
                       s.GetString());

    // Encapsulate the original message.
    std::string payload;
    if (!EncapsulateMessage(s.GetString(), "", &payload)) {
        GLERROR_MQTTCLIENT("Failed to serialize cloud message.");
        return LWMQTT_INTERNAL_ERROR;
    }

    // Send the message.
    lwmqtt_message_t msg = {
        .qos = LWMQTT_QOS1,
        .retained = false,
        .payload = (uint8_t*)payload.data(),
        .payload_len = payload.size(),
    };
    lwmqtt_err_t rc = lwmqtt_publish(&mMqttClient,
                                     lwmqtt_string(mHelloTopic.c_str()),
                                     msg,
                                     MQTT_COMMAND_TIMEOUT_MSEC);

    // Dump the content of the HELLO for debugging purpose.
    std::ofstream f("/tmp/cloudconnect_last_hello");
    if (f.is_open()) {
        f << s.GetString() << std::endl;
    }
    return rc;
}
#endif // #if AP
void MQTTClient::SubscribeCallback(lwmqtt_client_t *client, void *ref, lwmqtt_string_t topic, lwmqtt_message_t msg)
{
    string topicName = string(topic.data, topic.len);

    if (mConnectionInfo.mState.mState != MQTTConnectionInfo::State::CONNECTED) {
        printf("Ignoring received message of %ld bytes on topic '%s': "
                           "connection process not terminated yet.",
                           msg.payload_len,
                           topicName.c_str());
        return;
    }

    printf("Received a message of %ld bytes on topic '%s'.",
                       msg.payload_len,
                       topicName.c_str());

    mConnectionInfo.mMessages.mRxSizeLast = msg.payload_len;
    if (msg.payload_len > mConnectionInfo.mMessages.mRxSizePeak) {
        mConnectionInfo.mMessages.mRxSizePeak = msg.payload_len;
    }

    // Invoke the registered callback.
    if (mOnMessageCallback) {
        mOnMessageCallback(topicName, vector<byte>(msg.payload, msg.payload + msg.payload_len));
    }
}

lwmqtt_err_t MQTTClient::Subscribe()
{
    lwmqtt_err_t rc;
    BLog("MQTT topic %s", mSubscribeTopic.c_str());
    rc = lwmqtt_subscribe_one(&mMqttClient,
                              lwmqtt_string(mSubscribeTopic.c_str()),  // Benoit j'avais un probleme une variable a null.
                              LWMQTT_QOS1,
                              MQTT_COMMAND_TIMEOUT_MSEC);
    return rc;
}

void MQTTClient::Start()
{
    if (!mStarted) {
        mStarted = true;
        mConnectionSMTimer.start(0.0, MQTT_CONNECTION_SM_TIMER_PERIOD_SECS);
    }
}

void MQTTClient::Stop()
{
    if (mStarted) {
        bool wasConnected = (mConnectionInfo.mState.mState == MQTTConnectionInfo::State::CONNECTED);

        mStarted = false;
        mConnectionSMTimer.stop();
        mNetworkTimer.stop();
        UpdateConnectionState(MQTTConnectionInfo::State::INACTIVE);
        if (NetworkIsConnected()) {
            lwmqtt_disconnect(&mMqttClient, MQTT_COMMAND_TIMEOUT_MSEC);
        }
        NetworkDisconnect();

        // Invoke the registered callback.
        if (wasConnected && mOnDisconnectCallback) {
            mOnDisconnectCallback();
        }
    }
}

void MQTTClient::SendMessage(const std::string& topic, const vector<byte>& message, const std::string messageTag)
{
    if (mConnectionInfo.mState.mState != MQTTConnectionInfo::State::CONNECTED) {
        mConnectionInfo.mMessages.mTxDroppedTotal++;
        mConnectionInfo.mMessages.mTxDroppedLastDisconnection++;
        return;
    }

    // Get the topic.
    std::string fullTopic = mPublishTopicBase + topic;

    std::string payload;

    // Encapsulate the original message.
    if (!EncapsulateMessage(message, messageTag, &payload)) {
        printf("Failed to serialize cloud message.");
        return;
    }

    // Send the message.
    printf("Publishing message from WebSocket on topic '%s'...",
                      fullTopic.c_str());

    lwmqtt_message_t msg = {
        LWMQTT_QOS1,
        false,
        (uint8_t*)payload.data(),
        payload.size(),
    };

    const auto start = std::chrono::steady_clock::now();

    lwmqtt_err_t rc = lwmqtt_publish(&mMqttClient,
                                     lwmqtt_string(fullTopic.c_str()),
                                     msg,
                                     MQTT_COMMAND_TIMEOUT_MSEC);

    if (rc == LWMQTT_SUCCESS) {
        UpdateMqttAckTime(std::chrono::steady_clock::now() - start);
        mConnectionInfo.mMessages.mTxTotal++;
        mConnectionInfo.mMessages.mTxCurrentConnection++;
        mConnectionInfo.mMessages.mTxSizeLast = payload.size();
        if (mConnectionInfo.mMessages.mTxSizeLast > mConnectionInfo.mMessages.mTxSizePeak) {
            mConnectionInfo.mMessages.mTxSizePeak = mConnectionInfo.mMessages.mTxSizeLast;
        }
    }

    if (rc == LWMQTT_SUCCESS) {
        printf("Published message from WebSocket on topic '%s' successfully.",
                          fullTopic.c_str());
    }
    else if (rc == LWMQTT_BUFFER_TOO_SHORT) {
        printf("Failed to publish WebSocket message on topic '%s': %s.",
                           fullTopic.c_str(),
                           lwmqtt_strerr(rc));
        // Do not trigger a disconnect.
    }
    else {
        printf("Failed to publish WebSocket message on topic '%s': %s.",
                           fullTopic.c_str(),
                           lwmqtt_strerr(rc));
        TriggerDisconnect(rc);
    }
}

void MQTTClient::UpdateConnectionState(MQTTConnectionInfo::State state, const lwmqtt_err_t code)
{
    static MQTTConnectionInfo::State prevState = MQTTConnectionInfo::State::INACTIVE;

    bool connecting = (state == MQTTConnectionInfo::State::CONNECTED && state != prevState);
    bool disconnecting = (state == MQTTConnectionInfo::State::DISCONNECTED && prevState == MQTTConnectionInfo::State::CONNECTED);

    mConnectionInfo.mState.mState = state;
    mConnectionInfo.mState.mCode = code;

    // Update connection retries: if we just disconnected, reset the retries to
    // 0.  Else, increase the number of retries each time we come back to the
    // disconnected state.
    if (disconnecting) {
        mConnectionInfo.mState.mRetries = 0;
    }
    else if (state == MQTTConnectionInfo::State::DISCONNECTED && prevState != MQTTConnectionInfo::State::INACTIVE) {
        mConnectionInfo.mState.mRetries++;
    }

    // Update the uptime only if we are connecting or disconnecting.
    // Intermediate/transient states should not affect the uptime.
    if (connecting || disconnecting) {
        mConnectionInfo.mState.mUptime = getSysUptime();
    }

    // Update the previous state.
    prevState = state;
}

void MQTTClient::UpdateBrokerIpAddr(int fd)
{
    struct sockaddr sockaddr;
    socklen_t addrLen = sizeof(sockaddr);

    if (getpeername(fd, &sockaddr, &addrLen) == 0) {
        if (sockaddr.sa_family == AF_INET) {
            //struct sockaddr_in *sa = (struct sockaddr_in *)&sockaddr;
            //SETV4(mConnectionInfo.mBrokerIpAddr, sa->sin_addr.s_addr);
        }
        else if (sockaddr.sa_family == AF_INET6) {
            //truct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&sockaddr;
            //SETV6(mConnectionInfo.mBrokerIpAddr, sa6->sin6_addr.s6_addr);
        }
        else {
            printf("Invalid IP address family.");
            return;
        }
    }
    else {
        printf("Failed to get IP address of the MQTT broker.");
        return;
    }
}

void MQTTClient::UpdateMqttAckTime(std::chrono::duration<double> duration)
{
    auto now = std::chrono::steady_clock::now();
    uint32_t duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();

    if (duration_ms > 0) {
		#if AP
        mConnectionInfo.mAckTimes.mSinceBeginning.add(duration_ms);
        mConnectionInfo.mAckTimes.mCurrentConnection.add(duration_ms);
		#endif // #if AP
        mConnectionInfo.mAckTimes.mHistoricalData.push_back({ now, duration_ms });
        mConnectionInfo.mAckTimes.mLastMessage = duration_ms;

        if (duration_ms > mConnectionInfo.mAckTimes.mPeakSinceBeginning) {
            mConnectionInfo.mAckTimes.mPeakSinceBeginning = duration_ms;
        }
        if (duration_ms > mConnectionInfo.mAckTimes.mPeakCurrentConnection) {
            mConnectionInfo.mAckTimes.mPeakCurrentConnection = duration_ms;
        }
    }

    // Remove all historical data older than 5 minutes.
    while (mConnectionInfo.mAckTimes.mHistoricalData.size() > 0 &&
           std::chrono::duration_cast<std::chrono::minutes>(now - mConnectionInfo.mAckTimes.mHistoricalData.front().first) >= std::chrono::minutes(5)) {
        mConnectionInfo.mAckTimes.mHistoricalData.erase(mConnectionInfo.mAckTimes.mHistoricalData.begin());
    }
}

void MQTTClient::InitTimer()
{
    // Setup the MQTT connection state machine timer.
    mConnectionSMTimer.set<MQTTClient, &MQTTClient::ConnectionSMTimerCallback>(this);

    // Setup the MQTT network timer.
    mNetworkTimer.set<MQTTClient, &MQTTClient::NetworkTimerCallback>(this);
#if AP
    // Setup the GSM timer.
    mGSMTimer.set<MQTTClient, &MQTTClient::GSMTimerCallback>(this);
    mGSMTimer.start(0.0, 1.0);
#endif // #if AP
}
#if 0
void MQTTClient::NetworkDisconnect()
{
    #if AP
    lwmqtt_mbedtls_network_disconnect(&mMqttNetworkConnection);
    #else
//    mSock.Close();
//    mTls.Close();
    #endif 
}


bool MQTTClient::NetworkIsConnected()
{
    //return mMqttNetworkConnection.is_connected;
    return true;
}

void MQTTClient::NetworkInit(string mqttHost,
                   int mqttHostPort,
                   bool validateMqttHostCert,
                   string deviceCertPath,
                   string deviceKeyPath,
                   string caCertPath)
{
#if 0

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
#endif
#if 0
    // Configure the MQTT client.
    //lwmqtt_set_network(&mMqttClient, &(mTls.m_ssl), lwmqtt_mbedtls_network_read, lwmqtt_mbedtls_network_write);
    lwmqtt_set_timers(&mMqttClient, &mMqttKeepAliveTimer, &mMqttCommandTimer, lwmqtt_unix_timer_set, lwmqtt_unix_timer_get);
    lwmqtt_set_callback(&mMqttClient, &mLwmqttMessageCallbackFunc, lwmqtt_message_callback_c_wrapper);
    BLog("mTls.m_ssl = %p, &mTls.m_ssl = %p, &(mTls.m_ssl) = %p", (void*)mTls.m_ssl, (void*)&mTls.m_ssl, (void*)&(mTls.m_ssl));
    // Setup the MQTT connection state machine timer.
    mConnectionSMTimer.set<MQTTClient, &MQTTClient::ConnectionSMTimerCallback>(this);
    // Configure the MQTT client.
    lwmqtt_set_network(&mMqttClient, network, lwmqtt_mbedtls_network_read, lwmqtt_mbedtls_network_write);
    lwmqtt_set_timers(&mMqttClient, &mMqttKeepAliveTimer, &mMqttCommandTimer, lwmqtt_unix_timer_set, lwmqtt_unix_timer_get);
    lwmqtt_set_callback(&mMqttClient, &mLwmqttMessageCallbackFunc, lwmqtt_message_callback_c_wrapper);
#endif
}

lwmqtt_err_t MQTTClient::ConnectingToBroker(int *fd)
{
    lwmqtt_err_t rc = lwmqtt_mbedtls_network_connect(&mMqttNetworkConnection, mMqttNetworkConnection.endpoint, mMqttNetworkConnection.endpoint_port);
    *fd = mMqttNetworkConnection.server_fd.fd;
    return rc;
}


lwmqtt_err_t MQTTClient::NetworkPeek(size_t *available)
{
    lwmqtt_err_t rc;

    rc = lwmqtt_mbedtls_network_peek(&mMqttNetworkConnection, available);
    return rc;
}

#if 0
void InitTlsData(TlsData_S &data, const char * host, int port, int socket)
{

    data.host = host;
    data.port = port;
    data.socket = socket;
    data.tls_cafile = (char *)"/data/simul/mosquitto/mosquitto/CA/mosquitto.org.crt";
    data.tls_capath = (char *)"/data/simul/mosquitto/mosquitto/CA";
    data.tls_certfile = (char *)"/data/simul/mosquitto/mosquitto/CA/client.crt.txt";
    data.tls_keyfile = (char *)"/data/simul/mosquitto/mosquitto/CA/client.key";
    data.tls_version = (char*)"tlsv1.2";
    data.tls_ciphers = nullptr;
    data.tls_alpn = (char *)"x-amzn-mqtt-ca";
    data.tls_cert_reqs = SSL_VERIFY_PEER;
    data.tls_insecure = false;
    data.ssl_ctx_defaults = true;
    data.tls_ocsp_required = false;
    data.tls_use_os_certs = false;
}

lwmqtt_err_t MQTTClient::OpenSocket()
{
    lwmqtt_err_t retVal;
    int retConnect;
    /* Avec mbedtls
    lwmqtt_mbedtls_network_connect(&mMqttNetworkConnection, mMqttNetworkConnection.endpoint, mMqttNetworkConnection.endpoint_port);
    */
    mSock.Init(mMqttNetworkConnection.endpoint, mMqttNetworkConnection.endpoint_port);
    retConnect = mSock.Connect();
    if (retConnect == 0)
    {
        BLog("Socket connected");
    }

    if (mSock.IsConnected())
    {
        retVal = LWMQTT_SUCCESS;
        mMqttNetworkConnection.server_fd = mSock.GetSocket();
    }
    else
    {
        retVal = LWMQTT_NETWORK_FAILED_CONNECT;
        mMqttNetworkConnection.server_fd = INVALID_SOCKET;
    }

    TlsData_S data;
    InitTlsData(data, mMqttNetworkConnection.endpoint, mMqttNetworkConnection.endpoint_port, mMqttNetworkConnection.server_fd);
    TLS monTls = TLS(data);
    monTls.Init();

    return retVal;
}

void MQTTClient::CloseSocket()
{
    //lwmqtt_mbedtls_network_disconnect(&mMqttNetworkConnection);

    mSock.Close();
    mTls.Close();
}
#endif 

#endif // #if 0