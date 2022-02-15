#include "MQTTClient.h"
#include "MQTTClientOpenSSL.h"

#include <aruba/util/grouplog_cloudconnect.h>



static lwmqtt_err_t lwqtt_read_callback_c_wrapper(void *ref, uint8_t *buffer, size_t len, size_t *sent, uint32_t timeout)
{
    auto& callback = *reinterpret_cast<lwmqttReadWriteCallbackFunc*>(ref);
    return callback(buffer, len, sent, timeout, true);
}

static lwmqtt_err_t lwqtt_write_callback_c_wrapper(void *ref, uint8_t *buffer, size_t len, size_t *sent, uint32_t timeout)
{
    auto& callback = *reinterpret_cast<lwmqttReadWriteCallbackFunc*>(ref);
    return callback(buffer, len, sent, timeout, false);
}

/**
 * @brief Class implementing the MQTT client using OpenSSL (derived from MQTTCLient)
 */

MQTTClientOpenSSL::MQTTClientOpenSSL(string mqttHost,
                       int mqttHostPort,
                       bool validateMqttHostCert,
                       std::string deviceCertPath,
                       std::string deviceKeyPath,
                       std::string caCertPath,
                       std::string onboardingCaCertPath,
                       OnConnectCallbackPtr onConnectCallback,
                       OnDisconnectCallbackPtr onDisconnectCallback,
                       OnMessageCallbackPtr onMessageCallback)
            : MQTTClient(mqttHost,
                  mqttHostPort,
                  validateMqttHostCert,
                  deviceCertPath,
                  deviceKeyPath,
                  caCertPath,
                  onboardingCaCertPath,
                  onConnectCallback,
                  onDisconnectCallback,
                  onMessageCallback),
                  mTls(&mTlsData)

{
    GLINFO_MQTTCLIENT("MQTTClientOpenSSL");
    GLINFO_MQTTCLIENT("%s, %d, %d, %s, %s, %s", mqttHost.c_str(), mqttHostPort, validateMqttHostCert, deviceCertPath.c_str(), deviceKeyPath.c_str(), caCertPath.c_str());

    mLwmqttReadWriteCallbackFunc = std::bind(&MQTTClientOpenSSL::ReadWrite,
                                        this,
                                        std::placeholders::_1,
                                        std::placeholders::_2,
                                        std::placeholders::_3,
                                        std::placeholders::_4,
                                        std::placeholders::_5
                                        );


    NetworkInit(mqttHost, mqttHostPort, validateMqttHostCert, deviceCertPath, deviceKeyPath, caCertPath);

    InitLWMQTTTClient();
    InitTimer();

    Start();
}

void MQTTClientOpenSSL::NetworkDisconnect()
{
    mTls.Close();
    mSock.Close();
    GLINFO_MQTTCLIENT("NetworkDisconnect");
}


bool MQTTClientOpenSSL::NetworkIsConnected()
{
    GLINFO_MQTTCLIENT("NetworkIsConnected");
    return mTlsData.tls_connected;
}


extern void lwmqtt_set_network(lwmqtt_client_t *client, void *ref, lwmqtt_network_read_t read, lwmqtt_network_write_t write);


void MQTTClientOpenSSL::NetworkInit(string mqttHost,
                   int mqttHostPort,
                   bool validateMqttHostCert,
                   string deviceCertPath,
                   string deviceKeyPath,
                   string caCertPath)
{
    GLINFO_MQTTCLIENT("NetworkInit");
    // Initialize the MQTT network connection info.
    strncpy(mTlsData.host, mqttHost.c_str(), sizeof(mTlsData.host));
    mTlsData.port = mqttHostPort;
    mTlsData.socket = INVALID_SOCKET;
    
    strncpy(mTlsData.tls_cafile, caCertPath.c_str(), sizeof(mTlsData.tls_cafile));
    //strncpy(mTlsData.tls_capath, caCertPath.c_str(), sizeof(mTlsData.tls_capath));

    strncpy(mTlsData.tls_certfile, deviceCertPath.c_str(), sizeof(mTlsData.tls_certfile));
    strncpy(mTlsData.tls_keyfile, deviceKeyPath.c_str(), sizeof(mTlsData.tls_keyfile));

    mTlsData.tls_insecure = validateMqttHostCert ? SSL_VERIFY_PEER : SSL_VERIFY_NONE;

    strncpy(mTlsData.tls_version, "tlsv1.2", sizeof(mTlsData.tls_version));
    strncpy(mTlsData.tls_alpn, "x-amzn-mqtt-ca", sizeof(mTlsData.tls_alpn));

    mTlsData.tls_connected = false;

    // Configure the MQTT client.
    lwmqtt_set_network(&mMqttClient, &mLwmqttReadWriteCallbackFunc, lwqtt_read_callback_c_wrapper, lwqtt_write_callback_c_wrapper);
}

lwmqtt_err_t MQTTClientOpenSSL::ConnectingToBroker(int *fd)
{
    lwmqtt_err_t retVal = LWMQTT_NETWORK_FAILED_CONNECT;
    int retConnect;

    mSock.Init(mTlsData.host, mTlsData.port);
    retConnect = mSock.Connect();
    if (retConnect == 0) {
        GLINFO_MQTTCLIENT("Socket connected");
    }

    if (mSock.IsConnected()) {
        retVal = LWMQTT_SUCCESS;
        mTlsData.socket = *fd = mSock.GetSocket();
        if (mTls.Init() == TLS::Msg_Success) {
            GLINFO_MQTTCLIENT("TLS Socket connected");
            retVal = LWMQTT_SUCCESS;
        }
        else {
            GLINFO_MQTTCLIENT("TLS Socket connection failed");
            retVal = LWMQTT_NETWORK_FAILED_CONNECT;
        }
    }
    else {
        GLINFO_MQTTCLIENT("Error Socket connection failed");
        retVal = LWMQTT_NETWORK_FAILED_CONNECT;
    }

    if( retVal != LWMQTT_SUCCESS) {
        mSock.Close();
        mTls.Close();
        mTlsData.socket = *fd = INVALID_SOCKET;
   }
    return retVal;
}

#include <sys/ioctl.h>
#include <sys/select.h>
#include <time.h>

void PrintHex(char *data, size_t len)
{
    char * ptr = data;
    /*
    for (;len>8;len-=8,ptr=ptr+8)
    {
        printf("%02X %02X %02X %02X %02X %02X %02X %02X  #n", *(ptr+0),*(ptr+1),*(ptr+2),*(ptr+3),*(ptr+4),*(ptr+5),*(ptr+6),*(ptr+7) );
    }*/
    for (;len>0;len--,ptr++)
    {
        printf("%02X ", *ptr);
    }
    printf("\n");
}

void MQTTClientOpenSSL::Select()
{
	struct timespec local_timeout;

	fd_set readfds, writefds;
	int fdcount;
    int sock = mSock.GetSocket();

	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	if(sock != INVALID_SOCKET){
		FD_SET(sock, &readfds);
    }
    // 100 ms
    local_timeout.tv_nsec = 100 * 1000000;
    local_timeout.tv_sec  = 0;
    fdcount = pselect(sock+1, &readfds, &writefds, NULL, &local_timeout, NULL);
    if(fdcount)
    {
        if(FD_ISSET(sock, &readfds))
        {
            size_t len;
            uint8_t buf[1];
            BLog("On a une donnees =============================== ");
            Write(buf, 0, &len, 10);
        }
    }
    else
    {
        BLog("On a un timeout =============================== fdcount = %d", fdcount);
    }

    /*
        int iocAvail;
    int rc = ioctl(mSock.GetSocket(), FIONREAD, &iocAvail);
    if (rc < 0) {
        BLog("LWMQTT_NETWORK_FAILED_READ");
        return LWMQTT_NETWORK_FAILED_READ;
    }

    if( iocAvail >  0) {
        char buf[256];
        if (iocAvail > 256)
            iocAvail = 256;
        read(mSock.GetSocket(), buf, iocAvail);
        BLog("On a avaiable = %d", iocAvail);
        PrintHex(buf, iocAvail);
    }
    */
}
#if 0
lwmqtt_err_t MQTTClientOpenSSL::NetworkPeek(size_t *available)
{
#define USE_PENDING
#ifdef USE_PENDING
    *available = mTls.SSL_Pending();
    if(*available > 0)
        GLINFO_MQTTCLIENT("MQTTClientOpenSSL:: return *available %lu", *available);
#else
    TLS::TlsMsg_E retVal;
    //GLINFO_MQTTCLIENT("MQTTClientOpenSSL::NetworkPeek +++---------------");
    retVal = mTls.Peek(available);
    //GLINFO_MQTTCLIENT("MQTTClientOpenSSL:: return error code %d, and available %lu", retVal, *available);
    if (retVal == TLS::Msg_Success)
        return LWMQTT_SUCCESS;
    return LWMQTT_NETWORK_FAILED_READ;
#endif
#undef USE_PENDING
    Select();
    return LWMQTT_SUCCESS;

}
#else
lwmqtt_err_t MQTTClientOpenSSL::NetworkPeek(size_t *available)
{
    if (mTls.Peek(available) == TLS::Msg_Success)
    {
        return LWMQTT_SUCCESS;
    }
    return LWMQTT_NETWORK_FAILED_READ;
}
#endif
lwmqtt_err_t MQTTClientOpenSSL::ReadWrite(uint8_t *buffer, size_t len, size_t *read, uint32_t timeout, bool rdwr )
{
    //GLINFO_MQTTCLIENT("MQTTClientOpenSSL::ReadWrite +++---------------");
    if (rdwr)
        return Read(buffer, len, read, timeout);
    return Write(buffer, len, read, timeout);
}


lwmqtt_err_t MQTTClientOpenSSL::Read(uint8_t *buffer, size_t len, size_t *read, uint32_t timeout)
{
    TLS::TlsMsg_E retVal;
    size_t available = mTls.SSL_Pending();
    if(available > 0)
        GLINFO_MQTTCLIENT("MQTTClientOpenSSL:: return *available %lu", available);
//    GLINFO_MQTTCLIENT("MQTTClientOpenSSL::Read len = %lu, read = %lu, timeout = %u", len, *read, timeout);
    retVal = mTls.Read(buffer, len, read, timeout);
    if (retVal == TLS::Msg_Success)
        return LWMQTT_SUCCESS;
    return LWMQTT_NETWORK_FAILED_READ;
}

lwmqtt_err_t MQTTClientOpenSSL::Write(uint8_t *buffer, size_t len, size_t *sent, uint32_t timeout)
{
    TLS::TlsMsg_E retVal;
    GLINFO_MQTTCLIENT("MQTTClientOpenSSL::Write len = %lu, snet = %lu, timeout = %u", len, *sent, timeout);
    retVal = mTls.Write(buffer, len, sent, timeout);
    if (retVal == TLS::Msg_Success)
        return LWMQTT_SUCCESS;
    return LWMQTT_NETWORK_FAILED_WRITE;
}