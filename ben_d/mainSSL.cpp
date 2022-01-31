#include "Socket.h"
#include "SSLConnection.h"

#include <iostream>
#include <unistd.h>

#if 1
#define HOST "test.mosquitto.org"
#define PORT 8884
#define c1 "/data/simul/lwmqtt/256dpi/lwmqtt/ca/mosquitto.org.crt"
#define c2 "/data/simul/lwmqtt/256dpi/lwmqtt/ca/"
#define c3 "/data/simul/lwmqtt/256dpi/lwmqtt/ca/client.crt.txt"
#define c4 "/data/simul/lwmqtt/256dpi/lwmqtt/ca/client.key"
#elif 0
#define HOST "iot.isb.arubanetworks.com"
#define PORT 443
#define c1 "/data/simul/lwmqtt/256dpi/lwmqtt/ca/AmazonRootCA.pem"
#define c2 "/data/simul/lwmqtt/256dpi/lwmqtt/ca"
#define c3 "/data/simul/lwmqtt/256dpi/lwmqtt/ca/cert.pem"
#define c4 "/data/simul/lwmqtt/256dpi/lwmqtt/ca/key.pem"
#else
#define HOST "iot.isb.arubanetworks.com"
#define PORT 443
#define c1 "/aruba/conf/AmazonRootCA.pem"
#define c2 "/aruba/conf/"
#define c3 "/aruba/fs/smb_ap/onboarding/cert.pem"
#define c4 "/aruba/fs/smb_ap/onboarding/key.pem"
#endif

#include <string.h>



void InitTlsData(TlsData_S &data, int socket = INVALID_SOCKET, const char * host = HOST, int port = PORT, bool insecure = false)
{

    memset(&data,0,sizeof(data));
    strncpy(data.host,host,sizeof(data.host));
    data.port = port;
    data.socket = socket;
    strncpy(data.tls_cafile,c1,sizeof(data.tls_cafile));
    strncpy(data.tls_capath,c2,sizeof(data.tls_capath));
    strncpy(data.tls_certfile,c3,sizeof(data.tls_certfile));
    strncpy(data.tls_keyfile,c4,sizeof(data.tls_keyfile));

    strncpy(data.tls_version,"tlsv1.2",sizeof(data.tls_version));
    strncpy(data.tls_ciphers,"",sizeof(data.tls_ciphers));
    strncpy(data.tls_alpn,"x-amzn-mqtt-ca",sizeof(data.tls_alpn));

    data.tls_cert_reqs = SSL_VERIFY_PEER;
    data.tls_insecure = false;
    data.ssl_ctx_defaults = true;
    data.tls_ocsp_required = false;
    data.tls_use_os_certs = false;
}

void TestSSL()
{
    Socket mSock(HOST, PORT);
    mSock.Connect();
    if (mSock.IsConnected()) {
        TlsData_S data;
        InitTlsData(data, mSock.GetSocket());
        TLS tls(&data);
        tls.Init();
        sleep(2);
    }
    else {
        std::cout << "Failed to connected to host " << HOST  << ", and port " << PORT << std::endl;
    }
}


void TestSocket()
{
    Socket mSock("iot.isb.arubanetworks.com", 443);
    for (int i=0; i<1; i++){
        std::cout << (mSock.GetState() == Socket::Connected ? "Socket connected" : "Socket non connected") << std::endl;
        mSock.GetState() == Socket::Connected ? "Socket connected" : "Socket non connected";
        mSock.Connect();
        std::cout << (mSock.GetState() == Socket::Connected ? "Socket connected" : "Socket non connected") << std::endl;
        std::cout << "Socket number is " << mSock.GetSocket() << std::endl;
        mSock.Print();
        mSock.Close();
    }
}

int main(int argc, char *argv[], char * env[])
{
    //TestSocket();
    TestSSL();
}