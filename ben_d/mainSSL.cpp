#include "Socket.h"
#include "SSLConnection.h"

#include <iostream>
#include <unistd.h>

#if 0
#define HOST "test.mosquitto.org"
#define PORT 8884
#define c1 "/data/simul/lwmqtt/256dpi/lwmqtt/ca/mosquitto.org.crt";
#define c2 "/data/simul/lwmqtt/256dpi/lwmqtt/ca/";
#define c3 "/data/simul/lwmqtt/256dpi/lwmqtt/ca/client.crt.txt";
#define c4 "/data/simul/lwmqtt/256dpi/lwmqtt/ca/client.key";
#else
#define HOST "iot.isb.arubanetworks.com"
#define PORT 443
#define c1 "/data/simul/lwmqtt/256dpi/lwmqtt/ca/AmazonRootCA.pem";
#define c2 "/data/simul/lwmqtt/256dpi/lwmqtt/ca";
#define c3 "/data/simul/lwmqtt/256dpi/lwmqtt/ca/cert.pem";
#define c4 "/data/simul/lwmqtt/256dpi/lwmqtt/ca/key.pem";
#endif




void InitTlsData(TlsData_S &data, int socket = INVALID_SOCKET, const char * host = HOST, int port = PORT, bool insecure = false)
{

    data.host = host;
    data.port = port;
    data.socket = socket;
    data.tls_cafile = (char *)  c1;
    data.tls_capath = (char *)  c2;
    data.tls_certfile = (char *)c3;
    data.tls_keyfile = (char *) c4;
    data.tls_version = (char*)  "tlsv1.2";
    data.tls_ciphers = nullptr;
    data.tls_alpn = (char *)"x-amzn-mqtt-ca";
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
        sleep(10);
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