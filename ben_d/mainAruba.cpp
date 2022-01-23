#include <cstdlib>
#include <string>
#include <memory>

#include "CloudConnect.h"
#include "config.h"

using std::string;
using std::vector;

/*
    MQTTClient monMqtt(
      "iot.isb.arubanetworks.com",
      443,
      false,
      "./cert.pem", //"/aruba/fs/smb_ap/onboarding/cert.pem",
      "./key.pem", // /aruba/fs/smb_ap/onboarding/key.pem",
      "./AmazonRootCA.pem", //"/aruba/conf/AmazonRootCA.pem",
      "./smb_ca_certificate.pem" //"/aruba/conf/smb_ca_certificate.pem"
    );
*/

DaemonConfig daemonConf_App = {
    /*mqttHost:*/ "",
    /*mqttHostPort:*/ 443,
    /*mqttHostCertValidation:*/ true,
    /*deviceCert:*/ "",
    /*deviceKey:*/ "",
    /*caCert:*/ DEFAULT_CA_CERT_PATH,
    /*onboardingCaCert:*/ DEFAULT_ONBOARDING_CA_CERT_PATH,
    /*debug:*/ false,
    /*toStdout:*/ false,
    /*forceMqttConnStart:*/ false
};

#if 0
    false,
    "./ca/client.crt.txt", //"/aruba/fs/smb_ap/onboarding/cert.pem",
    "./ca/client.key", // /aruba/fs/smb_ap/onboarding/key.pem",
    "./ca/mosquitto.org.crt", //"/aruba/conf/AmazonRootCA.pem",
    "./ca/smb_ca_certificate.pem" //"/aruba/conf/smb_ca_certificate.pem"
#endif // #if 0
DaemonConfig daemonConf_Mosq = {
    /*mqttHost:*/ "test.mosquitto.org",
    /*mqttHostPort:*/ 8884,
    /*mqttHostCertValidation:*/ true,
    /*deviceCert:*/ "./ca/client.crt.txt",
    /*deviceKey:*/ "./ca/mosquitto.org.crt",
    /*caCert:*/  "./ca/mosquitto.org.crt",
    /*onboardingCaCert:*/ "./ca/AmazonRootCA.pem",
    /*debug:*/ false,
    /*toStdout:*/ false,
    /*forceMqttConnStart:*/ false
};

int mainAruba(const int argc, char *argv[], char *env[])
{
   ev::default_loop loop;
    // Create the cloud connect daemon.
    std::unique_ptr<CloudConnect> app;
    try {
        app.reset(new CloudConnect(loop,
                         daemonConf_Mosq.mqttHost,
                         daemonConf_Mosq.mqttHostPort,
                         daemonConf_Mosq.mqttHostCertValidation,
                         daemonConf_Mosq.deviceCert,
                         daemonConf_Mosq.deviceKey,
                         daemonConf_Mosq.caCert,
                         daemonConf_Mosq.onboardingCaCert,
                         daemonConf_Mosq.forceMqttConnStart));
    }
    catch (const std::runtime_error& e) {
        GLERROR_DEFAULT("Failed to initialize CloudConnect: %s.", e.what());
        return EXIT_FAILURE;
    }
    catch (...) {
        GLERROR_DEFAULT("Failed to initialize CloudConnect: Unhandled exception.");
        return EXIT_FAILURE;
    }

    // Start the main loop.
    try {
        loop.run();
    }
    catch (const std::exception& e) {
        printf("Unhandled exception: %s.", e.what());
        return EXIT_FAILURE;
    }
    catch (...) {
        printf("Unhandled exception, terminating.");
        return EXIT_FAILURE;
    }
    return 0;
}

#if 0
#include "Socket.h"
#include "SSLConnection.h"

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

#endif // #if 0