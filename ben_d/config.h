#ifndef __config_h__
#define __config_h__

// Donne une erreur dans si on utilise la première ligne, la deuxième ligne donne un "Warning", la troisième semble parfaite
//#define BLog(...) do {printf("Benoit:%s(%d): ", __FILE__, __LINE__);printf(" " ##__VA_ARGS__);printf("\n");} while(0)
//#define BLog(...) do {printf("Benoit:%s(%d): ", __FILE__, __LINE__);printf(" " __VA_OPT__(,) __VA_ARGS__);printf("\n");} while(0)
#define BLog(format, ...) do {printf("Benoit:%s:%s(%d): " format "\n", __FILE__, __func__, __LINE__ __VA_OPT__(,) __VA_ARGS__);} while(0)
#define BTraceIn do {printf("Benoit:%s:%s(%d):In \n", __FILE__, __func__, __LINE__);} while(0);
#define BTraceOut do {printf("Benoit:%s:%s(%d):Out \n", __FILE__, __func__, __LINE__);} while(0);


enum DBLogLevel {
    DBLogLevel_INFO = true,
    DBLogLevel_SSL_CTX = false,
    DBLogLevel_SSL_CERT = false,
    DBLogLevel_SSL_READ = false,
    DBLogLevel_SSL_WRITE = false,
    DBLogLevel_SSL_RW = false,

};
#define DBLog(Log, format, ...) do {if(Log) {printf("Benoit:%s:%s(%d): " format "\n", __FILE__, __func__, __LINE__ __VA_OPT__(,) __VA_ARGS__);}} while(0)
#define DBTraceIn  DBLog(DBLogLevel_INFO) 
#define DBTraceOut DBLog(DBLogLevel_INFO)


#define GLDEBUG_DEFAULT BLog
#define GLINFO_DEFAULT BLog
#define GLERROR_DEFAULT BLog

#include <string>

#define DEFAULT_CA_CERT_PATH "/aruba/conf/AmazonRootCA.pem"
#define DEFAULT_ONBOARDING_CA_CERT_PATH "/aruba/conf/smb_ca_certificate.pem"


#define UNUSED(A) (void)(A)
/**
 * @brief Daemon configuration.
 */
struct DaemonConfig {
    std::string mqttHost; /**< Host of the MQTT broker to connect to. */
    int mqttHostPort; /**< Port of the MQTT broker to connect to. */
    bool mqttHostCertValidation; /**< Indicates if server certificate should be validated. */
    std::string deviceCert; /**< Path to the location of the device certificate file. */
    std::string deviceKey; /**< Path to the location of the device private key file. */
    std::string caCert; /**< Path to the CA certificate file to use to connect to the MQTT broker. */
    std::string onboardingCaCert; /**< Path to the CA certificate file used to connect to the onboarding service. */
    bool debug; /**< whether or not debug logging is enabled */
    bool toStdout; /**< whether or not debug logging to stdout is enabled */
    bool forceMqttConnStart; /**< whether or not MQTT connection should be started immediately */
};


#endif // #ifndef __config_h__