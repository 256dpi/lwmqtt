#include <iostream>
extern "C" {
#include <lwmqtt.h>
#include <lwmqtt/unix.h>
}
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "config.h"

#define COMMAND_TIMEOUT 5000
#define MESSAGE_TIMEOUT 1000

char *host[] = {
    (char *)"test.mosquitto.org",
    (char *)"localhost",
    0
};

enum hostNameIndex
{
  host_mosquitto = 0,
  host_localhost = 1,
  host_null
};

int currentHost = host_mosquitto;


lwmqtt_unix_network_t network = {0};

lwmqtt_unix_timer_t timer1, timer2, timer3;

lwmqtt_client_t client;

static void message_arrived(lwmqtt_client_t *client, void *ref, lwmqtt_string_t topic, lwmqtt_message_t msg) {
  printf("message_arrived: %.*s => %.*s (%d)\n", (int)topic.len, topic.data, (int)msg.payload_len, (char *)msg.payload,
         (int)msg.payload_len);
}

#include <cpr/cpr.h>

void main1() {
    cpr::Response r = cpr::Get(cpr::Url{"http://192.168.2.34:8000/login.html"});
    //r.status_code;                  // 200
    //r.header["content-type"];       // application/json; charset=utf-8
    //r.text;                         // JSON text string
    std::cout << "Benoit cpr: " << r.status_code << ", " << r.text << std::endl;
}


#include <curl/curl.h>

size_t writeFunction(void *ptr, size_t size, size_t nmemb, std::string* data) {
    data->append((char*) ptr, size * nmemb);
    return size * nmemb;
}
void main2()
{
    auto curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://api.github.com/repos/libcpr/cpr/contributors?anon=true&key=value");
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
        curl_easy_setopt(curl, CURLOPT_USERPWD, "user:pass");
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "curl/7.42.0");
        curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 50L);
        curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);

        std::string response_string;
        std::string header_string;
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeFunction);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_string);

        char* url;
        long response_code;
        double elapsed;

        curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &elapsed);
        curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &url);
        curl_easy_cleanup(curl);
        curl = NULL;
        printf("Curl: %s, %s, code %ld \n", response_string.c_str(), header_string.c_str(), response_code);
        printf("Curl: %s, elapsed %f \n", url, elapsed);
    }
}

void main3() {
    std::cout << "Allo\n";
    curl_global_init(CURL_GLOBAL_DEFAULT);
    auto curl = curl_easy_init();
    if (curl) {
    std::cout << "Allo\n";
        curl_easy_setopt(curl, CURLOPT_URL, "https://www.example.com");
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
        curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 50L);
        curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);

        std::string response_string;
        std::string header_string;
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeFunction);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_string);

        curl_easy_perform(curl);
        std::cout << "allo response" << response_string << std::endl;
        char* url;
        long response_code;
        double elapsed;

        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &elapsed);
        curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &url);
        std::cout << "allo response" << response_code << std::endl;
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        curl = NULL;
    }
    else
    {
      std::cout << "curl_esay_init() ne marche pas!\n";
    }
}

int mainSync() {
  //main1();
  // initialize client
  lwmqtt_init(&client, (uint8_t *)malloc(512), 512, (uint8_t *)malloc(512), 512);

  // configure client
  lwmqtt_set_network(&client, &network, lwmqtt_unix_network_read, lwmqtt_unix_network_write);
  lwmqtt_set_timers(&client, &timer1, &timer2, lwmqtt_unix_timer_set, lwmqtt_unix_timer_get);
  lwmqtt_set_callback(&client, NULL, message_arrived);

  // configure message time
  lwmqtt_unix_timer_set(&timer3, MESSAGE_TIMEOUT);

  // connect to broker
  lwmqtt_err_t err = lwmqtt_unix_network_connect(&network, (char *)host[currentHost], 1883);
  if (err != LWMQTT_SUCCESS) {
    printf("failed lwmqtt_unix_network_connect: %d\n", err);
    exit(1);
  }

  // prepare options
  lwmqtt_options_t options = lwmqtt_default_options;
  options.client_id = lwmqtt_string("lwmqtt");
  options.username = lwmqtt_string("try");
  options.password = lwmqtt_string("try");
  options.keep_alive = 5;

  // send connect packet
  lwmqtt_return_code_t return_code;
  err = lwmqtt_connect(&client, options, NULL, &return_code, COMMAND_TIMEOUT);
  if (err != LWMQTT_SUCCESS) {
    printf("failed lwmqtt_connect: %d (%d)\n", err, return_code);
    exit(1);
  }

  // log
  printf("connected!\n");

  // subscribe to topic
  err = lwmqtt_subscribe_one(&client, lwmqtt_string("hello"), LWMQTT_QOS0, COMMAND_TIMEOUT);
  if (err != LWMQTT_SUCCESS) {
    printf("failed lwmqtt_subscribe: %d\n", err);
    exit(1);
  }

  // loop forever
  for (;;) {
    // check if data is available
    size_t available = 0;
    err = lwmqtt_unix_network_peek(&network, &available);
    if (err != LWMQTT_SUCCESS) {
      printf("failed lwmqtt_unix_network_peek: %d\n", err);
      exit(1);
    }

    // process data if available
    if (available > 0) {
      err = lwmqtt_yield(&client, available, COMMAND_TIMEOUT);
      if (err != LWMQTT_SUCCESS) {
        printf("failed lwmqtt_yield: %d\n", err);
        exit(1);
      }
    }

    // keep connection alive
    err = lwmqtt_keep_alive(&client, COMMAND_TIMEOUT);
    if (err != LWMQTT_SUCCESS) {
      printf("failed lwmqtt_keep_alive: %d\n", err);
      exit(1);
    }

    // check if message is due
    if (lwmqtt_unix_timer_get(&timer3) <= 0) {
      // prepare message
      lwmqtt_message_t msg = {LWMQTT_QOS0, false, (uint8_t *)("world"),  5};

      // publish message
      err = lwmqtt_publish(&client, lwmqtt_string("hello"), msg, COMMAND_TIMEOUT);
      if (err != LWMQTT_SUCCESS) {
        printf("failed lwmqtt_keep_alive: %d\n", err);
        exit(1);
      }

      // reset timer
      lwmqtt_unix_timer_set(&timer3, MESSAGE_TIMEOUT);
    }

    // sleep for 100ms
    usleep(100 * 1000);
  }
}

#include "MQTTClient.h"

static int mainAruba(const int argc, char *argv[], char *env[])
{
    ev::default_loop loop;

    MQTTClient monMqtt(
      "iot.isb.arubanetworks.com",
      443,
      false,
      "./cert.pem", //"/aruba/fs/smb_ap/onboarding/cert.pem",
      "./key.pem", // /aruba/fs/smb_ap/onboarding/key.pem",
      "./AmazonRootCA.pem", //"/aruba/conf/AmazonRootCA.pem",
      "./smb_ca_certificate.pem" //"/aruba/conf/smb_ca_certificate.pem"
    );


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

int mainMosquitto(const int argc, char *argv[], char *env[])
{
   ev::default_loop loop;

   MQTTClient monMqtt(
    "test.mosquitto.org",
    8884,
    false,
    "./ca/client.crt.txt", //"/aruba/fs/smb_ap/onboarding/cert.pem",
    "./ca/client.key", // /aruba/fs/smb_ap/onboarding/key.pem",
    "./ca/mosquitto.org.crt", //"/aruba/conf/AmazonRootCA.pem",
    "./ca/smb_ca_certificate.pem" //"/aruba/conf/smb_ca_certificate.pem"
    );


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

#include "Socket.h"
#include "SSLConnection.h"

static void InitTlsData(TlsData_S &data, const char * host, int port, int socket)
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

void TestSocketClass()
{
    string host = "test.mosquitto.org";
    int port = 8884;
    int delay = 50;
    Socket monSocket = Socket(host.c_str(), port, delay);
    monSocket.Print();
    monSocket.Connect();
    TlsData_S data;
    InitTlsData(data, host.c_str(), port, monSocket.GetSocket());
    TLS monTls = TLS(data);
    sleep(3);
    BLog("--------------------------------------------------------------------");
    monTls.Init();
    sleep(3);
    BLog("--------------------------------------------------------------------");
    monSocket.Print();
    sleep(3);
    BLog("--------------------------------------------------------------------");
    monSocket.Close();
    sleep(3);
    BLog("--------------------------------------------------------------------");

}



int TestDevMain(const int argc, char *argv[], char *env[])
{
  //mainMosquitto(argc, argv, env);
  mainAruba(argc, argv, env);
  //mainSync();
  //TestSocketClass();
  //mainMosquitto(argc, argv, env);
  return 0;
}