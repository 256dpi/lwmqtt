#ifndef __SSLConnection_h__
#define __SSLConnection_h__

#include <functional>

/***
 * Grosse note: On a la version # define OPENSSL_VERSION_NUMBER  0x1000213fL sur les APs
 * 
 * 
***/

#include <stdint.h>

#include <openssl/ossl_typ.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/ui.h>
#include <openssl/x509v3.h>

extern "C" {

const size_t TlsData_MaxTextLen = 256;
typedef struct TlsData_s {
	char host[TlsData_MaxTextLen];
	uint16_t port;
    int socket;

    char tls_cafile[TlsData_MaxTextLen];
    char tls_capath[TlsData_MaxTextLen];
    char tls_certfile[TlsData_MaxTextLen];
    char tls_keyfile[TlsData_MaxTextLen];
    char tls_version[TlsData_MaxTextLen];
    char tls_ciphers[TlsData_MaxTextLen];
    char tls_alpn[TlsData_MaxTextLen];
    int  tls_cert_reqs;
    bool tls_insecure;
    bool ssl_ctx_defaults;
    bool tls_ocsp_required;
    bool tls_use_os_certs;
    bool tls_connected;

} TlsData_S;

} // extern "C" {


class TLS
{
    public:
        enum TlsMsg_E {
            Msg_Err_Read = -5,
            Msg_Err_Write = -4,
            Msg_Err_Peek = -3,
            Msg_Err_Tls = -2,
            Msg_Error   = -1,
            Msg_Success = 0
        };
        TLS(TlsData_S *data);
        ~TLS() {Close();};

        int Init();

        bool IsInitialized() { return m_initialized;}
        SSL *GetSsl() {return m_ssl;}
        SSL *m_ssl;
        void Close();
        TlsMsg_E Read(uint8_t *buffer, size_t len, size_t *read, uint32_t timeout);
        TlsMsg_E Write(uint8_t *buffer, size_t len, size_t *read, uint32_t timeout);
        TlsMsg_E Peek(size_t *available);
        int SSL_Pending();
        int HandleSslError(int ret);
        void PrintSslError(int err);


    private:
        int InitSslCtx(); // net__init_ssl_ctx()
        void ResetInitialized() { m_initialized = false;}
        void SetInitialized() { m_initialized = true;}
        void SetupUiMethod();
        void InitTlsCrypto(); //net__init_tls();
        void InitTlsCryptoVersion(); // Init SSL lib and crypto based on the openssl version.
        int  LoadCA(); //static int net__tls_load_ca(struct mosquitto *mosq)
        void SetSSLCtx(); 
        void DHECiphers();
        void SetALPN();
        int  Certificats();
        void PrintTlsError();
        void SetOpensslExIndex();
        void SslClose();
        int SslConnect(); // net__socket_connect_tls(mosq))
        
        TlsData_S *m_tls_data;
    
        SSL_CTX *m_ssl_ctx;
        SSL_CTX *m_user_ssl_ctx;
        // OpenSSL user interface method
        UI_METHOD *m_ui_method = nullptr;

        // OpenSSL index 
        int m_openssl_ex_index;

        // Init or Not
        bool m_initialized; 

        	bool m_want_write;
	bool m_want_connect;

};

extern "C" {

#include "lwmqtt.h"


} // extern "C"

#endif // #ifndef __SSLConnection_h__