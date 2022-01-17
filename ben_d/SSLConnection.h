#ifndef __SSLConnection_h__
#define __SSLConnection_h__

/***
 * Grosse note: On a la version # define OPENSSL_VERSION_NUMBER  0x1000213fL sur les APs
 * 
 * 
***/

#include <stdint.h>

#include <openssl/ossl_typ.h>

extern "C" {

typedef struct TlsData_s {
	const char *host;
	uint16_t port;
    int socket;

    char *tls_cafile;
    char *tls_capath;
    char *tls_certfile;
    char *tls_keyfile;
    int (*tls_pw_callback)(char *buf, int size, int rwflag, void *userdata);
    char *tls_version;
    char *tls_ciphers;
    char *tls_psk;  // TODO: n'est pas utilisé je crois
    char *tls_psk_identity;  // TODO: n'est pas utilisé je crois
    //char *m_tls_engine;
    //char *m_tls_engine_kpass_sha1;
    char *tls_alpn;
    int tls_cert_reqs;
    bool tls_insecure;
    bool ssl_ctx_defaults;
    bool tls_ocsp_required;
    bool tls_use_os_certs;

} TlsData_S;

} // extern "C" {


class TLS
{
    public:
        enum {
            Msg_Err_Tls = -2,
            Msg_Error   = -1,
            Msg_Success = 0
        };
        TLS(const char *host, uint16_t port, int socket );
        TLS(TlsData_S &data);
        int Init(); //int net__socket_connect_step3(struct mosquitto *mosq, const char *host)
        int InitSslCtx(); // net__init_ssl_ctx()

        bool IsInitialized() { return m_initialized;}
        void SetInitialized() { m_initialized = true;}
        void ResetInitialized() { m_initialized = false;}

    private:
        void SetupUiMethod();
        void InitTlsCrypto(); //net__init_tls();
        void InitTlsCryptoVersion(); // Init SSL lib and crypto based on the openssl version.
        int LoadCA(); //static int net__tls_load_ca(struct mosquitto *mosq)
        void SetSSLCtx(); 
        void DHECiphers();
        void SetALPN();
        int  Certificats();
        void PrintTlsError();
        void SetOpensslExIndex();
        void SslClose();
        int SslConnect(); // net__socket_connect_tls(mosq))

        int sock;
        TlsData_S m_tls_data;
    
        SSL *m_ssl;
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


#endif // #ifndef __SSLConnection_h__