#ifndef __mosq_h__
#define __mosq_h__

#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int mosq_sock_t;

struct mosquitto {
    mosq_sock_t sock;
    
	SSL *ssl;
	SSL_CTX *ssl_ctx;
	SSL_CTX *user_ssl_ctx;
	char tls_cafile[256];
	char tls_capath[256];
	char tls_certfile[256];
	char tls_keyfile[256];
	int (*tls_pw_callback)(char *buf, int size, int rwflag, void *userdata);
	char *tls_version;
	char *tls_alpn;
	int tls_cert_reqs;
	bool tls_insecure;
	bool ssl_ctx_defaults;
	bool tls_ocsp_required;
	bool tls_use_os_certs;

	char host[256];
	uint16_t port;
	char *bind_address;
	uint8_t max_qos;
	uint8_t retain_available;
	bool tcp_nodelay;
	
	bool want_connect;
	bool want_write;

	bool is_connected;
};

/* Error values */
enum mosq_err_t {
	MOSQ_ERR_AUTH_CONTINUE = -4,
	MOSQ_ERR_NO_SUBSCRIBERS = -3,
	MOSQ_ERR_SUB_EXISTS = -2,
	MOSQ_ERR_CONN_PENDING = -1,
	MOSQ_ERR_SUCCESS = 0,
	MOSQ_ERR_NOMEM = 1,
	MOSQ_ERR_PROTOCOL = 2,
	MOSQ_ERR_INVAL = 3,
	MOSQ_ERR_NO_CONN = 4,
	MOSQ_ERR_CONN_REFUSED = 5,
	MOSQ_ERR_NOT_FOUND = 6,
	MOSQ_ERR_CONN_LOST = 7,
	MOSQ_ERR_TLS = 8,
	MOSQ_ERR_PAYLOAD_SIZE = 9,
	MOSQ_ERR_NOT_SUPPORTED = 10,
	MOSQ_ERR_AUTH = 11,
	MOSQ_ERR_ACL_DENIED = 12,
	MOSQ_ERR_UNKNOWN = 13,
	MOSQ_ERR_ERRNO = 14,
	MOSQ_ERR_EAI = 15,
	MOSQ_ERR_PROXY = 16,
	MOSQ_ERR_PLUGIN_DEFER = 17,
	MOSQ_ERR_MALFORMED_UTF8 = 18,
	MOSQ_ERR_KEEPALIVE = 19,
	MOSQ_ERR_LOOKUP = 20,
	MOSQ_ERR_MALFORMED_PACKET = 21,
	MOSQ_ERR_DUPLICATE_PROPERTY = 22,
	MOSQ_ERR_TLS_HANDSHAKE = 23,
	MOSQ_ERR_QOS_NOT_SUPPORTED = 24,
	MOSQ_ERR_OVERSIZE_PACKET = 25,
	MOSQ_ERR_OCSP = 26,
	MOSQ_ERR_TIMEOUT = 27,
	MOSQ_ERR_RETAIN_NOT_SUPPORTED = 28,
	MOSQ_ERR_TOPIC_ALIAS_INVALID = 29,
	MOSQ_ERR_ADMINISTRATIVE_ACTION = 30,
	MOSQ_ERR_ALREADY_EXISTS = 31,
};

#  define COMPAT_CLOSE(a) close(a)
#  define COMPAT_ECONNRESET ECONNRESET
#  define COMPAT_EINTR EINTR
#  define COMPAT_EWOULDBLOCK EWOULDBLOCK

/* For when not using winsock libraries. */
#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif


#include <openssl/ssl.h>
#include <openssl/engine.h>

//int mosquitto__server_certificate_verify(int preverify_ok, X509_STORE_CTX *ctx);
//int mosquitto__verify_certificate_hostname(X509 *cert, const char *hostname);
// Benoit ces lignes viennent de tls_mosh.h <<<<

#ifdef __cplusplus
}// extern "C" {
#endif


#endif // #ifndef __mosq_h__