/**
 * @file ssl_network.c
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2021-12-06
 * 
 * @copyright Copyright (c) 2021
 * 
 * 
 * 
 * 
 * Benoit:
 * 
 * A surveiller			//mosq->want_connect = true;
			//mosq->want_write = true;
			//mosq->want_connect = true;

Pour les permiers essais prendre 
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
mais on a 
 OPENSSL_VERSION_NUMBER  0x1000213fL
dans ION

On supprime car on ne devrait pas avoir de Engine dans mbedTLS, a verifier
#if !defined(OPENSSL_NO_ENGINE)

Il faut revoir 
mosquitto__verify_ocsp_status_cb()
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ui.h>
#include <openssl/ssl.h>


#include <lwmqtt.h>
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    #error "OPENSSL_VERSION_NUMBER < 0x10100000L"
#endif

#include "mosq.h"
#include "config.h"
#include "tls_mosq.h"


int net__socket_connect(struct mosquitto *mosq, const char *host, uint16_t port, const char *bind_address, bool blocking);
int net__socket_close(struct mosquitto *mosq);
int net__try_connect(const char *host, uint16_t port, mosq_sock_t *sock, const char *bind_address, bool blocking);
int net__try_connect_step1(struct mosquitto *mosq, const char *host);
int net__try_connect_step2(struct mosquitto *mosq, uint16_t port, mosq_sock_t *sock);
int net__socket_connect_step3(struct mosquitto *mosq, const char *host);
int net__socket_nonblock(mosq_sock_t *sock);
int net__socketpair(mosq_sock_t *sp1, mosq_sock_t *sp2);
static int net__handle_ssl(struct mosquitto* mosq, int ret);

ssize_t net__read(struct mosquitto *mosq, void *buf, size_t count);
ssize_t net__write(struct mosquitto *mosq, const void *buf, size_t count);

void net__print_ssl_error(struct mosquitto *mosq);
int net__socket_apply_tls(struct mosquitto *mosq);
int net__socket_connect_tls(struct mosquitto *mosq);
int mosquitto__verify_ocsp_status_cb(SSL * ssl, void *arg);
UI_METHOD *net__get_ui_method(void);

int mosquitto__verify_ocsp_status_cb(SSL * ssl, void *arg)

{
	return 0;
}

int tls_ex_index_mosq = -1;
UI_METHOD *_ui_method = NULL;

static bool is_tls_initialized = false;

/* Functions taken from OpenSSL s_server/s_client */
static int ui_open(UI *ui)
{
	return UI_method_get_opener(UI_OpenSSL())(ui);
}

static int ui_read(UI *ui, UI_STRING *uis)
{
	return UI_method_get_reader(UI_OpenSSL())(ui, uis);
}

static int ui_write(UI *ui, UI_STRING *uis)
{
	return UI_method_get_writer(UI_OpenSSL())(ui, uis);
}

static int ui_close(UI *ui)
{
	return UI_method_get_closer(UI_OpenSSL())(ui);
}

void setup_ui_method(void)
{
	_ui_method = UI_create_method("OpenSSL application user interface");
	UI_method_set_opener(_ui_method, ui_open);
	UI_method_set_reader(_ui_method, ui_read);
	UI_method_set_writer(_ui_method, ui_write);
	UI_method_set_closer(_ui_method, ui_close);
}

static void cleanup_ui_method(void)
{
	if(_ui_method){
		UI_destroy_method(_ui_method);
		_ui_method = NULL;
	}
}

UI_METHOD *net__get_ui_method(void)
{
	return _ui_method;
}

int net__init(void)
{
	return MOSQ_ERR_SUCCESS;
}

void net__cleanup(void)
{
#  if OPENSSL_VERSION_NUMBER < 0x10100000L
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
	ERR_remove_thread_state(NULL);
	EVP_cleanup();

	is_tls_initialized = false;
#  endif

	CONF_modules_unload(1);
	cleanup_ui_method();


}

void net__init_tls(void)
{
	BTraceIn
	if(is_tls_initialized) return;

#  if OPENSSL_VERSION_NUMBER < 0x10100000L
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();
#  else
	OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS \
			| OPENSSL_INIT_ADD_ALL_DIGESTS \
			| OPENSSL_INIT_LOAD_CONFIG, NULL);
#  endif
	//setup_ui_method();
	if(tls_ex_index_mosq == -1){
		tls_ex_index_mosq = SSL_get_ex_new_index(0, "client context", NULL, NULL, NULL);
	}

	is_tls_initialized = true;
	BTraceOut
}

/* Close a socket associated with a context and set it to -1.
 * Returns 1 on failure (context is NULL)
 * Returns 0 on success.
 */
int net__socket_close(struct mosquitto *mosq)
{
	int rc = 0;

	assert(mosq);
	{
		if(mosq->ssl){
			if(!SSL_in_init(mosq->ssl)){
				SSL_shutdown(mosq->ssl);
			}
			SSL_free(mosq->ssl);
			mosq->ssl = NULL;
		}
	}
    if(mosq->sock != INVALID_SOCKET){
        rc = COMPAT_CLOSE(mosq->sock);
        mosq->sock = INVALID_SOCKET;
    }
    return rc;
}

static int net__try_connect_tcp(const char *host, uint16_t port, mosq_sock_t *sock, const char *bind_address, bool blocking)
{
	struct addrinfo hints;
	struct addrinfo *ainfo, *rp;
	struct addrinfo *ainfo_bind, *rp_bind;
	int s;
	int rc = MOSQ_ERR_SUCCESS;

	ainfo_bind = NULL;
	BTraceIn

	*sock = INVALID_SOCKET;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	s = getaddrinfo(host, NULL, &hints, &ainfo);
	if(s){
		errno = s;
		return MOSQ_ERR_EAI;
	}

	if(bind_address){
		s = getaddrinfo(bind_address, NULL, &hints, &ainfo_bind);
		if(s){
			freeaddrinfo(ainfo);
			errno = s;
			return MOSQ_ERR_EAI;
		}
	}

	for(rp = ainfo; rp != NULL; rp = rp->ai_next){
		*sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if(*sock == INVALID_SOCKET) continue;

		if(rp->ai_family == AF_INET){
			((struct sockaddr_in *)rp->ai_addr)->sin_port = htons(port);
		}else if(rp->ai_family == AF_INET6){
			((struct sockaddr_in6 *)rp->ai_addr)->sin6_port = htons(port);
		}else{
			COMPAT_CLOSE(*sock);
			*sock = INVALID_SOCKET;
			continue;
		}

		if(bind_address){  // Benoit: Passe pas ici
			BLog("pas ici");
			for(rp_bind = ainfo_bind; rp_bind != NULL; rp_bind = rp_bind->ai_next){
				if(bind(*sock, rp_bind->ai_addr, rp_bind->ai_addrlen) == 0){
					break;
				}
			}
			if(!rp_bind){
				COMPAT_CLOSE(*sock);
				*sock = INVALID_SOCKET;
				continue;
			}
		}
		blocking = true; // Benoit
		if(!blocking){
			/* Set non-blocking */
			if(net__socket_nonblock(sock)){
				BLog(" non-blocking");
				continue;
			}
		}

		rc = connect(*sock, rp->ai_addr, rp->ai_addrlen);
		if(rc == 0 || errno == EINPROGRESS || errno == COMPAT_EWOULDBLOCK){
			if(rc < 0 && (errno == EINPROGRESS || errno == COMPAT_EWOULDBLOCK)){
				rc = MOSQ_ERR_CONN_PENDING;
			}

			if(blocking){
				/* Set non-blocking */
				BLog("Force to know Blocking");
				if(net__socket_nonblock(sock)){
					continue;
				}
			}
			BLog("On quitte");
			break;
		}
		BLog("Suivant");
		COMPAT_CLOSE(*sock);
		*sock = INVALID_SOCKET;
	}
	freeaddrinfo(ainfo);
	if(bind_address){
		freeaddrinfo(ainfo_bind);
	}
	if(!rp){
		BLog("if(!rp) on n'a pas passé a travers tous les rp");
		return MOSQ_ERR_ERRNO;
	}
	BTraceOut
	return rc;
}

int net__try_connect(const char *host, uint16_t port, mosq_sock_t *sock, const char *bind_address, bool blocking)
{
	if(port == 0){
		return MOSQ_ERR_NOT_SUPPORTED;
	}else{
	printf("Benoit: ICI NO WITH_UNIX_SOCKETS host %s, port = %d\n", host, port);
		return net__try_connect_tcp(host, port, sock, bind_address, blocking);
	}
}

void net__print_ssl_error(struct mosquitto *mosq)
{
	char ebuf[256];
	unsigned long e;
	int num = 0;

	e = ERR_get_error();
	while(e){
		printf("OpenSSL Error[%d]: %s", num, ERR_error_string(e, ebuf));
		e = ERR_get_error();
		num++;
	}
}

int net__socket_connect_tls(struct mosquitto *mosq)
{
	int ret, err;
	long res;

	ERR_clear_error();
	if (mosq->tls_ocsp_required) {
		/* Note: OCSP is available in all currently supported OpenSSL versions. */
		if ((res=SSL_set_tlsext_status_type(mosq->ssl, TLSEXT_STATUSTYPE_ocsp)) != 1) {
			printf("Could not activate OCSP (error: %ld)", res);
			return MOSQ_ERR_OCSP;
		}
		if ((res=SSL_CTX_set_tlsext_status_cb(mosq->ssl_ctx, mosquitto__verify_ocsp_status_cb)) != 1) {
			printf("Could not activate OCSP (error: %ld)", res);
			return MOSQ_ERR_OCSP;
		}
		if ((res=SSL_CTX_set_tlsext_status_arg(mosq->ssl_ctx, mosq)) != 1) {
			printf("Could not activate OCSP (error: %ld)", res);
			return MOSQ_ERR_OCSP;
		}
	}

	ret = SSL_connect(mosq->ssl);
	if(ret != 1) {
		err = SSL_get_error(mosq->ssl, ret);
		if (err == SSL_ERROR_SYSCALL) {
			//mosq->want_connect = true;
			return MOSQ_ERR_SUCCESS;
		}
		if(err == SSL_ERROR_WANT_READ){
			//mosq->want_connect = true;
			/* We always try to read anyway */
		}else if(err == SSL_ERROR_WANT_WRITE){
			//mosq->want_write = true;
			//mosq->want_connect = true;
		}else{
			net__print_ssl_error(mosq);

			COMPAT_CLOSE(mosq->sock);
			mosq->sock = INVALID_SOCKET;
			net__print_ssl_error(mosq);
			return MOSQ_ERR_TLS;
		}
	}else{
		//mosq->want_connect = false;
	}
	return MOSQ_ERR_SUCCESS;
}

static int net__tls_load_ca(struct mosquitto *mosq)
{
	int ret;

	if(mosq->tls_use_os_certs){
		SSL_CTX_set_default_verify_paths(mosq->ssl_ctx);
	}
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if(mosq->tls_cafile || mosq->tls_capath){
		ret = SSL_CTX_load_verify_locations(mosq->ssl_ctx, mosq->tls_cafile, NULL);
		if(ret == 0){
			if(mosq->tls_cafile && mosq->tls_capath){
				printf("Error: Unable to load CA certificates, check cafile \"%s\" and capath \"%s\".", mosq->tls_cafile, mosq->tls_capath);
			}else if(mosq->tls_cafile){
				printf("Error: Unable to load CA certificates, check cafile \"%s\".", mosq->tls_cafile);
			}else{
				printf("Error: Unable to load CA certificates, check capath \"%s\".", mosq->tls_capath);
			}
			return MOSQ_ERR_TLS;
		}
	}
#else
#endif
	return MOSQ_ERR_SUCCESS;
}

static int net__init_ssl_ctx(struct mosquitto *mosq)
{
	int ret;
	uint8_t tls_alpn_wire[256];
	uint8_t tls_alpn_len;
	static int compteur = 0;
	printf("Benoit: ICI: net__init_ssl_ctx, compteur = %d\n", compteur++);

	if(mosq->user_ssl_ctx){
		printf("Benoit: mosq->user_ssl_ctx est non-nul\n");
		mosq->ssl_ctx = mosq->user_ssl_ctx;
	}

	/* Apply default SSL_CTX settings. This is only used if MOSQ_OPT_SSL_CTX
	 * has not been set, or if both of MOSQ_OPT_SSL_CTX and
	 * MOSQ_OPT_SSL_CTX_WITH_DEFAULTS are set. */
	if(mosq->tls_cafile || mosq->tls_capath || mosq->tls_use_os_certs){
		printf("Benoit: On est à la bonne place \n");
		if(!mosq->ssl_ctx){
			printf("Benoit: On initialise le ctx c'est bien \n");
			net__init_tls();

#if OPENSSL_VERSION_NUMBER < 0x10100000L
			mosq->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
#else
			printf("Benoit: opensll version > 0x10100000 \n");
			mosq->ssl_ctx = SSL_CTX_new(TLS_client_method());
#endif

			if(!mosq->ssl_ctx){
				printf("Error: Unable to create TLS context.");
				net__print_ssl_error(mosq);
				return MOSQ_ERR_TLS;
			}
		}


			SSL_CTX_set_options(mosq->ssl_ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		/* Allow use of DHE ciphers */
		SSL_CTX_set_dh_auto(mosq->ssl_ctx, 1);
#endif
		/* Disable compression */
		SSL_CTX_set_options(mosq->ssl_ctx, SSL_OP_NO_COMPRESSION);

		/* Set ALPN */
		if(mosq->tls_alpn) {
			tls_alpn_len = (uint8_t) strnlen(mosq->tls_alpn, 254);
			tls_alpn_wire[0] = tls_alpn_len;  /* first byte is length of string */
			memcpy(tls_alpn_wire + 1, mosq->tls_alpn, tls_alpn_len);
			SSL_CTX_set_alpn_protos(mosq->ssl_ctx, tls_alpn_wire, tls_alpn_len + 1U);
		}

//#ifdef SSL_MODE_RELEASE_BUFFERS
			/* Use even less memory per SSL connection. */
			SSL_CTX_set_mode(mosq->ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
//#endif

		if(mosq->tls_cafile || mosq->tls_capath || mosq->tls_use_os_certs){
			ret = net__tls_load_ca(mosq);
			if(ret != MOSQ_ERR_SUCCESS){
				net__print_ssl_error(mosq);
				return MOSQ_ERR_TLS;
			}
			if(mosq->tls_cert_reqs == 0){
				SSL_CTX_set_verify(mosq->ssl_ctx, SSL_VERIFY_NONE, NULL);
			}else{
				SSL_CTX_set_verify(mosq->ssl_ctx, SSL_VERIFY_PEER, mosquitto__server_certificate_verify);
			}

			if(mosq->tls_pw_callback){
				SSL_CTX_set_default_passwd_cb(mosq->ssl_ctx, mosq->tls_pw_callback);
				SSL_CTX_set_default_passwd_cb_userdata(mosq->ssl_ctx, mosq);
			}

			if(mosq->tls_certfile){
				ret = SSL_CTX_use_certificate_chain_file(mosq->ssl_ctx, mosq->tls_certfile);
				if(ret != 1){
					printf("Error: Unable to load client certificate \"%s\".", mosq->tls_certfile);
					net__print_ssl_error(mosq);
					return MOSQ_ERR_TLS;
				}
			}
			if(mosq->tls_keyfile){
				// if(mosq->tls_keyform == mosq_k_engine){ Benoit
				if(0){
				}else{
					ret = SSL_CTX_use_PrivateKey_file(mosq->ssl_ctx, mosq->tls_keyfile, SSL_FILETYPE_PEM);
					if(ret != 1){
						printf("Error: Unable to load client key file \"%s\".", mosq->tls_keyfile);
						net__print_ssl_error(mosq);
						return MOSQ_ERR_TLS;
					}
				}
				ret = SSL_CTX_check_private_key(mosq->ssl_ctx);
				if(ret != 1){
					printf("Error: Client certificate/key are inconsistent.");
					net__print_ssl_error(mosq);
					return MOSQ_ERR_TLS;
				}
			}
#ifdef FINAL_WITH_TLS_PSK
		}else if(mosq->tls_psk){
			SSL_CTX_set_psk_client_callback(mosq->ssl_ctx, psk_client_callback);
			if(mosq->tls_ciphers == NULL){
				SSL_CTX_set_cipher_list(mosq->ssl_ctx, "PSK");
			}
#endif
		}
	}

	return MOSQ_ERR_SUCCESS;
}



int net__socket_connect_step3(struct mosquitto *mosq, const char *host)
{
	BIO *bio;
	BTraceIn
	int rc = net__init_ssl_ctx(mosq);
	if(rc){
		net__socket_close(mosq);
		return rc;
	}

	if(mosq->ssl_ctx){
		if(mosq->ssl){
			SSL_free(mosq->ssl);
		}
		mosq->ssl = SSL_new(mosq->ssl_ctx);
		if(!mosq->ssl){
			net__socket_close(mosq);
			net__print_ssl_error(mosq);
			BLog("MOSQ_ERR_TLS");
			return MOSQ_ERR_TLS;
		}

		SSL_set_ex_data(mosq->ssl, tls_ex_index_mosq, mosq);
		bio = BIO_new_socket(mosq->sock, BIO_NOCLOSE);
		if(!bio){
			net__socket_close(mosq);
			net__print_ssl_error(mosq);
			BLog("MOSQ_ERR_TLS");
			return MOSQ_ERR_TLS;
		}
		SSL_set_bio(mosq->ssl, bio, bio);

		/*
		 * required for the SNI resolving
		 */
		if(SSL_set_tlsext_host_name(mosq->ssl, host) != 1) {
			net__socket_close(mosq);
			BLog("MOSQ_ERR_TLS");
			return MOSQ_ERR_TLS;
		}
		do {
			if(net__socket_connect_tls(mosq)){
				net__socket_close(mosq);
				BLog("MOSQ_ERR_TLS");
				return MOSQ_ERR_TLS;
			}
			if (mosq->want_connect == false)
				break;
			sleep(1);
		} while (1);
	}
	BTraceOut
	return MOSQ_ERR_SUCCESS;
}

/* Create a socket and connect it to 'ip' on port 'port'.  */
int net__socket_connect(struct mosquitto *mosq, const char *host, uint16_t port, const char *bind_address, bool blocking)
{
	int rc, rc2;
	BTraceIn
	if(!mosq || !host) return MOSQ_ERR_INVAL;
	BLog(" host %s", host);

	rc = net__try_connect(host, port, &mosq->sock, bind_address, blocking);  // Benoit: Ici on a une trace de wireshark.
	if(rc > 0) return rc;

	BLog("net__socket_connect %d", mosq->tcp_nodelay);
	if(mosq->tcp_nodelay){
		BLog("PAS ICI: mosq->tcp_nodelay %s\n", host);
		int flag = 1;
		if(setsockopt(mosq->sock, IPPROTO_TCP, TCP_NODELAY, (const void*)&flag, sizeof(int)) != 0){
			printf("Warning: Unable to set TCP_NODELAY.");
		}
	}

	{
		BLog("ICI: vers net__socket_connect_step3 %s\n", host);
		rc2 = net__socket_connect_step3(mosq, host);
		if(rc2) return rc2;
	}
	BTraceOut
	return rc;
}

static int net__handle_ssl(struct mosquitto* mosq, int ret)
{
	int err;
	//BTraceIn
	err = SSL_get_error(mosq->ssl, ret);
	if (err == SSL_ERROR_WANT_READ) {
		//BLog("READ");
		ret = -1;
		errno = EAGAIN;
	}
	else if (err == SSL_ERROR_WANT_WRITE) {
		BLog("WRITE");
		ret = -1;
		mosq->want_write = true;
		errno = EAGAIN;
	}
	else {
		BLog("ELSE");
		net__print_ssl_error(mosq);
		errno = EPROTO;
	}
	ERR_clear_error();

	return ret;
}

ssize_t net__read(struct mosquitto *mosq, void *buf, size_t count)
{
	//BTraceIn
	int ret;
	assert(mosq);
	errno = 0;
	if(mosq->ssl){
		ret = SSL_read(mosq->ssl, buf, (int)count);
		if(ret <= 0){
			ret = net__handle_ssl(mosq, ret);
		}
		if(ret>0)
			BLog("Read from SSL %d bytes", ret);
		return (ssize_t )ret;
	}else{
		/* Call normal read/recv */
		ret = read(mosq->sock, buf, count);
		if(ret>0)
			BLog("Read from SSL %d bytes", ret);
		return ret;
	}
}

ssize_t net__write(struct mosquitto *mosq, const void *buf, size_t count)
{
	int ret;
	assert(mosq);
	errno = 0;
	if(mosq->ssl){
		mosq->want_write = false;
		ret = SSL_write(mosq->ssl, buf, (int)count);
		if(ret < 0){
			ret = net__handle_ssl(mosq, ret);
		}
		return (ssize_t )ret;
	}else{
		/* Call normal write/send */

		return write(mosq->sock, buf, count);

	}
}


int net__socket_nonblock(mosq_sock_t *sock)
{
	int opt;
	/* Set non-blocking */
	BTraceIn
	opt = fcntl(*sock, F_GETFL, 0);
	if(opt == -1){
		COMPAT_CLOSE(*sock);
		*sock = INVALID_SOCKET;
		return MOSQ_ERR_ERRNO;
	}
	if(fcntl(*sock, F_SETFL, opt | O_NONBLOCK) == -1){
		/* If either fcntl fails, don't want to allow this client to connect. */
		COMPAT_CLOSE(*sock);
		*sock = INVALID_SOCKET;
		return MOSQ_ERR_ERRNO;
	}
	return MOSQ_ERR_SUCCESS;
}

int net__socketpair(mosq_sock_t *pairR, mosq_sock_t *pairW)
{
	BTraceIn
	int sv[2];

	*pairR = INVALID_SOCKET;
	*pairW = INVALID_SOCKET;

	if(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1){
		return MOSQ_ERR_ERRNO;
	}
	if(net__socket_nonblock(&sv[0])){
		COMPAT_CLOSE(sv[1]);
		return MOSQ_ERR_ERRNO;
	}
	if(net__socket_nonblock(&sv[1])){
		COMPAT_CLOSE(sv[0]);
		return MOSQ_ERR_ERRNO;
	}
	*pairR = sv[0];
	*pairW = sv[1];
	return MOSQ_ERR_SUCCESS;

}

lwmqtt_err_t lwmqtt_network_read(void *ref, uint8_t *buf, size_t len, size_t *read, uint32_t timeout)
{
	struct mosquitto *mosq = (struct mosquitto *)ref;
	ssize_t byteRead;
	byteRead = net__read(mosq, buf, len);
	if (byteRead < -1)
	{
		*read = 0;
		return LWMQTT_NETWORK_FAILED_READ;
	}
	else if(byteRead == -1 )
	{
		*read = 0;
		return LWMQTT_SUCCESS;
	}
	*read = byteRead;
	return LWMQTT_SUCCESS;
}

lwmqtt_err_t lwmqtt_network_write(void *ref, uint8_t *buf, size_t len, size_t *sent, uint32_t timeout)
{
	struct mosquitto *mosq = (struct mosquitto *)ref;
	ssize_t byteRead;
	byteRead = net__write(mosq, buf, len);
	if (byteRead < -1)
	{
		*sent = 0;
		return LWMQTT_NETWORK_FAILED_WRITE;
	}
	else if(byteRead == -1 )
	{
		*sent = 0;
		return LWMQTT_SUCCESS;
	}
	*sent = byteRead;
	return LWMQTT_SUCCESS;
}

#include <unistd.h>
 #include <sys/ioctl.h>

lwmqtt_err_t GetFionRead(int sock, size_t *available)
{
    int iocAvail;
    int rc = ioctl(sock, FIONREAD, &iocAvail);
    if (rc < 0) {
		*available = 0;
        BLog("LWMQTT_NETWORK_FAILED_READ");
        return LWMQTT_NETWORK_FAILED_READ;
    }
	*available = iocAvail;

    return LWMQTT_SUCCESS;
}

lwmqtt_err_t lwmqtt_network_SSL_pending(SSL *ssl, size_t *available)
{
	ssize_t byteToRead;
	byteToRead = SSL_pending(ssl);
	if (byteToRead < 0)
	{
		*available = 0;
		return LWMQTT_NETWORK_FAILED_READ;
	}
	*available = byteToRead;
	return LWMQTT_SUCCESS;
}

lwmqtt_err_t lwmqtt_network_peek(void *ref, size_t *available)
{
	lwmqtt_err_t rc = LWMQTT_SUCCESS;
	struct mosquitto *mosq = (struct mosquitto *)ref;
	rc = lwmqtt_network_SSL_pending(mosq->ssl, available);
	if (*available > 0)
		return rc;
	rc = GetFionRead(mosq->sock, available);
	if( rc == LWMQTT_SUCCESS) {
		if(*available)
			*available = 1;
	}
	return rc;
	
}
