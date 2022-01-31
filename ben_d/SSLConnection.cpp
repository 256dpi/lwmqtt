#include "config.h"
#include "Socket.h"
#include "SSLConnection.h"

#include <iostream>
#include <string>
#include <cstring>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/ui.h>
#include <openssl/x509v3.h>

#include <unistd.h>


void TLS::PrintSslError(int e1)
{
    DBTraceIn;
	char ebuf[256];
	unsigned long e;
	int num = 0;
    if(e1 != 0)
		DBLog(DBLogLevel_INFO, "OpenSSL (e1) Error[%d]: %s", num, ERR_error_string(e1, ebuf));


	e = ERR_get_error();
	while(e){
		DBLog(DBLogLevel_INFO, "OpenSSL Error[%d]: %s", num, ERR_error_string(e, ebuf));
		e = ERR_get_error();
		num++;
	}
}

int TLS::HandleSslError(int ret)
{
	int err;
	err = SSL_get_error(m_ssl, ret);
    switch(err)
    {
        case SSL_ERROR_WANT_READ:
            {
                //DBLog(DBLogLevel_SSL_RW, "READ"); // Too many print out
                ret = -1;   
                errno = EAGAIN;
            }
            break;

        case SSL_ERROR_WANT_WRITE:
            {
                DBLog(DBLogLevel_SSL_RW, "WRITE");
                ret = -1;
                errno = EAGAIN;
            }
            break;
        case SSL_ERROR_ZERO_RETURN:
            {
        		DBLog(DBLogLevel_SSL_RW, "SSL_ERROR_ZERO_RETURN");
		        PrintSslError(err);
		        errno = EPROTO;
            }
            break;
        case SSL_CTRL_SESS_CACHE_FULL:
            {
                long val;
                val = SSL_CTX_sess_get_cache_size(m_ssl_ctx);
        		DBLog(DBLogLevel_SSL_RW, "CACHE SIZE = %ld", val);
		        PrintSslError(err);
		        errno = EPROTO;
            }
            break;
    	default:
            {
        		DBLog(DBLogLevel_SSL_RW, "ELSE. err = %d", err);
		        PrintSslError(err);
		        errno = EPROTO;
            }
            break;
	}
	ERR_clear_error();

	return ret;
}

TLS::TlsMsg_E TLS::Peek(size_t *available) {
    BTraceIn
    TlsMsg_E err = Msg_Success;
    ssize_t ret;
	ERR_clear_error();
    if(m_ssl)
    {
        ret = SSL_peek(m_ssl, NULL, 0);
        //BLog("SSL_peek() = %ld", ret);
        if(ret < 0){
            err = Msg_Err_Peek;
            *available = 0;
            HandleSslError(ret);
        }
        else {
            *available = (size_t)ret;
        }
    }
    return err;
}

TLS::TlsMsg_E TLS::Read(uint8_t *buffer, size_t len, size_t *read, uint32_t timeout)
{
//    BTraceIn
    TlsMsg_E err = Msg_Success;
    ssize_t ret;
	ERR_clear_error();
    if(m_ssl)
    {
        ret = SSL_read(m_ssl, buffer, len);
        if(ret <= 0){
            *read = 0;
            HandleSslError(ret);
        }
        else {
            *read = (size_t)ret;
        }
    }
    return err;
}

TLS::TlsMsg_E TLS::Write(uint8_t *buffer, size_t len, size_t *sent, uint32_t timeout)
{
//    BTraceIn
    TlsMsg_E err = Msg_Success;
    ssize_t ret;
	ERR_clear_error();
    if(m_ssl)
    {
        ret = SSL_write(m_ssl, buffer, len);
        if(ret <= 0){
            err = Msg_Err_Write;
            *sent = 0;
            HandleSslError(ret);
        }
        else {
            *sent = (size_t)ret;
        }
    }
    return err;
}

extern "C"
{

    int g_tls_ex_index_mosq = -1;
    void SetGlobalOpensslExIndex(int index)
    {
        BLog("___ %d", index);
        g_tls_ex_index_mosq = index;
    }
    int GetGlobalOpensslExIndex(void)
    {
        BLog("___  %d", g_tls_ex_index_mosq );
        return g_tls_ex_index_mosq;
    }

    static int mosquitto__cmp_hostname_wildcard(char *certname, const char *hostname)
    {
        size_t i;
        size_t len;

        BLog("____");
        if (!certname || !hostname)
        {
            return 1;
        }

        if (certname[0] == '*')
        {
            if (certname[1] != '.')
            {
                return 1;
            }
            certname += 2;
            len = strlen(hostname);
            for (i = 0; i < len - 1; i++)
            {
                if (hostname[i] == '.')
                {
                    hostname += i + 1;
                    break;
                }
            }
            return strcasecmp(certname, hostname);
        }
        else
        {
            return strcasecmp(certname, hostname);
        }
    }

    /* This code is based heavily on the example provided in "Secure Programming
     * Cookbook for C and C++".
     */
    int mosquitto__verify_certificate_hostname(X509 *cert, const char *hostname)
    {
        int i;
        char name[256];
        X509_NAME *subj;
        bool have_san_dns = false;
        STACK_OF(GENERAL_NAME) * san;
        const GENERAL_NAME *nval;
        const unsigned char *data;
        unsigned char ipv6_addr[16];
        unsigned char ipv4_addr[4];
        int ipv6_ok;
        int ipv4_ok;
        BTraceIn
        ipv6_ok = inet_pton(AF_INET6, hostname, &ipv6_addr);
        ipv4_ok = inet_pton(AF_INET, hostname, &ipv4_addr);

        san = (STACK_OF(GENERAL_NAME) *)X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
        if (san)
        {
            for (i = 0; i < sk_GENERAL_NAME_num(san); i++)
            {
                nval = sk_GENERAL_NAME_value(san, i);
                if (nval->type == GEN_DNS)
                {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
                    data = ASN1_STRING_data(nval->d.dNSName);
#else
                    data = ASN1_STRING_get0_data(nval->d.dNSName);
#endif
                    if (data && !mosquitto__cmp_hostname_wildcard((char *)data, hostname))
                    {
                        sk_GENERAL_NAME_pop_free(san, GENERAL_NAME_free);
                        return 1;
                    }
                    have_san_dns = true;
                }
                else if (nval->type == GEN_IPADD)
                {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
                    data = ASN1_STRING_data(nval->d.iPAddress);
#else
                    data = ASN1_STRING_get0_data(nval->d.iPAddress);
#endif
                    if (nval->d.iPAddress->length == 4 && ipv4_ok)
                    {
                        if (!memcmp(ipv4_addr, data, 4))
                        {
                            sk_GENERAL_NAME_pop_free(san, GENERAL_NAME_free);
                            return 1;
                        }
                    }
                    else if (nval->d.iPAddress->length == 16 && ipv6_ok)
                    {
                        if (!memcmp(ipv6_addr, data, 16))
                        {
                            sk_GENERAL_NAME_pop_free(san, GENERAL_NAME_free);
                            return 1;
                        }
                    }
                }
            }
            sk_GENERAL_NAME_pop_free(san, GENERAL_NAME_free);
            if (have_san_dns)
            {
                /* Only check CN if subjectAltName DNS entry does not exist. */
                return 0;
            }
        }

        subj = X509_get_subject_name(cert);
        if (X509_NAME_get_text_by_NID(subj, NID_commonName, name, sizeof(name)) > 0)
        {
            name[sizeof(name) - 1] = '\0';
            if (!mosquitto__cmp_hostname_wildcard(name, hostname))
                return 1;
        }
        return 0;
    }

    int opensll__server_certificate_verify(int preverify_ok, X509_STORE_CTX *ctx)
    {
        BTraceIn
        /* Preverify should have already checked expiry, revocation.
         * We need to verify the hostname. */
        SSL *ssl;
        X509 *cert;
        TlsData_S *tls_data;

        /* Always reject if preverify_ok has failed. */
        if (!preverify_ok)
            return 0;

        ssl = (SSL *)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
        tls_data = (TlsData_S *)SSL_get_ex_data(ssl, GetGlobalOpensslExIndex());
        BLog("mTls.m_ssl ici ssl = %p", (void*)ssl);
    	BLog("tls_ex_index_mosq = %d", GetGlobalOpensslExIndex());
        if (!tls_data){
            BLog("Error tls_data");
            return 0;
        }

        if (tls_data->tls_insecure == false
            && tls_data->port != 0 /* no hostname checking for unix sockets */
        )
        {
            BLog("X509_STORE_CTX_ phase 1");

            if (X509_STORE_CTX_get_error_depth(ctx) == 0)
            {
                BLog("X509_STORE_CTX_get_error_depth phase 2");
                /* FIXME - use X509_check_host() etc. for sufficiently new openssl (>=1.1.x) */
                cert = X509_STORE_CTX_get_current_cert(ctx);
                /* This is the peer certificate, all others are upwards in the chain. */
                preverify_ok = mosquitto__verify_certificate_hostname(cert, tls_data->host);
                if (preverify_ok != 1)
                {
                    BLog("Error: host name verification failed.");
                }
                return preverify_ok;
            }
            else
            {
                return preverify_ok;
            }
        }
        else
        {
            return preverify_ok;
        }
    }
}

TLS::TLS(TlsData_S *data)
{
    m_initialized = false;
    m_openssl_ex_index = -1;
    m_ssl_ctx = nullptr;
    m_ssl = nullptr;
    m_tls_data = data;
}

void TLS::Close()
{
    SslClose();
	if(m_ssl_ctx){
		SSL_CTX_free(m_ssl_ctx);
	}
    m_ssl_ctx = nullptr;
}

void TLS::InitTlsCryptoVersion(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    BLog("OUI OPENSSL_VERSION_NUMBER < 0x10100000L");
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
#else
    BLog("NON OPENSSL_VERSION_NUMBER < 0x10100000L");
    OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS | OPENSSL_INIT_LOAD_CONFIG, NULL);
#endif
}

void TLS::SetOpensslExIndex()
{
    if (m_openssl_ex_index == -1)
    {
        m_openssl_ex_index = SSL_get_ex_new_index(0, (void *)"client context", NULL, NULL, NULL);
        SetGlobalOpensslExIndex(m_openssl_ex_index);
    }
}

void TLS::InitTlsCrypto(void)
{
    BTraceIn if (IsInitialized()) return;

    InitTlsCryptoVersion();
    SetOpensslExIndex();
    SetInitialized();
    BTraceOut
}

void TLS::PrintTlsError(void)
{
    char ebuf[256];
    unsigned long e;
    int num = 0;

    e = ERR_get_error();
    while (e)
    {
        BLog("OpenSSL Error[%d]: %s", num, ERR_error_string(e, ebuf));
        e = ERR_get_error();
        num++;
    }
}

int TLS::LoadCA()
{
    int ret;
    if (m_tls_data->tls_use_os_certs)
    {
        SSL_CTX_set_default_verify_paths(m_ssl_ctx);
    }
    if (m_tls_data->tls_cafile || m_tls_data->tls_capath)
    {
        ret = SSL_CTX_load_verify_locations(m_ssl_ctx, m_tls_data->tls_cafile, nullptr);
        if (ret == 0)
        {
            if (m_tls_data->tls_cafile && m_tls_data->tls_capath)
            {
                BLog("Error: Unable to load CA certificates, check cafile \"%s\" and capath \"%s\".", m_tls_data->tls_cafile, m_tls_data->tls_capath);
            }
            else if (m_tls_data->tls_cafile)
            {
                BLog("Error: Unable to load CA certificates, check cafile \"%s\".", m_tls_data->tls_cafile);
            }
            else
            {
                BLog("Error: Unable to load CA certificates, check capath \"%s\".", m_tls_data->tls_capath);
            }
            return Msg_Err_Tls;
        }
    }
    return Msg_Success;
}

int TLS::Certificats()
{
    int ret;
    if (m_tls_data->tls_cafile || m_tls_data->tls_capath || m_tls_data->tls_use_os_certs)
    {
        BLog("if(m_tls_cafile || m_tls_capath || m_tls_use_os_certs)");
        ret = LoadCA();
        if (ret != Msg_Success)
        {
            PrintTlsError();
            return Msg_Err_Tls;
        }
        if (m_tls_data->tls_cert_reqs == 0)
        {
            SSL_CTX_set_verify(m_ssl_ctx, SSL_VERIFY_NONE, 0);
        }
        else
        {
            SSL_CTX_set_verify(m_ssl_ctx, SSL_VERIFY_PEER, opensll__server_certificate_verify);
        }
        if (m_tls_data->tls_certfile)
        {
            ret = SSL_CTX_use_certificate_chain_file(m_ssl_ctx, m_tls_data->tls_certfile);
            if (ret != 1)
            {
                BLog("Error: Unable to load client certificate \"%s\".", m_tls_data->tls_certfile);
                PrintTlsError();
                BLog("Msg_Err_Tls");
                return Msg_Err_Tls;
            }
        }
        if (m_tls_data->tls_keyfile)
        {
            printf("Benoit: 1000: m_tls_data->tls_keyfile \n");
            printf("Benoit: 1003: FAUX (m_tls_data->tls_keyform == mosq_k_engine) \n");
            ret = SSL_CTX_use_PrivateKey_file(m_ssl_ctx, m_tls_data->tls_keyfile, SSL_FILETYPE_PEM);
            if (ret != 1)
            {
                BLog("Error: Unable to load client key file \"%s\".", m_tls_data->tls_keyfile);
                PrintTlsError();
                BLog("Msg_Err_Tls");
                return Msg_Err_Tls;
            }
            ret = SSL_CTX_check_private_key(m_ssl_ctx);
            if (ret != 1)
            {
                BLog("Error: Client certificate/key are inconsistent.");
                PrintTlsError();
                BLog("Msg_Err_Tls");
                return Msg_Err_Tls;
            }
        }
    }
    return Msg_Success;
}

void TLS::SetSSLCtx()
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    m_ssl_ctx = SSL_CTX_new(SSLv23_client_method());
#else
    BLog("opensll version > 0x10100000");
    m_ssl_ctx = SSL_CTX_new(TLS_client_method());
#endif
}

void TLS::DHECiphers()
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    /* Allow use of DHE ciphers */
    SSL_CTX_set_dh_auto(m_ssl_ctx, 1);
#endif
}

void TLS::SetALPN()
{
    uint8_t tls_alpn_wire[256];
    uint8_t tls_alpn_len;

    /* Set ALPN */
    if (m_tls_data->tls_alpn)
    {
        tls_alpn_len = (uint8_t)strnlen(m_tls_data->tls_alpn, 254);
        tls_alpn_wire[0] = tls_alpn_len; /* first byte is length of string */
        memcpy(tls_alpn_wire + 1, m_tls_data->tls_alpn, tls_alpn_len);
        SSL_CTX_set_alpn_protos(m_ssl_ctx, tls_alpn_wire, tls_alpn_len + 1U);
    }
}

/**
 * @brief Initialize TLSConnection
 * Valide les differentes options de connexion au TLS
 *
 * @return int
 */
int TLS::InitSslCtx()
{
    int ret = Msg_Success;

    static int compteur = 0;
    BTraceIn
        BLog("compteur = %d\n", compteur++);
    // TODO: valider si on peut réentrer dans cette fonction, voir net__init_ssl_ctx

    /* Apply default SSL_CTX settings. This is only used if MOSQ_OPT_SSL_CTX
     * has not been set, or if both of MOSQ_OPT_SSL_CTX and
     * MOSQ_OPT_SSL_CTX_WITH_DEFAULTS are set. */
    if (m_tls_data->tls_cafile || m_tls_data->tls_capath || m_tls_data->tls_use_os_certs)
    {
        BLog("On est à la bonne place");
        if (!m_ssl_ctx)
        {
            BLog("On initialise le ctx c'est bien");
            InitTlsCrypto();

            SetSSLCtx();

            if (!m_ssl_ctx)
            {
                BLog("Msg_Err_Tls");
                PrintTlsError();
                ret = Msg_Err_Tls;
            }
        }
        if (ret == Msg_Success)
        {
            // TODO: Benoit Il faut prendre le TLSv1.2 ou 1.3
            // pour le moment par défaut on prend "tlsv1.2"
            if (!strcmp(m_tls_data->tls_version, "tlsv1.2"))
            {
                BLog("all0");
                SSL_CTX_set_options(m_ssl_ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
            }
            else
            {
                BLog("Erreur pour la version de tlsv1.2, %s", m_tls_data->tls_version);
            }

            /* Disable compression */
            SSL_CTX_set_options(m_ssl_ctx, SSL_OP_NO_COMPRESSION);

            DHECiphers();

            SetALPN();

            /* Use even less memory per SSL connection. */
            SSL_CTX_set_mode(m_ssl_ctx, SSL_MODE_RELEASE_BUFFERS);

            ret = Certificats();
        }
    }
    return ret;
}

void TLS::SslClose()
{
    if (m_ssl)
    {
        if (!SSL_in_init(m_ssl))
        {
            SSL_shutdown(m_ssl);
        }
        SSL_free(m_ssl);
        m_ssl = nullptr;
    }
}

int TLS::SslConnect()
{
 	int ret, err;

	ERR_clear_error();

	ret = SSL_connect(m_ssl);
	if(ret != 1) {
		err = SSL_get_error(m_ssl, ret);
		if (err == SSL_ERROR_SYSCALL) {
			m_want_connect = true;
			BLog("m_want_connect = true; SSL_ERROR_SYSCALL");
			return Msg_Success;
		}
		if(err == SSL_ERROR_WANT_READ){
			m_want_connect = true;
			BLog("m_want_connect = true; SSL_ERROR_WANT_READ");
			/* We always try to read anyway */
		}else if(err == SSL_ERROR_WANT_WRITE){
			m_want_write = true;
			m_want_connect = true;
			BLog("m_want_connect = true; SSL_ERROR_WANT_WRITE");
		}else{
			PrintTlsError();
			BLog("MOSQ_ERR_TLS");
			return Msg_Err_Tls;
		}
	}else{
		BLog("m_want_connect = false;");
		m_want_connect = false;
	}
	BLog("net__socket_connect_tls return");
	return Msg_Success;

}

int TLS::Init()
{
    BIO *bio;
    BTraceIn;
    int rc = InitSslCtx();
    if (rc)
    {
        SslClose();
        return rc;
    }

    if (m_ssl_ctx)
    {
        if (m_ssl)
        {
            SSL_free(m_ssl);
        }
        m_ssl = SSL_new(m_ssl_ctx);
        BLog("m_ssl = %p, &m_ssl = %p, &(m_ssl) = %p", (void*)m_ssl, (void*)&m_ssl, (void*)&(m_ssl));
        if (!m_ssl)
        {
            return Msg_Err_Tls;
        }

        SSL_set_ex_data(m_ssl, m_openssl_ex_index, m_tls_data);
        bio = BIO_new_socket(m_tls_data->socket, BIO_NOCLOSE);
        if (!bio)
        {
            SslClose();
            PrintTlsError();
            BLog("Msg_Err_Tls");
            return Msg_Err_Tls;
        }
        SSL_set_bio(m_ssl, bio, bio);

        /*
         * required for the SNI resolving
         */
        if (SSL_set_tlsext_host_name(m_ssl, m_tls_data->host) != 1)
        {
            SslClose();
            BLog("Msg_Err_Tls");
            return Msg_Err_Tls;
        }
        do {
            if (SslConnect())
            {
                SslClose();
                BLog("Msg_Err_Tls");
                return Msg_Err_Tls;
            }
            sleep(1);
        } while (m_want_connect);
        
    }
    BTraceOut;
    return Msg_Success;
}

#ifdef WITH_TLS
static int net__handle_ssl(struct mosquitto* mosq, int ret)
{
	int err;
	BTraceIn
	err = SSL_get_error(mosq->ssl, ret);
	if (err == SSL_ERROR_WANT_READ) {
		BLog("READ");
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
	BTraceIn
	int ret;
	assert(mosq);
	errno = 0;
	if(mosq->ssl){
		ret = SSL_read(mosq->ssl, buf, (int)count);
		if(ret <= 0){
			ret = net__handle_ssl(mosq, ret);
		}
		return (ssize_t )ret;
	}else{
		/* Call normal read/recv */
		return read(mosq->sock, buf, count);
	}
}

ssize_t net__write(struct mosquitto *mosq, const void *buf, size_t count)
{
	int ret;
	assert(mosq);
	BTraceIn
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

#endif // #ifdef WITH_TLS

