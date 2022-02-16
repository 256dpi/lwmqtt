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
#include <sys/ioctl.h>

#if AP
#include <aruba/util/grouplog_cloudconnect.h>
#else
#include "config.h"
#endif

void TLS::PrintSslError(int e1)
{
	char ebuf[256];
	unsigned long e;
	int num = 0;
    if(e1 != 0)
		GLERROR_LWMQTT("OpenSSL (e1) Error[%d]: %s", num, ERR_error_string(e1, ebuf));


	e = ERR_get_error();
	while(e){
		GLERROR_LWMQTT("OpenSSL Error[%d]: %s", num, ERR_error_string(e, ebuf));
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
                ret = 0;
                errno = EAGAIN;
            }
            break;

        case SSL_ERROR_WANT_WRITE:
            {
                //DBLog(DBLogLevel_SSL_RW, "WRITE");
                ret = 0;
                errno = EAGAIN;
            }
            break;
        case SSL_ERROR_ZERO_RETURN:
            {
        		GLERROR_LWMQTT("SSL_ERROR_ZERO_RETURN");
		        PrintSslError(err);
		        errno = EPROTO;
            }
            break;
        case SSL_CTRL_SESS_CACHE_FULL:
            {
                long val;
                val = SSL_CTX_sess_get_cache_size(m_ssl_ctx);
        		GLERROR_LWMQTT("CACHE SIZE = %ld", val);
		        PrintSslError(err);
		        errno = EPROTO;
            }
            break;

        case SSL_ERROR_SYSCALL:
            {
        		GLERROR_LWMQTT("SSL_ERROR_SYSCALL, set m_want_connect");
		        PrintSslError(err);
                m_want_connect = true;
                ret = 0;
            }
            break;
    	default:
            {
        		GLERROR_LWMQTT("Unkown. err = %d", err);
		        PrintSslError(err);
		        errno = EPROTO;
            }
            break;
	}
	ERR_clear_error();

	return ret;
}



TLS::TlsMsg_E  GetFionRead(int sock, size_t *available)
{
    int iocAvail;
    int rc = ioctl(sock, FIONREAD, &iocAvail);
    if (rc < 0) {
		*available = 0;
        GLERROR_LWMQTT("LWMQTT_NETWORK_FAILED_READ");
        return TLS::Msg_Err_Peek;
    }
	*available = iocAvail;

    return TLS::Msg_Success;
}

TLS::TlsMsg_E lwmqtt_network_SSL_pending(SSL *ssl, size_t *available)
{
	ssize_t byteToRead;
	byteToRead = SSL_pending(ssl);
	if (byteToRead < 0)
	{
		*available = 0;
		return TLS::Msg_Err_Peek;
	}
	*available = byteToRead;
	return TLS::Msg_Success;
}

TLS::TlsMsg_E TLS::Peek(size_t *available) {
	TlsMsg_E rc = Msg_Success;
	rc = lwmqtt_network_SSL_pending(m_ssl, available);
	if (*available > 0)
		return rc;
	rc = GetFionRead(m_tls_data->socket, available);
	if( rc == Msg_Success) {
		if(*available)
			*available = 1;
	}
	return rc;
}

TLS::TlsMsg_E TLS::Read(uint8_t *buffer, size_t len, size_t *read, uint32_t timeout)
{
    TlsMsg_E err = Msg_Success;
    ssize_t ret;
	ERR_clear_error();
    if(m_ssl)
    {
        ret = SSL_read(m_ssl, buffer, len);
        if(ret <= 0){
             ret = Msg_Err_Read;
            *read = 0;
            if (!HandleSslError(ret) )
                err = Msg_Success;
        }
        else {
            *read = (size_t)ret;
            GLERROR_LWMQTT("SSL_read() len = %lu, read = %lu, timeout = %u", len, *read, timeout);
        }
    }
    return err;
}

TLS::TlsMsg_E TLS::Write(uint8_t *buffer, size_t len, size_t *sent, uint32_t timeout)
{
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
            GLERROR_LWMQTT("SSL_write() len = %lu, sent = %lu, timeout = %u", len, *sent, timeout);
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
    static int mosquitto__verify_certificate_hostname(X509 *cert, const char *hostname)
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
    m_tls_data->tls_connected = false;
    SslClose();
	if(m_ssl_ctx){
		SSL_CTX_free(m_ssl_ctx);
	}
    m_ssl_ctx = nullptr;
}

void TLS::InitTlsCryptoVersion(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
#else
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
    if (IsInitialized())
        return;

    InitTlsCryptoVersion();
    SetOpensslExIndex();
    SetInitialized();
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
            SSL_CTX_set_options(m_ssl_ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

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

    int rc = InitSslCtx();
    if (rc)
    {
        Close();
        return rc;
    }

    if (m_ssl_ctx)
    {
        if (m_ssl)
        {
            SSL_free(m_ssl);
        }
        m_ssl = SSL_new(m_ssl_ctx);
        if (!m_ssl)
        {
            return Msg_Err_Tls;
        }

        SSL_set_ex_data(m_ssl, m_openssl_ex_index, m_tls_data);
        bio = BIO_new_socket(m_tls_data->socket, BIO_NOCLOSE);
        if (!bio)
        {
            Close();
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
            Close();
            BLog("Msg_Err_Tls");
            return Msg_Err_Tls;
        }
        do {
            if (SslConnect())
            {
                Close();
                BLog("Msg_Err_Tls");
                return Msg_Err_Tls;
            }
            sleep(1);  // TODO: Benoit Check this sleep, is usefull or not ?
        } while (m_want_connect);
        
    }
    m_tls_data->tls_connected = true;
    return Msg_Success;
}

