#include "config.h"
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

extern "C"
{

    int g_tls_ex_index_mosq = -1;
    void SetGlobalOpensslExIndex(int index)
    {
        g_tls_ex_index_mosq = index;
    }
    int GetGlobalOpensslExIndex(void)
    {
        return g_tls_ex_index_mosq;
    }

    static int mosquitto__cmp_hostname_wildcard(char *certname, const char *hostname)
    {
        size_t i;
        size_t len;

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

    int mosquitto__server_certificate_verify(int preverify_ok, X509_STORE_CTX *ctx)
    {
        /* Preverify should have already checked expiry, revocation.
         * We need to verify the hostname. */
        SSL *ssl;
        X509 *cert;
        TlsData_S *tls_data;

        /* Always reject if preverify_ok has failed. */
        if (!preverify_ok)
            return 0;

        ssl = (SSL *)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
        tls_data = (TlsData_S *)SSL_get_ex_data(ssl, g_tls_ex_index_mosq);
        if (!tls_data)
            return 0;

        if (tls_data->tls_insecure == false
#ifndef WITH_BROKER
            && tls_data->port != 0 /* no hostname checking for unix sockets */
#endif
        )
        {
            if (X509_STORE_CTX_get_error_depth(ctx) == 0)
            {
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

extern "C"
{
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

} // extern "C" {

TLS::TLS(const char *host, uint16_t port, int socket)
{
    m_initialized = false;
    m_openssl_ex_index = -1;
    m_ssl_ctx = nullptr;
    m_tls_data.host = host; // std::string(host).c_str();
    m_tls_data.port = port;
    m_tls_data.socket = socket;
}

TLS::TLS(TlsData_S &data)
{
    m_initialized = false;
    m_openssl_ex_index = -1;
    m_ssl_ctx = nullptr;
    m_tls_data = data;
}

void TLS::SetupUiMethod(void)
{
    m_ui_method = UI_create_method("OpenSSL application user interface");
    UI_method_set_opener(m_ui_method, ui_open);
    UI_method_set_reader(m_ui_method, ui_read);
    UI_method_set_writer(m_ui_method, ui_write);
    UI_method_set_closer(m_ui_method, ui_close);
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
    SetupUiMethod();
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
    if (m_tls_data.tls_use_os_certs)
    {
        SSL_CTX_set_default_verify_paths(m_ssl_ctx);
    }
    if (m_tls_data.tls_cafile || m_tls_data.tls_capath)
    {
        ret = SSL_CTX_load_verify_locations(m_ssl_ctx, m_tls_data.tls_cafile, m_tls_data.tls_capath);
        if (ret == 0)
        {
            if (m_tls_data.tls_cafile && m_tls_data.tls_capath)
            {
                BLog("Error: Unable to load CA certificates, check cafile \"%s\" and capath \"%s\".", m_tls_data.tls_cafile, m_tls_data.tls_capath);
            }
            else if (m_tls_data.tls_cafile)
            {
                BLog("Error: Unable to load CA certificates, check cafile \"%s\".", m_tls_data.tls_cafile);
            }
            else
            {
                BLog("Error: Unable to load CA certificates, check capath \"%s\".", m_tls_data.tls_capath);
            }
            return Msg_Err_Tls;
        }
    }
    return Msg_Success;
}

int TLS::Certificats()
{
    int ret;
    if (m_tls_data.tls_cafile || m_tls_data.tls_capath || m_tls_data.tls_use_os_certs)
    {
        BLog("if(m_tls_cafile || m_tls_capath || m_tls_use_os_certs)");
        ret = LoadCA();
        if (ret != Msg_Success)
        {
            PrintTlsError();
            return Msg_Err_Tls;
        }
        if (m_tls_data.tls_cert_reqs == 0)
        {
            SSL_CTX_set_verify(m_ssl_ctx, SSL_VERIFY_NONE, NULL);
        }
        else
        {
            SSL_CTX_set_verify(m_ssl_ctx, SSL_VERIFY_PEER, mosquitto__server_certificate_verify);
        }
        if (m_tls_data.tls_certfile)
        {
            ret = SSL_CTX_use_certificate_chain_file(m_ssl_ctx, m_tls_data.tls_certfile);
            if (ret != 1)
            {
                BLog("Error: Unable to load client certificate \"%s\".", m_tls_data.tls_certfile);
                PrintTlsError();
                BLog("Msg_Err_Tls");
                return Msg_Err_Tls;
            }
        }
        if (m_tls_data.tls_keyfile)
        {
            printf("Benoit: 1000: m_tls_data.tls_keyfile \n");
            printf("Benoit: 1003: FAUX (m_tls_data.tls_keyform == mosq_k_engine) \n");
            ret = SSL_CTX_use_PrivateKey_file(m_ssl_ctx, m_tls_data.tls_keyfile, SSL_FILETYPE_PEM);
            if (ret != 1)
            {
                BLog("Error: Unable to load client key file \"%s\".", m_tls_data.tls_keyfile);
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
    DHECiphers();
    SSL_CTX_set_dh_auto(m_ssl_ctx, 1);
#endif
}

void TLS::SetALPN()
{
    uint8_t tls_alpn_wire[256];
    uint8_t tls_alpn_len;

    /* Set ALPN */
    if (m_tls_data.tls_alpn)
    {
        tls_alpn_len = (uint8_t)strnlen(m_tls_data.tls_alpn, 254);
        tls_alpn_wire[0] = tls_alpn_len; /* first byte is length of string */
        memcpy(tls_alpn_wire + 1, m_tls_data.tls_alpn, tls_alpn_len);
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
    if (m_tls_data.tls_cafile || m_tls_data.tls_capath || m_tls_data.tls_use_os_certs)
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
            if (!strcmp(m_tls_data.tls_version, "tlsv1.2"))
            {
                SSL_CTX_set_options(m_ssl_ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
            }
            else
            {
                BLog("Erreur pour la version de tlsv1.2, %s", m_tls_data.tls_version);
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
        m_ssl = NULL;
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
        if (!m_ssl)
        {
            return Msg_Err_Tls;
        }

        SSL_set_ex_data(m_ssl, m_openssl_ex_index, &m_tls_data);
        bio = BIO_new_socket(m_tls_data.socket, BIO_NOCLOSE);
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
        if (SSL_set_tlsext_host_name(m_ssl, m_tls_data.host) != 1)
        {
            SslClose();
            BLog("Msg_Err_Tls");
            return Msg_Err_Tls;
        }

        if (SslConnect())
        {
            SslClose();
            BLog("Msg_Err_Tls");
            return Msg_Err_Tls;
        }
    }
    BTraceOut;
    return Msg_Success;
}


#if 0
/* Create a socket and connect it to 'ip' on port 'port'.  */
int net__socket_connect(struct mosquitto *mosq, const char *host, uint16_t port, const char *bind_address, bool blocking)
{
    int rc, rc2;
BTraceIn
    if(!mosq || !host) return MOSQ_ERR_INVAL;
    BLog(" host %s", host);

    rc = net__try_connect(host, port, &m_sock, bind_address, blocking);
    if(rc > 0) return rc;

    BLog("net__socket_connect %d", m_tcp_nodelay);
    if(m_tcp_nodelay){
        BLog("PAS ICI: m_tcp_nodelay %s\n", host);
        int flag = 1;
        if(setsockopt(m_sock, IPPROTO_TCP, TCP_NODELAY, (const void*)&flag, sizeof(int)) != 0){
            log__printf(mosq, MOSQ_LOG_WARNING, "Warning: Unable to set TCP_NODELAY.");
        }
    }

#if defined(WITH_SOCKS) && !defined(WITH_BROKER)
    if(!m_socks5_host)
#endif
    {
        BLog("ICI: vers net__socket_connect_step3 %s\n", host);
        rc2 = net__socket_connect_step3(mosq, host);
        if(rc2) return rc2;
    }
BTraceOut
    return rc;
}
#endif

#ifdef WITH_TLS
static int net__handle_ssl(struct mosquitto *mosq, int ret)
{
    int err;

    err = SSL_get_error(m_ssl, ret);
    if (err == SSL_ERROR_WANT_READ)
    {
        ret = -1;
        errno = EAGAIN;
    }
    else if (err == SSL_ERROR_WANT_WRITE)
    {
        ret = -1;
#ifdef WITH_BROKER
        mux__add_out(mosq);
#else
        m_want_write = true;
#endif
        errno = EAGAIN;
    }
    else
    {
        PrintTlsError();
        errno = EPROTO;
    }
    ERR_clear_error();
#ifdef WIN32
    WSASetLastError(errno);
#endif

    return ret;
}
#endif
