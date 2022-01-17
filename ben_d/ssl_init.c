





#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/time.h>
#include <strings.h>

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

extern int net__init(void);

static unsigned int init_refcount = 0;

int mosquitto_lib_init(void)
{
	int rc;

	if (init_refcount == 0) {
#if _POSIX_TIMERS>0 && defined(_POSIX_MONOTONIC_CLOCK)
#error "Benoit ici on est en mode ?"
		struct timespec tp;

		clock_gettime(CLOCK_MONOTONIC, &tp);
		srand((unsigned int)tp.tv_nsec);
#else
		struct timeval tv;

		gettimeofday(&tv, NULL);
		srand(tv.tv_sec*1000 + tv.tv_usec/1000);
#endif

		rc = net__init();
		if (rc != MOSQ_ERR_SUCCESS) {
			return rc;
		}
	}

	init_refcount++;
	return MOSQ_ERR_SUCCESS;
}


