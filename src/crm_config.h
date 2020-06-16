#ifndef _CRM_CONFIG
#define _CRM_CONFIG

#include "crm_core.h"

typedef struct crm_config_s crm_config_t;
typedef struct crm_server_config_s crm_server_config_t;

struct crm_config_s {
	const char *local_address;
	int local_port;
	int timeout;
	int log_level;
};

struct crm_server_config_s {
	const char *server_address;
	const char *server_type;
	int server_port;
	const char *password;
	void *extra; // type specific
};

struct crm_trojanserver_config_s {
	struct crm_trojanserver_ssl_s {
		const char *cert;
	} ssl;
	struct crm_trojanserver_ws_s {
		bool enabled;
		const char *path;
		const char *hostname;
		bool double_tls;
	} websocket;
};

#endif
