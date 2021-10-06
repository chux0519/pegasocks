#ifndef _PGS_CONFIG_H
#define _PGS_CONFIG_H

#include "log.h"
#include "crypto.h"
#include "utils.h"

#include <stdbool.h>
#include <stdint.h>
#include "parson/parson.h"

#define SERVER_TYPE_TROJAN "trojan"
#define SERVER_TYPE_V2RAY "v2ray"
#define SERVER_TYPE_SHADOWSOCKS "shadowsocks"

#define IS_TROJAN_SERVER(type) (strcasecmp((type), SERVER_TYPE_TROJAN) == 0)
#define IS_V2RAY_SERVER(type) (strcasecmp((type), SERVER_TYPE_V2RAY) == 0)
#define IS_SHADOWSOCKS_SERVER(type)                                            \
	(strcasecmp((type), SERVER_TYPE_SHADOWSOCKS) == 0)

// root config fields
#define CONFIG_LOCAL_ADDRESS "local_address"
#define CONFIG_LOCAL_PORT "local_port"
#define CONFIG_CONTROL_PORT "control_port"
#define CONFIG_CONTROL_FILE "control_file"
#define CONFIG_PING_INTERVAL "ping_interval"
#define CONFIG_LOG_FILE "log_file"
#define CONFIG_LOG_LEVEL "log_level"
#define CONFIG_TIMEOUT "timeout"
#define CONFIG_SERVERS "servers"
#define CONFIG_DNS_SERVERS "dns_servers"

// server fields
#define CONFIG_SERVER_ADDRESS "server_address"
#define CONFIG_SERVER_TYPE "server_type"
#define CONFIG_SERVER_PORT "server_port"
#define CONFIG_SERVER_PASSWORD "password"

// SNI
#define CONFIG_SSL_SNI "ssl.sni"

// WS
#define CONFIG_WS_PATH "websocket.path"
#define CONFIG_WS_HOSTNAME "websocket.hostname"

// VMESS secure
#define CONFIG_VMESS_SECURE "secure"

// SHADOWSOCKS
#define CONFIG_SS_METHOD "method"
#define CONFIG_SS_PLUGIN "plugin"
#define CONFIG_SS_PLUGIN_OPTS "plugin_opts"

typedef struct pgs_config_ssl_s pgs_trojanserver_ssl_t;
typedef struct pgs_config_ssl_s pgs_v2rayserver_ssl_t;

#define pgs_config_info(config, ...)                                           \
	pgs_logger_main_info(config->log_file, __VA_ARGS__)
#define pgs_config_error(config, ...)                                          \
	pgs_logger_main_error(config->log_file, __VA_ARGS__)

typedef struct pgs_server_config_s {
	const char *server_address;
	const char *server_type;
	int server_port;
	uint8_t *password;
	void *extra; // type specific
} pgs_server_config_t;

typedef struct pgs_config_s {
	JSON_Value *root_value;
	pgs_server_config_t *servers;
	int servers_count;
	const char *local_address;
	int local_port;
	int control_port;
	const char *control_file;
	int timeout;
	int ping_interval;
	int log_level;
	FILE *log_file;
	bool log_isatty;
	pgs_list_t *dns_servers;
} pgs_config_t;

typedef struct pgs_config_ssl_s {
	bool enabled;
	const char *sni;
	const char *cert;
} pgs_config_ssl_t;

typedef struct pgs_config_ws_s {
	bool enabled;
	const char *path;
	const char *hostname;
} pgs_config_ws_t;

typedef struct pgs_config_extra_trojan_s {
	pgs_config_ws_t websocket;
	pgs_config_ssl_t ssl;
} pgs_config_extra_trojan_t;

typedef struct pgs_config_extra_v2ray_s {
	pgs_config_ws_t websocket;
	pgs_config_ssl_t ssl;
	pgs_cryptor_type_t secure;
} pgs_config_extra_v2ray_t;

typedef struct pgs_config_extra_ss_s {
	pgs_cryptor_type_t method;
	const char *plugin;
	const char *plugin_opts;
} pgs_config_extra_ss_t;

/* common */
// load config from file
pgs_config_t *pgs_config_load(const char *config);
// parse config from string
pgs_config_t *pgs_config_parse(const char *json);
pgs_server_config_t *pgs_config_parse_servers(pgs_config_t *config,
					      JSON_Array *arr);
pgs_config_t *pgs_config_new();
void pgs_config_free(pgs_config_t *config);
pgs_server_config_t *pgs_servers_config_new(uint64_t len);
void pgs_servers_config_free(pgs_server_config_t *servers,
			     uint64_t servers_count);
void *pgs_server_config_parse_extra(pgs_config_t *config,
				    const char *server_type, JSON_Object *jobj);
void pgs_server_config_free_extra(const char *server_type, void *ptr);

/* trojan config */
pgs_config_extra_trojan_t *pgs_config_extra_trojan_parse(pgs_config_t *config,
							 JSON_Object *jobj);
pgs_config_extra_trojan_t *pgs_config_extra_trojan_new();
void pgs_config_extra_trojan_free(pgs_config_extra_trojan_t *tconf);

/* v2ray config */
pgs_config_extra_v2ray_t *pgs_config_extra_v2ray_parse(pgs_config_t *config,
						       JSON_Object *jobj);
pgs_config_extra_v2ray_t *pgs_config_extra_v2ray_new();
void pgs_config_extra_v2ray_free(pgs_config_extra_v2ray_t *ptr);

/* shadowsocks config */
pgs_config_extra_ss_t *pgs_config_extra_ss_parse(pgs_config_t *config,
						 JSON_Object *jobj);
pgs_config_extra_ss_t *pgs_config_extra_ss_new();
void pgs_config_extra_ss_free(pgs_config_extra_ss_t *ptr);

#endif
