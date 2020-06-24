#ifndef _PGS_CONFIG
#define _PGS_CONFIG

#include "pgs_core.h"
#include "pgs_log.h"
#include <stdbool.h>
#include <json-c/json.h>

typedef struct pgs_config_s pgs_config_t;
typedef struct pgs_server_config_s pgs_server_config_t;
typedef struct pgs_trojanserver_config_s pgs_trojanserver_config_t;
typedef struct pgs_trojanserver_ssl_s pgs_trojanserver_ssl_t;
typedef struct pgs_trojanserver_ws_s pgs_trojanserver_ws_t;

#define pgs_config_info(config, ...)                                           \
	pgs_logger_main_info(config->log_file, __VA_ARGS__)
#define pgs_config_error(config, ...)                                          \
	pgs_logger_main_error(config->log_file, __VA_ARGS__)

struct pgs_config_s {
	pgs_server_config_t *servers;
	int servers_count;
	const char *local_address;
	int local_port;
	int timeout;
	int log_level;
	FILE *log_file;
};

struct pgs_server_config_s {
	const char *server_address;
	const char *server_type;
	int server_port;
	char *password;
	void *extra; // type specific
};

struct pgs_trojanserver_config_s {
	struct pgs_trojanserver_ssl_s {
		const char *cert;
	} ssl;
	struct pgs_trojanserver_ws_s {
		bool enabled;
		const char *path;
		const char *hostname;
		bool double_tls;
	} websocket;
	pgs_ssl_ctx_t *ssl_ctx;
};

pgs_config_t *pgs_config_load(const char *config);
pgs_server_config_t *pgs_config_parse_servers(pgs_config_t *config,
					      json_object *jobj);

void *pgs_server_config_parse_extra(pgs_config_t *config,
				    const char *server_type, json_object *jobj);
void pgs_server_config_free_extra(const char *server_type, void *ptr);

pgs_trojanserver_config_t *pgs_trojanserver_config_parse(pgs_config_t *config,
							 json_object *jobj);

pgs_trojanserver_config_t *pgs_trojanserver_config_new();
void pgs_trojanserver_config_free(pgs_trojanserver_config_t *tconf);

pgs_config_t *pgs_config_new();
void pgs_config_free(pgs_config_t *config);

pgs_server_config_t *pgs_servers_config_new(pgs_size_t len);
void pgs_servers_config_free(pgs_server_config_t *servers,
			     pgs_size_t servers_count);

#endif
