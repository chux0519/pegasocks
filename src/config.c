#include "config.h"
#include "parson/parson.h"
#include "crypto.h"

#include <stdio.h>
#include <unistd.h>

/**
 * load config
 *
 * this will try to open the config file and
 * parse it as json inputo
 *
 * @param config file path, must in json format
 * @return a pointer to newly created config
 */
pgs_config_t *pgs_config_load(const char *config)
{
	// Open config file, parse as json
	FILE *fp = fopen(config, "r");
	if (fp == NULL) {
		return NULL;
	}

	// Read from file
	fseek(fp, 0, SEEK_END);
	int fsize = ftell(fp);
	rewind(fp);
	char *fcontent = (char *)malloc(sizeof(char) * (fsize + 1));
	fread(fcontent, 1, fsize, fp);
	fcontent[fsize] = '\0';

	pgs_config_t *ptr = pgs_config_parse(fcontent);

	// Release buffer and fd
	free(fcontent);
	fclose(fp);

	return ptr;
}

pgs_config_t *pgs_config_parse(const char *json)
{
	pgs_config_t *ptr = pgs_config_new();
	JSON_Object *root_obj;
	JSON_Object *log_file_obj;
	JSON_Array *servers_array;

	ptr->root_value = json_parse_string(json);

	if (ptr->root_value == NULL ||
	    json_value_get_type(ptr->root_value) != JSONObject)
		goto error;
	root_obj = json_value_get_object(ptr->root_value);

	const char *log_file =
		json_object_get_string(root_obj, CONFIG_LOG_FILE);
	if (log_file != NULL) {
		FILE *log_fd = fopen(log_file, "a+");
		if (log_fd == NULL) {
			goto error;
		} else {
			ptr->log_file = log_fd;
		}
	}
	ptr->log_isatty = isatty(fileno(ptr->log_file));

	const char *local_address =
		json_object_get_string(root_obj, CONFIG_LOCAL_ADDRESS);
	if (local_address == NULL)
		goto error;
	ptr->local_address = local_address;

	double port = json_object_get_number(root_obj, CONFIG_LOCAL_PORT);
	if (port == 0)
		goto error;
	ptr->local_port = (int)port;

	const char *control_file =
		json_object_get_string(root_obj, CONFIG_CONTROL_FILE);
	if (control_file != NULL)
		ptr->control_file = control_file;

	double control_port =
		json_object_get_number(root_obj, CONFIG_CONTROL_PORT);
	if (control_file == NULL && control_port != 0)
		ptr->control_port = (int)control_port;

	double timeout = json_object_get_number(root_obj, CONFIG_TIMEOUT);
	if (timeout != 0)
		ptr->timeout = (int)timeout;

	double log_level = json_object_get_number(root_obj, CONFIG_LOG_LEVEL);
	if (log_level != 0)
		ptr->log_level = (int)log_level;

	double ping_interval =
		json_object_get_number(root_obj, CONFIG_PING_INTERVAL);
	if (ping_interval != 0)
		ptr->ping_interval = (int)ping_interval;
	else
		ptr->ping_interval = 120;

	servers_array = json_object_get_array(root_obj, CONFIG_SERVERS);
	if (servers_array == NULL)
		goto error;

	ptr->servers_count = json_array_get_count(servers_array);

	ptr->servers = pgs_config_parse_servers(ptr, servers_array);
	if (ptr->servers == NULL)
		goto error;

	return ptr;
error:
	pgs_config_error(ptr, "Error: pgs_config_parse");
	pgs_config_free(ptr);

	return NULL;
}

pgs_server_config_t *pgs_config_parse_servers(pgs_config_t *config,
					      JSON_Array *servers_array)
{
	JSON_Object *server;
	int len = json_array_get_count(servers_array);
	if (len == 0)
		return NULL;
	pgs_server_config_t *ptr = pgs_servers_config_new(len);
	for (int i = 0; i < len; i++) {
		server = json_array_get_object(servers_array, i);
		if (server == NULL)
			goto error;

		const char *server_address =
			json_object_get_string(server, CONFIG_SERVER_ADDRESS);
		if (servers_array == NULL)
			goto error;
		ptr[i].server_address = server_address;

		double server_port =
			json_object_get_number(server, CONFIG_SERVER_PORT);
		if (server_port == 0)
			goto error;
		ptr[i].server_port = (int)server_port;

		const char *server_type =
			json_object_get_string(server, CONFIG_SERVER_TYPE);
		if (server_type == NULL)
			goto error;
		ptr[i].server_type = server_type;

		const char *password =
			json_object_get_string(server, CONFIG_SERVER_PASSWORD);
		if (password == NULL)
			goto error;

		if (IS_TROJAN_SERVER(server_type)) {
			// password = to_hexstring(sha224(password))
			uint8_t encoded_pass[SHA224_LEN];
			uint64_t encoded_len = 0;
			sha224((const uint8_t *)password, strlen(password),
			       encoded_pass, &encoded_len);
			if (encoded_len != SHA224_LEN)
				goto error;

			uint8_t *hexpass =
				to_hexstring(encoded_pass, encoded_len);

			ptr[i].password = hexpass;
		} else if (IS_V2RAY_SERVER(server_type)) {
			size_t len = strlen(password);
			if (len != 36) // invalid uuid
				goto error;
			char uuid_hex[32];
			for (int j = 0, k = 0; j < 36 && k < 32;) {
				if (password[j] != '-')
					uuid_hex[k++] = password[j++];
				else
					j++;
			}
			uint8_t *uuid = malloc(16 * sizeof(uint8_t));
			hextobin(uuid_hex, uuid, 16);
			ptr[i].password = uuid;
		} else if (IS_SHADOWSOCKS_SERVER(server_type)) {
			uint8_t *pass = (uint8_t *)strdup(password);
			ptr[i].password = pass;
		}
		if (ptr[i].password == NULL)
			goto error;

		// parse type specific data
		ptr[i].extra = pgs_server_config_parse_extra(
			config, server_type, server);
		if (ptr[i].extra == NULL)
			goto error;
	}
	return ptr;
error:
	pgs_config_error(config, "Error: pgs_config_parse_servers");
	pgs_servers_config_free(ptr, len);
	return NULL;
}

void pgs_server_config_free_extra(const char *server_type, void *ptr)
{
	if (IS_TROJAN_SERVER(server_type)) {
		return pgs_config_extra_trojan_free(ptr);
	} else if (IS_V2RAY_SERVER(server_type)) {
		return pgs_config_extra_v2ray_free(ptr);
	} else if (IS_SHADOWSOCKS_SERVER(server_type)) {
		return pgs_config_extra_ss_free(ptr);
	}
}

void *pgs_server_config_parse_extra(pgs_config_t *config,
				    const char *server_type, JSON_Object *jobj)
{
	if (IS_TROJAN_SERVER(server_type)) {
		return pgs_config_extra_trojan_parse(config, jobj);
	} else if (IS_V2RAY_SERVER(server_type)) {
		return pgs_config_extra_v2ray_parse(config, jobj);
	} else if (IS_SHADOWSOCKS_SERVER(server_type)) {
		return pgs_config_extra_ss_parse(config, jobj);
	}
	return NULL;
}

pgs_config_t *pgs_config_new()
{
	pgs_config_t *ptr = malloc(sizeof(pgs_config_t));
	ptr->root_value = NULL;
	ptr->servers = NULL;
	ptr->servers_count = 0;
	ptr->local_address = NULL;
	ptr->local_port = 0;
	ptr->control_port = 0;
	ptr->control_file = "/tmp/pegas.sock";
	ptr->timeout = 30;
	ptr->log_level = 0;
	ptr->log_file = stderr;
	return ptr;
}

pgs_server_config_t *pgs_servers_config_new(uint64_t len)
{
	pgs_server_config_t *ptr = malloc(sizeof(pgs_server_config_t) * len);
	for (int i = 0; i < len; i++) {
		ptr[i].server_address = NULL;
		ptr[i].server_port = 0;
		ptr[i].server_type = NULL;
		ptr[i].password = NULL;
		ptr[i].extra = NULL;
	}
	return ptr;
}

void pgs_servers_config_free(pgs_server_config_t *ptr, uint64_t len)
{
	if (ptr == NULL || len == 0)
		return;
	for (int i = 0; i < len; i++) {
		if (ptr[i].extra)
			pgs_server_config_free_extra(ptr[i].server_type,
						     ptr[i].extra);
		if (ptr[i].server_type != NULL && ptr[i].password != NULL &&
		    (IS_TROJAN_SERVER(ptr[i].server_type) ||
		     IS_V2RAY_SERVER(ptr[i].server_type) ||
		     IS_SHADOWSOCKS_SERVER(ptr[i].server_type)))
			free(ptr[i].password);
	}
	free(ptr);
	ptr = NULL;
}

void pgs_config_free(pgs_config_t *config)
{
	if (config->log_file != stderr)
		fclose(config->log_file);
	if (config->servers)
		pgs_servers_config_free(config->servers, config->servers_count);

	if (config->root_value != NULL) {
		json_value_free(config->root_value);
		config->root_value = NULL;
	}

	free(config);

	config = NULL;
}

/* trojan config */
pgs_config_extra_trojan_t *pgs_config_extra_trojan_parse(pgs_config_t *config,
							 JSON_Object *jobj)
{
	pgs_config_extra_trojan_t *ptr = pgs_config_extra_trojan_new();
	ptr->ssl.enabled = true;

	const char *sni = json_object_dotget_string(jobj, CONFIG_SSL_SNI);
	if (sni != NULL)
		ptr->ssl.sni = sni;

	const char *ws_path = json_object_dotget_string(jobj, CONFIG_WS_PATH);
	if (ws_path != NULL) {
		ptr->websocket.enabled = true;
		ptr->websocket.path = ws_path;
	}

	const char *ws_hostname =
		json_object_dotget_string(jobj, CONFIG_WS_HOSTNAME);
	if (ws_hostname != NULL)
		ptr->websocket.hostname = ws_hostname;

	return ptr;

error:
	pgs_config_error(config, "Error: pgs_config_extra_trojan_parse");
	pgs_config_extra_trojan_free(ptr);
	return NULL;
}

pgs_config_extra_trojan_t *pgs_config_extra_trojan_new()
{
	pgs_config_extra_trojan_t *ptr =
		malloc(sizeof(pgs_config_extra_trojan_t));
	ptr->ssl.enabled = true;
	ptr->ssl.cert = NULL;
	ptr->ssl.sni = NULL;
	ptr->websocket.enabled = false;
	ptr->websocket.hostname = NULL;
	ptr->websocket.path = NULL;

	return ptr;
}

void pgs_config_extra_trojan_free(pgs_config_extra_trojan_t *ptr)
{
	free(ptr);
	ptr = NULL;
}

/* v2ray */
pgs_config_extra_v2ray_t *pgs_config_extra_v2ray_parse(pgs_config_t *config,
						       JSON_Object *jobj)
{
	pgs_config_extra_v2ray_t *ptr = pgs_config_extra_v2ray_new();

	const char *secure = json_object_get_string(jobj, CONFIG_VMESS_SECURE);
	if (secure != NULL) {
		if (strcasecmp(secure, "aes-128-gcm") == 0) {
			ptr->secure = AEAD_AES_128_GCM;
		} else if (strcasecmp(secure, "aes-128-cfb") == 0) {
			ptr->secure = AES_128_CFB;
		} else if (strcasecmp(secure, "chacha20-poly1305") == 0) {
			ptr->secure = AEAD_CHACHA20_POLY1305;
		}
	}

	JSON_Value *ssl_value = json_object_get_value(jobj, "ssl");
	if (ssl_value != NULL) {
		ptr->ssl.enabled = true;
	} else {
		ptr->ssl.enabled = false;
	}

	const char *sni = json_object_dotget_string(jobj, CONFIG_SSL_SNI);
	if (sni != NULL)
		ptr->ssl.sni = sni;

	const char *ws_path = json_object_dotget_string(jobj, CONFIG_WS_PATH);
	if (ws_path != NULL) {
		ptr->websocket.enabled = true;
		ptr->websocket.path = ws_path;
	}

	const char *ws_hostname =
		json_object_dotget_string(jobj, CONFIG_WS_HOSTNAME);
	if (ws_hostname != NULL)
		ptr->websocket.hostname = ws_hostname;

	return ptr;

error:
	pgs_config_error(config, "Error: pgs_config_extra_v2ray_parse");
	pgs_config_extra_v2ray_free(ptr);
	return NULL;
}

pgs_config_extra_v2ray_t *pgs_config_extra_v2ray_new()
{
	pgs_config_extra_v2ray_t *ptr =
		malloc(sizeof(pgs_config_extra_v2ray_t));
	ptr->ssl.enabled = false;
	ptr->ssl.cert = NULL;
	ptr->ssl.sni = NULL;
	ptr->websocket.enabled = false;
	ptr->websocket.hostname = NULL;
	ptr->websocket.path = NULL;
	ptr->secure = AES_128_CFB;

	return ptr;
}
void pgs_config_extra_v2ray_free(pgs_config_extra_v2ray_t *ptr)
{
	free(ptr);
	ptr = NULL;
}

/* shadowsocks */
pgs_config_extra_ss_t *pgs_config_extra_ss_parse(pgs_config_t *config,
						 JSON_Object *jobj)
{
	pgs_config_extra_ss_t *ptr = pgs_config_extra_ss_new();

	const char *method = json_object_get_string(jobj, CONFIG_SS_METHOD);
	if (method != NULL) {
		if (strcasecmp(method, "aes-128-cfb") == 0) {
			ptr->method = AES_128_CFB;
		} else if (strcasecmp(method, "aes-128-gcm") == 0) {
			ptr->method = AEAD_AES_128_GCM;
		} else if (strcasecmp(method, "aes-256-gcm") == 0) {
			ptr->method = AEAD_AES_256_GCM;
		} else if (strcasecmp(method, "chacha20-poly1305") == 0) {
			ptr->method = AEAD_CHACHA20_POLY1305;
		}
	}

	const char *plugin = json_object_dotget_string(jobj, CONFIG_SS_PLUGIN);
	const char *plugin_opts =
		json_object_dotget_string(jobj, CONFIG_SS_PLUGIN_OPTS);
	if (plugin != NULL)
		ptr->plugin = plugin;
	if (plugin_opts != NULL)
		ptr->plugin_opts = plugin_opts;

	return ptr;

error:
	pgs_config_error(config, "Error: pgs_config_extra_ss_parse");
	pgs_config_extra_ss_free(ptr);
	return NULL;
}

pgs_config_extra_ss_t *pgs_config_extra_ss_new()
{
	pgs_config_extra_ss_t *ptr = malloc(sizeof(pgs_config_extra_ss_t));
	ptr->plugin = NULL;
	ptr->plugin_opts = NULL;
	ptr->method = AEAD_CHACHA20_POLY1305;

	return ptr;
}

void pgs_config_extra_ss_free(pgs_config_extra_ss_t *ptr)
{
	free(ptr);
	ptr = NULL;
}
