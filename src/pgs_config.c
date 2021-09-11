#include "pgs_config.h"
#include "pgs_crypto.h"

#include <stdio.h>
#include <unistd.h>

#include <json-c/json.h>

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

	// Parse json file
	json_object *jobj = json_tokener_parse(fcontent);

	// Release buffer and fd
	free(fcontent);
	fclose(fp);

	// Parse content
	pgs_config_t *ptr = pgs_config_new();

	json_object *log_file_obj;
	if (json_object_object_get_ex(jobj, "log_file", &log_file_obj)) {
		const char *log_file = json_object_get_string(log_file_obj);
		if (log_file != NULL) {
			FILE *log_fd = fopen(log_file, "a+");
			if (log_fd == NULL) {
				goto error;
			} else {
				ptr->log_file = log_fd;
			}
		}
	}

	ptr->log_isatty = isatty(fileno(ptr->log_file));
	ptr->ping_interval = 120;

	json_object_object_foreach(jobj, key, val)
	{
		if (strcmp(key, "local_address") == 0) {
			ptr->local_address = json_object_get_string(val);
			if (ptr->local_address == NULL)
				goto error;
		} else if (strcmp(key, "local_port") == 0) {
			ptr->local_port = json_object_get_int(val);
			if (ptr->local_port == 0)
				goto error;
		} else if (strcmp(key, "control_file") == 0) {
			ptr->control_file = json_object_get_string(val);
			if (ptr->control_file == NULL)
				goto error;
		} else if (strcmp(key, "control_port") == 0) {
			ptr->control_port = json_object_get_int(val);
			if (ptr->control_port == 0)
				goto error;
		} else if (strcmp(key, "timeout") == 0) {
			ptr->timeout = json_object_get_int(val);
			if (ptr->timeout == 0)
				goto error;
		} else if (strcmp(key, "log_level") == 0) {
			ptr->log_level = json_object_get_int(val);
		} else if (strcmp(key, "servers") == 0) {
			ptr->servers_count = json_object_array_length(val);
			ptr->servers = pgs_config_parse_servers(ptr, val);
			if (ptr->servers == NULL)
				goto error;
		} else if (strcmp(key, "ping_interval") == 0) {
			ptr->ping_interval = json_object_get_int(val);
		}
	}
	return ptr;
error:
	pgs_config_error(ptr, "Error: pgs_config_load");
	pgs_config_free(ptr);
	return NULL;
}

pgs_server_config_t *pgs_config_parse_servers(pgs_config_t *config,
					      json_object *jobj)
{
	int len = json_object_array_length(jobj);
	if (len == 0)
		return NULL;
	pgs_server_config_t *ptr = pgs_servers_config_new(len);
	for (int i = 0; i < len; i++) {
		json_object *jobj_server = json_object_array_get_idx(jobj, i);
		if (jobj_server == NULL)
			goto error;

		json_object_object_foreach(jobj_server, key, val)
		{
			if (strcmp(key, "server_address") == 0) {
				ptr[i].server_address =
					json_object_get_string(val);
				if (ptr[i].server_address == NULL)
					goto error;
			} else if (strcmp(key, "server_port") == 0) {
				ptr[i].server_port = json_object_get_int(val);
				if (ptr[i].server_port == 0)
					goto error;
			} else if (strcmp(key, "server_type") == 0) {
				ptr[i].server_type =
					json_object_get_string(val);
				if (ptr[i].server_type == NULL)
					goto error;
			} else if (strcmp(key, "password") == 0) {
				ptr[i].password =
					(uint8_t *)json_object_get_string(val);
				if (ptr[i].password == NULL)
					goto error;
			}
		}
		if (strcmp(ptr[i].server_type, "trojan") == 0) {
			// password = to_hexstring(sha224(password))
			uint8_t encoded_pass[SHA224_LEN];
			uint64_t encoded_len = 0;
			sha224((const uint8_t *)ptr[i].password,
			       strlen((const char *)ptr[i].password),
			       encoded_pass, &encoded_len);
			if (encoded_len != SHA224_LEN)
				goto error;

			uint8_t *hexpass =
				to_hexstring(encoded_pass, encoded_len);

			ptr[i].password = hexpass;
		}
		if (strcmp(ptr[i].server_type, "v2ray") == 0) {
			char uuid_hex[32];
			for (int j = 0, k = 0; j < 36 && k < 32;) {
				if (ptr[i].password[j] != '-')
					uuid_hex[k++] = ptr[i].password[j++];
				else
					j++;
			}
			uint8_t *uuid = malloc(16 * sizeof(uint8_t));
			hextobin(uuid_hex, uuid, 16);
			ptr[i].password = uuid;
		}
		// parse type specific data
		ptr[i].extra = pgs_server_config_parse_extra(
			config, ptr[i].server_type, jobj_server);
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
	if (strcmp(server_type, "trojan") == 0) {
		return pgs_trojanserver_config_free(ptr);
	}
}

void *pgs_server_config_parse_extra(pgs_config_t *config,
				    const char *server_type, json_object *jobj)
{
	if (strcmp(server_type, "trojan") == 0) {
		return pgs_trojanserver_config_parse(config, jobj);
	} else if (strcmp(server_type, "v2ray") == 0) {
		return pgs_v2rayserver_config_parse(config, jobj);
	}

	return NULL;
}

pgs_config_t *pgs_config_new()
{
	pgs_config_t *ptr = malloc(sizeof(pgs_config_t));
	ptr->servers = NULL;
	ptr->servers_count = 0;
	ptr->local_address = NULL;
	ptr->local_port = 0;
	ptr->control_port = 0;
	ptr->control_file = "/tmp/pegas.sock";
	ptr->timeout = 0;
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
		if (ptr[i].server_type != NULL &&
		    (strcmp(ptr[i].server_type, "trojan") == 0 ||
		     strcmp(ptr[i].server_type, "v2ray") == 0) &&
		    ptr[i].password != NULL)
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

	free(config);

	config = NULL;
}

/* trojan config */
pgs_trojanserver_config_t *pgs_trojanserver_config_parse(pgs_config_t *config,
							 json_object *jobj)
{
	pgs_trojanserver_config_t *ptr = pgs_trojanserver_config_new();
	ptr->ssl_ctx = pgs_ssl_ctx_new();
	if (ptr->ssl_ctx == NULL) {
		pgs_config_error(config, "Error: pgs_ssl_ctx_new");
		goto error;
	}

	json_object *ssl_obj;
	if (json_object_object_get_ex(jobj, "ssl", &ssl_obj)) {
		ptr->ssl.enabled = true;
		json_object_object_foreach(ssl_obj, k, v)
		{
			if (strcmp(k, "sni") == 0) {
				ptr->ssl.sni = json_object_get_string(v);
			}
		}
	}

	json_object *ws_obj;
	if (json_object_object_get_ex(jobj, "websocket", &ws_obj)) {
		// parse websocket config
		ptr->websocket.enabled = true;
		json_object_object_foreach(ws_obj, k, v)
		{
			if (strcmp(k, "path") == 0) {
				ptr->websocket.path = json_object_get_string(v);
			} else if (strcmp(k, "hostname") == 0) {
				ptr->websocket.hostname =
					json_object_get_string(v);
			}
		}

		if (ptr->websocket.enabled && (ptr->websocket.path == NULL ||
					       ptr->websocket.hostname == NULL))
			goto error;
	}

	return ptr;

error:
	pgs_config_error(config, "Error: pgs_trojanserver_config_parse");
	pgs_trojanserver_config_free(ptr);
	return NULL;
}

pgs_trojanserver_config_t *pgs_trojanserver_config_new()
{
	pgs_trojanserver_config_t *ptr =
		malloc(sizeof(pgs_trojanserver_config_t));
	ptr->ssl.enabled = true;
	ptr->ssl.cert = NULL;
	ptr->ssl.sni = NULL;
	ptr->websocket.enabled = false;
	ptr->websocket.hostname = NULL;
	ptr->websocket.path = NULL;
	ptr->ssl_ctx = NULL;

	return ptr;
}

void pgs_trojanserver_config_free(pgs_trojanserver_config_t *ptr)
{
	if (ptr->ssl_ctx != NULL)
		pgs_ssl_ctx_free(ptr->ssl_ctx);
	free(ptr);
	ptr = NULL;
}

/* v2ray */
pgs_v2rayserver_config_t *pgs_v2rayserver_config_parse(pgs_config_t *config,
						       json_object *jobj)
{
	pgs_v2rayserver_config_t *ptr = pgs_v2rayserver_config_new();

	json_object *secure_obj;
	if (json_object_object_get_ex(jobj, "secure", &secure_obj)) {
		const char *secure = json_object_get_string(secure_obj);
		if (secure && strcmp(secure, "aes-128-gcm") == 0) {
			ptr->secure = V2RAY_SECURE_GCM;
		}
	}

	json_object *ssl_obj;
	if (json_object_object_get_ex(jobj, "ssl", &ssl_obj)) {
		ptr->ssl.enabled = true;
		ptr->ssl_ctx = pgs_ssl_ctx_new();
		if (ptr->ssl_ctx == NULL) {
			pgs_config_error(config, "Error: pgs_ssl_ctx_new");
			goto error;
		}
		json_object_object_foreach(ssl_obj, k, v)
		{
			if (strcmp(k, "sni") == 0) {
				ptr->ssl.sni = json_object_get_string(v);
			}
		}
	} else {
		ptr->ssl.enabled = false;
		ptr->ssl_ctx = NULL;
	}
	json_object *ws_obj;
	if (json_object_object_get_ex(jobj, "websocket", &ws_obj)) {
		// parse websocket config
		ptr->websocket.enabled = true;
		json_object_object_foreach(ws_obj, k, v)
		{
			if (strcmp(k, "path") == 0) {
				ptr->websocket.path = json_object_get_string(v);
			} else if (strcmp(k, "hostname") == 0) {
				ptr->websocket.hostname =
					json_object_get_string(v);
			}
		}
	}

	if (ptr->websocket.enabled &&
	    (ptr->websocket.path == NULL || ptr->websocket.hostname == NULL))
		goto error;

	return ptr;

error:
	pgs_config_error(config, "Error: pgs_v2rayserver_config_parse");
	pgs_v2rayserver_config_free(ptr);
	return NULL;
}

pgs_v2rayserver_config_t *pgs_v2rayserver_config_new()
{
	pgs_v2rayserver_config_t *ptr =
		malloc(sizeof(pgs_v2rayserver_config_t));
	ptr->ssl.enabled = false;
	ptr->ssl.cert = NULL;
	ptr->ssl.sni = NULL;
	ptr->websocket.enabled = false;
	ptr->websocket.hostname = NULL;
	ptr->websocket.path = NULL;
	ptr->ssl_ctx = NULL;
	ptr->secure = V2RAY_SECURE_CFB;

	return ptr;
}
void pgs_v2rayserver_config_free(pgs_v2rayserver_config_t *ptr)
{
	if (ptr->ssl_ctx != NULL)
		pgs_ssl_ctx_free(ptr->ssl_ctx);
	free(ptr);
	ptr = NULL;
}
