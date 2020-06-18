#include "crm_config.h"
#include <stdio.h>
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
crm_config_t *crm_config_load(const char *config)
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
	char *fcontent = (char *)malloc(sizeof(char) * fsize);
	fread(fcontent, 1, fsize, fp);

	// Parse json file
	json_object *jobj = json_tokener_parse(fcontent);

	// Release buffer and fd
	crm_free(fcontent);
	fclose(fp);

	// Parse content
	crm_config_t *ptr = crm_config_new();

	json_object_object_foreach(jobj, key, val)
	{
		if (strcmp(key, "local_address") == 0) {
			ptr->local_address = json_object_get_string(val);
			if (ptr->local_address == NULL) {
				crm_config_free(ptr);
			}
		} else if (strcmp(key, "local_port") == 0) {
			ptr->local_port = json_object_get_int(val);
			if (ptr->local_port == 0) {
				crm_config_free(ptr);
			}
		} else if (strcmp(key, "timeout") == 0) {
			ptr->timeout = json_object_get_int(val);
			if (ptr->timeout == 0) {
				crm_config_free(ptr);
			}
		} else if (strcmp(key, "log_level") == 0) {
			ptr->log_level = json_object_get_int(val);
		} else if (strcmp(key, "log_file") == 0) {
			const char *log_file = json_object_get_string(val);
			if (log_file != NULL) {
				FILE *log_fd = fopen(log_file, "a+");
				if (log_fd == NULL) {
					crm_config_free(ptr);
				} else {
					ptr->log_file = log_fd;
				}
			}
		} else if (strcmp(key, "servers") == 0) {
			ptr->servers_count = json_object_array_length(val);
			ptr->servers = crm_config_parse_servers(val);
			if (ptr->servers == NULL) {
				crm_config_free(ptr);
			}
		}
	}
	return ptr;
}

crm_server_config_t *crm_config_parse_servers(json_object *jobj)
{
	int len = json_object_array_length(jobj);
	if (len == 0)
		return NULL;
	crm_server_config_t *ptr =
		crm_malloc(sizeof(crm_server_config_t) * len);
	for (int i = 0; i < len; i++) {
		json_object *jobj_server = json_object_array_get_idx(jobj, i);
		if (jobj_server == NULL) {
			goto error;
		}

		json_object_object_foreach(jobj_server, key, val)
		{
			if (strcmp(key, "server_address") == 0) {
				ptr[i].server_address =
					json_object_get_string(val);
				if (ptr[i].server_address == NULL) {
					goto error;
				}
			} else if (strcmp(key, "server_port") == 0) {
				ptr[i].server_port = json_object_get_int(val);
				if (ptr[i].server_port == 0) {
					goto error;
				}
			} else if (strcmp(key, "server_type") == 0) {
				ptr[i].server_type =
					json_object_get_string(val);
				if (ptr[i].server_type == NULL) {
					goto error;
				}
			} else if (strcmp(key, "password") == 0) {
				ptr[i].password = json_object_get_string(val);
				if (ptr[i].password == NULL) {
					goto error;
				}
			}
		}
		// parse type specific data
		ptr[i].extra = crm_server_config_parse_extra(ptr[i].server_type,
							     jobj_server);
	}
	return ptr;
error:
	perror("parse servers config");
	crm_free(ptr);
	return NULL;
}

void *crm_server_config_parse_extra(const char *server_type, json_object *jobj)
{
	if (strcmp(server_type, "trojan") == 0) {
		return crm_trojanserver_config_parse(jobj);
	}
	return NULL;
}

crm_trojanserver_config_t *crm_trojanserver_config_parse(json_object *jobj)
{
	crm_trojanserver_config_t *ptr = crm_trojanserver_config_new();

	json_object *ssl_obj = json_object_object_get(jobj, "ssl");
	json_object *ws_obj = json_object_object_get(jobj, "websocket");
	if (ssl_obj == NULL || ws_obj == NULL)
		goto error;

	// parse ssl config
	json_object_object_foreach(ssl_obj, key, val)
	{
		if (strcmp(key, "cert") == 0) {
			ptr->ssl.cert = json_object_get_string(val);
			if (ptr->ssl.cert == NULL)
				goto error;
		}
	}

	// parse websocket config
	json_object_object_foreach(ws_obj, k, v)
	{
		if (strcmp(k, "enabled") == 0) {
			ptr->websocket.enabled = json_object_get_boolean(v);
		} else if (strcmp(k, "path") == 0) {
			ptr->websocket.path = json_object_get_string(v);
		} else if (strcmp(k, "hostname") == 0) {
			ptr->websocket.hostname = json_object_get_string(v);
		} else if (strcmp(k, "double_tls") == 0) {
			ptr->websocket.double_tls = json_object_get_boolean(v);
		}
	}

	if (ptr->websocket.enabled &&
	    (ptr->websocket.path == NULL || ptr->websocket.hostname == NULL))
		goto error;

	return ptr;
error:
	perror("parse trojan server config");
	crm_trojanserver_config_free(ptr);
	return NULL;
}

crm_trojanserver_config_t *crm_trojanserver_config_new()
{
	crm_trojanserver_config_t *ptr =
		crm_malloc(sizeof(crm_trojanserver_config_t));
	ptr->ssl.cert = NULL;
	ptr->websocket.double_tls = false;
	ptr->websocket.enabled = false;
	ptr->websocket.hostname = NULL;
	ptr->websocket.path = NULL;

	return ptr;
}

void crm_trojanserver_config_free(crm_trojanserver_config_t *ptr)
{
	if (ptr->ssl.cert)
		crm_free((char *)ptr->ssl.cert);
	if (ptr->websocket.hostname)
		crm_free((char *)ptr->websocket.hostname);
	if (ptr->websocket.path)
		crm_free((char *)ptr->websocket.path);

	crm_free(ptr);
}

crm_config_t *crm_config_new()
{
	crm_config_t *ptr = crm_malloc(sizeof(crm_config_t));
	ptr->servers = NULL;
	ptr->servers_count = 0;
	ptr->local_address = NULL;
	ptr->local_port = 0;
	ptr->timeout = 0;
	ptr->log_level = 0;
	ptr->log_file = stderr;
	return ptr;
}

void crm_config_free(crm_config_t *config)
{
	if (config->local_address != NULL) {
		crm_free((char *)config->local_address);
	}
	if (config->log_file != stderr) {
		fclose(config->log_file);
	}

	if (config->servers != NULL) {
		crm_free(config->servers);
	}

	crm_free(config);

	config = NULL;
}
