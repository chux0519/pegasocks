#include "crm_config.h"
#include <stdio.h>
#include <json-c/json.h>
#include "crm_util.h"
#include <openssl/ssl.h>
#include <openssl/err.h>

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
			if (ptr->local_address == NULL)
				goto error;
		} else if (strcmp(key, "local_port") == 0) {
			ptr->local_port = json_object_get_int(val);
			if (ptr->local_port == 0)
				goto error;
		} else if (strcmp(key, "timeout") == 0) {
			ptr->timeout = json_object_get_int(val);
			if (ptr->timeout == 0)
				goto error;
		} else if (strcmp(key, "log_level") == 0) {
			ptr->log_level = json_object_get_int(val);
		} else if (strcmp(key, "log_file") == 0) {
			const char *log_file = json_object_get_string(val);
			if (log_file != NULL) {
				FILE *log_fd = fopen(log_file, "a+");
				if (log_fd == NULL) {
					goto error;
				} else {
					ptr->log_file = log_fd;
				}
			}
		} else if (strcmp(key, "servers") == 0) {
			ptr->servers_count = json_object_array_length(val);
			ptr->servers = crm_config_parse_servers(val);
			if (ptr->servers == NULL)
				goto error;
		}
	}
	return ptr;
error:
	perror("parse config");
	crm_config_free(ptr);
	return NULL;
}

crm_server_config_t *crm_config_parse_servers(json_object *jobj)
{
	int len = json_object_array_length(jobj);
	if (len == 0)
		return NULL;
	crm_server_config_t *ptr = crm_servers_config_new(len);
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
					(char *)json_object_get_string(val);
				if (ptr[i].password == NULL)
					goto error;
			}
		}
		// parse type specific data
		ptr[i].extra = crm_server_config_parse_extra(ptr[i].server_type,
							     jobj_server);
		if (strcmp(ptr[i].server_type, "trojan") == 0) {
			if (ptr[i].extra == NULL)
				goto error;
			// password = to_hexstring(sha224(password))
			crm_buf_t encoded_pass[SHA224_LEN];
			crm_size_t encoded_len = 0;
			sha224((const crm_buf_t *)ptr[i].password,
			       strlen(ptr[i].password), encoded_pass,
			       &encoded_len);
			if (encoded_len != SHA224_LEN)
				goto error;

			crm_buf_t *hexpass =
				to_hexstring(encoded_pass, encoded_len);

			ptr[i].password = (char *)hexpass;
		}
	}
	return ptr;
error:
	perror("parse servers config");
	crm_servers_config_free(ptr, len);
	return NULL;
}

void crm_server_config_free_extra(const char *server_type, void *ptr)
{
	if (strcmp(server_type, "trojan") == 0) {
		return crm_trojanserver_config_free(ptr);
	}
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
	if (ssl_obj == NULL)
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

	if (ws_obj != NULL) {
		// parse websocket config
		json_object_object_foreach(ws_obj, k, v)
		{
			if (strcmp(k, "enabled") == 0) {
				ptr->websocket.enabled =
					json_object_get_boolean(v);
			} else if (strcmp(k, "path") == 0) {
				ptr->websocket.path = json_object_get_string(v);
			} else if (strcmp(k, "hostname") == 0) {
				ptr->websocket.hostname =
					json_object_get_string(v);
			} else if (strcmp(k, "double_tls") == 0) {
				ptr->websocket.double_tls =
					json_object_get_boolean(v);
			}
		}

		if (ptr->websocket.enabled && (ptr->websocket.path == NULL ||
					       ptr->websocket.hostname == NULL))
			goto error;
	}

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	ptr->ssl_ctx = SSL_CTX_new(SSLv23_method());
	if (ptr->ssl_ctx == NULL) {
		fprintf(stderr, "SSL_CTX_new");
		ERR_print_errors_fp(stderr);
		goto error;
	}
	//if (SSL_CTX_load_verify_locations(ptr->ssl_ctx, ptr->ssl.cert, NULL) !=
	//    1) {
	//	fprintf(stderr, "SSL_CTX_load_verify_locations");
	//	goto error;
	//}
	//SSL_CTX_set_verify(ptr->ssl_ctx, SSL_VERIFY_PEER, NULL);

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
	ptr->ssl_ctx = NULL;

	return ptr;
}

void crm_trojanserver_config_free(crm_trojanserver_config_t *ptr)
{
	if (ptr->ssl_ctx != NULL)
		SSL_CTX_free(ptr->ssl_ctx);
	crm_free(ptr);
	ptr = NULL;
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

crm_server_config_t *crm_servers_config_new(crm_size_t len)
{
	crm_server_config_t *ptr =
		crm_malloc(sizeof(crm_server_config_t) * len);
	for (int i = 0; i < len; i++) {
		ptr[i].server_address = NULL;
		ptr[i].server_port = 0;
		ptr[i].server_type = NULL;
		ptr[i].password = NULL;
		ptr[i].extra = NULL;
	}
	return ptr;
}

void crm_servers_config_free(crm_server_config_t *ptr, crm_size_t len)
{
	if (ptr == NULL || len == 0)
		return;
	for (int i = 0; i < len; i++) {
		if (ptr[i].extra)
			crm_server_config_free_extra(ptr[i].server_type,
						     ptr[i].extra);
		if (ptr[i].server_type != NULL &&
		    strcmp(ptr[i].server_type, "trojan") == 0 &&
		    ptr[i].password != NULL)
			crm_free(ptr[i].password);
	}
	crm_free(ptr);
	ptr = NULL;
}

void crm_config_free(crm_config_t *config)
{
	if (config->log_file != stderr)
		fclose(config->log_file);
	if (config->servers)
		crm_servers_config_free(config->servers, config->servers_count);

	crm_free(config);

	config = NULL;
}
