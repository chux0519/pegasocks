#include "crm_config.h"
#include <stdio.h>
#include <json-c/json.h>

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
		}
		// TODO: parse server configs
	}
	return ptr;
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
	if (config->log_file != NULL) {
		crm_free((char *)config->log_file);
	}

	// TODO: free servers
	crm_free(config);

	config = NULL;
}
