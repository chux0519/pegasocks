#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "core/config.h"

#define PGS_STREUQAL(a, b) assert(strcmp((a), (b)) == 0)
#define PGS_STRNEUQAL(a, b) assert(strcmp((a), (b)) != 0)

void test_base_config()
{
	static const char json[] = "{\
        \"servers\": [\
            {\
                \"server_address\": \"1.1.1.1\",\
                \"server_type\": \"trojan\",\
                \"server_port\": 443,\
                \"ssl\": {\
                    \"sni\": \"trojan.example.com\"\
                },\
                \"password\": \"password\"\
            }\
        ],\
        \"local_address\": \"0.0.0.0\",\
        \"local_port\": 1080,\
        \"control_port\": 11080,\
        \"ping_interval\": 120,\
        \"timeout\": 60,\
        \"log_file\": \"log_file\",\
        \"log_level\": 1\
    }";
	pgs_config_t *config = pgs_config_parse((const char *)json);
	assert(config != NULL);
	PGS_STREUQAL(config->local_address, "0.0.0.0");
	assert(config->log_file != NULL);
	assert(config->log_file != stderr);
	assert(config->local_port == 1080);
	assert(config->control_port == 11080);
	assert(config->ping_interval == 120);
	assert(config->timeout == 60);
	assert(config->log_level == 1);

	pgs_config_free(config);
}

void test_trojan_gfw_config()
{
	static const char json[] = "{\
        \"servers\": [\
            {\
                \"server_address\": \"trojan.example.com\",\
                \"server_type\": \"trojan\",\
                \"server_port\": 443,\
                \"ssl\": {\
                    \"sni\": \"trojan.example.com\"\
                },\
                \"password\": \"password\"\
            }\
        ],\
        \"local_address\": \"0.0.0.0\",\
        \"local_port\": 1080,\
        \"control_port\": 11080,\
        \"ping_interval\": 120,\
        \"timeout\": 60,\
        \"log_file\": \"log_file\",\
        \"log_level\": 1\
    }";
	pgs_config_t *config = pgs_config_parse((const char *)json);
	assert(config != NULL);
	PGS_STREUQAL(config->local_address, "0.0.0.0");
	assert(config->log_file != NULL);
	assert(config->log_file != stderr);
	assert(config->local_port == 1080);
	assert(config->control_port == 11080);
	assert(config->ping_interval == 120);
	assert(config->timeout == 60);
	assert(config->log_level == 1);

	pgs_server_config_t *server = &config->servers[0];
	assert(server != NULL);
	PGS_STREUQAL(server->server_address, "trojan.example.com");
	PGS_STREUQAL(server->server_type, "trojan");
	PGS_STRNEUQAL((const char *)server->password, "password");
	assert(server->password != NULL);
	assert(server->server_port == 443);

	assert(server->extra != NULL);
	pgs_config_extra_trojan_t *tconf =
		(pgs_config_extra_trojan_t *)server->extra;
	assert(tconf->ssl.enabled == true);
	PGS_STREUQAL(tconf->ssl.sni, "trojan.example.com");

	pgs_config_free(config);
}

void test_trojan_ws_config()
{
	static const char json[] = "{\
        \"servers\": [\
            {\
                \"server_address\": \"trojan.example.com\",\
                \"server_type\": \"trojan\",\
                \"server_port\": 443,\
                \"ssl\": {\
                    \"sni\": \"trojan.example.com\"\
                },\
                \"websocket\": {\
                    \"path\": \"/path\",\
                    \"hostname\": \"trojan.example.com\"\
                },\
                \"password\": \"password\"\
            }\
        ],\
        \"local_address\": \"0.0.0.0\",\
        \"local_port\": 1080,\
        \"control_port\": 11080,\
        \"ping_interval\": 120,\
        \"timeout\": 60,\
        \"log_file\": \"log_file\",\
        \"log_level\": 1\
    }";
	pgs_config_t *config = pgs_config_parse((const char *)json);
	assert(config != NULL);
	PGS_STREUQAL(config->local_address, "0.0.0.0");
	assert(config->log_file != NULL);
	assert(config->log_file != stderr);
	assert(config->local_port == 1080);
	assert(config->control_port == 11080);
	assert(config->ping_interval == 120);
	assert(config->timeout == 60);
	assert(config->log_level == 1);

	pgs_server_config_t *server = &config->servers[0];
	assert(server != NULL);
	PGS_STREUQAL(server->server_address, "trojan.example.com");
	PGS_STREUQAL(server->server_type, "trojan");
	PGS_STRNEUQAL((const char *)server->password, "password");
	assert(server->password != NULL);
	assert(server->server_port == 443);

	assert(server->extra != NULL);
	pgs_config_extra_trojan_t *tconf =
		(pgs_config_extra_trojan_t *)server->extra;
	assert(tconf->ssl.enabled == true);
	PGS_STREUQAL(tconf->ssl.sni, "trojan.example.com");

	PGS_STREUQAL(tconf->websocket.path, "/path");
	PGS_STREUQAL(tconf->websocket.hostname, "trojan.example.com");

	pgs_config_free(config);
}

void test_v2ray_tcp_config()
{
	static const char json[] = "{\
        \"servers\": [\
            {\
                \"server_address\": \"v2ray.example.com\",\
                \"server_type\": \"v2ray\",\
                \"server_port\": 10086,\
                \"password\": \"61455aba-a200-4b46-8dad-8478e1065e0d\"\
            }\
        ],\
        \"local_address\": \"0.0.0.0\",\
        \"local_port\": 1080,\
        \"control_port\": 11080,\
        \"ping_interval\": 120,\
        \"timeout\": 60,\
        \"log_file\": \"log_file\",\
        \"log_level\": 1\
    }";
	pgs_config_t *config = pgs_config_parse((const char *)json);
	assert(config != NULL);
	PGS_STREUQAL(config->local_address, "0.0.0.0");
	assert(config->log_file != NULL);
	assert(config->log_file != stderr);
	assert(config->local_port == 1080);
	assert(config->control_port == 11080);
	assert(config->ping_interval == 120);
	assert(config->timeout == 60);
	assert(config->log_level == 1);

	pgs_server_config_t *server = &config->servers[0];
	assert(server != NULL);
	PGS_STREUQAL(server->server_address, "v2ray.example.com");
	PGS_STREUQAL(server->server_type, "v2ray");
	PGS_STRNEUQAL((const char *)server->password, "password");
	assert(server->password != NULL);
	assert(server->server_port == 10086);

	pgs_config_free(config);
}

void test_v2ray_tcp_ssl_config()
{
	static const char json[] = "{\
        \"servers\": [\
            {\
                \"server_address\": \"v2ray.example.com\",\
                \"server_type\": \"v2ray\",\
                \"server_port\": 10086,\
                \"ssl\": {\
                    \"sni\": \"v2ray.example.com\"\
                },\
                \"password\": \"61455aba-a200-4b46-8dad-8478e1065e0d\"\
            }\
        ],\
        \"local_address\": \"0.0.0.0\",\
        \"local_port\": 1080,\
        \"control_port\": 11080,\
        \"ping_interval\": 120,\
        \"timeout\": 60,\
        \"log_file\": \"log_file\",\
        \"log_level\": 1\
    }";
	pgs_config_t *config = pgs_config_parse((const char *)json);
	assert(config != NULL);
	PGS_STREUQAL(config->local_address, "0.0.0.0");
	assert(config->log_file != NULL);
	assert(config->log_file != stderr);
	assert(config->local_port == 1080);
	assert(config->control_port == 11080);
	assert(config->ping_interval == 120);
	assert(config->timeout == 60);
	assert(config->log_level == 1);

	pgs_server_config_t *server = &config->servers[0];
	assert(server != NULL);
	PGS_STREUQAL(server->server_address, "v2ray.example.com");
	PGS_STREUQAL(server->server_type, "v2ray");
	PGS_STRNEUQAL((const char *)server->password, "password");
	assert(server->password != NULL);
	assert(server->server_port == 10086);

	assert(server->extra != NULL);
	pgs_config_extra_v2ray_t *vconf =
		(pgs_config_extra_v2ray_t *)server->extra;
	assert(vconf->ssl.enabled == true);
	PGS_STREUQAL(vconf->ssl.sni, "v2ray.example.com");

	pgs_config_free(config);
}

void test_v2ray_ws_config()
{
	static const char json[] = "{\
        \"servers\": [\
            {\
                \"server_address\": \"v2ray.example.com\",\
                \"server_type\": \"v2ray\",\
                \"server_port\": 10086,\
                \"websocket\": {\
                    \"path\": \"/path\",\
                    \"hostname\": \"v2ray.example.com\"\
                },\
                \"password\": \"61455aba-a200-4b46-8dad-8478e1065e0d\"\
            }\
        ],\
        \"local_address\": \"0.0.0.0\",\
        \"local_port\": 1080,\
        \"control_port\": 11080,\
        \"ping_interval\": 120,\
        \"timeout\": 60,\
        \"log_file\": \"log_file\",\
        \"log_level\": 1\
    }";
	pgs_config_t *config = pgs_config_parse((const char *)json);
	assert(config != NULL);
	PGS_STREUQAL(config->local_address, "0.0.0.0");
	assert(config->log_file != NULL);
	assert(config->log_file != stderr);
	assert(config->local_port == 1080);
	assert(config->control_port == 11080);
	assert(config->ping_interval == 120);
	assert(config->timeout == 60);
	assert(config->log_level == 1);

	pgs_server_config_t *server = &config->servers[0];
	assert(server != NULL);
	PGS_STREUQAL(server->server_address, "v2ray.example.com");
	PGS_STREUQAL(server->server_type, "v2ray");
	PGS_STRNEUQAL((const char *)server->password, "password");
	assert(server->password != NULL);
	assert(server->server_port == 10086);

	assert(server->extra != NULL);
	pgs_config_extra_v2ray_t *vconf =
		(pgs_config_extra_v2ray_t *)server->extra;
	assert(vconf->websocket.enabled == true);
	PGS_STREUQAL(vconf->websocket.path, "/path");
	PGS_STREUQAL(vconf->websocket.hostname, "v2ray.example.com");

	pgs_config_free(config);
}

void test_v2ray_wss_config()
{
	static const char json[] = "{\
        \"servers\": [\
            {\
                \"server_address\": \"v2ray.example.com\",\
                \"server_type\": \"v2ray\",\
                \"server_port\": 10086,\
                \"websocket\": {\
                    \"path\": \"/path\",\
                    \"hostname\": \"v2ray.example.com\"\
                },\
                \"ssl\": {\
                    \"sni\": \"v2ray.example.com\"\
                },\
                \"password\": \"61455aba-a200-4b46-8dad-8478e1065e0d\"\
            }\
        ],\
        \"local_address\": \"0.0.0.0\",\
        \"local_port\": 1080,\
        \"control_port\": 11080,\
        \"ping_interval\": 120,\
        \"timeout\": 60,\
        \"log_file\": \"log_file\",\
        \"log_level\": 1\
    }";
	pgs_config_t *config = pgs_config_parse((const char *)json);
	assert(config != NULL);
	PGS_STREUQAL(config->local_address, "0.0.0.0");
	assert(config->log_file != NULL);
	assert(config->log_file != stderr);
	assert(config->local_port == 1080);
	assert(config->control_port == 11080);
	assert(config->ping_interval == 120);
	assert(config->timeout == 60);
	assert(config->log_level == 1);

	pgs_server_config_t *server = &config->servers[0];
	assert(server != NULL);
	PGS_STREUQAL(server->server_address, "v2ray.example.com");
	PGS_STREUQAL(server->server_type, "v2ray");
	PGS_STRNEUQAL((const char *)server->password, "password");
	assert(server->password != NULL);
	assert(server->server_port == 10086);

	assert(server->extra != NULL);
	pgs_config_extra_v2ray_t *vconf =
		(pgs_config_extra_v2ray_t *)server->extra;
	assert(vconf->websocket.enabled == true);
	PGS_STREUQAL(vconf->websocket.path, "/path");
	PGS_STREUQAL(vconf->websocket.hostname, "v2ray.example.com");
	assert(vconf->ssl.enabled == true);
	PGS_STREUQAL(vconf->ssl.sni, "v2ray.example.com");

	pgs_config_free(config);
}

void test_shadowsocks_config()
{
	static const char json[] = "{\
        \"servers\": [\
            {\
                \"server_address\": \"ss.example.com\",\
                \"server_type\": \"shadowsocks\",\
                \"server_port\": 10086,\
                \"method\": \"chacha20-ietf-poly1305\",\
                \"plugin\": \"obfs-local\",\
                \"plugin_opts\": \"obfs=http;obfs-host=www.baidu.com\",\
                \"password\": \"password\"\
            }\
        ],\
        \"local_address\": \"0.0.0.0\",\
        \"local_port\": 1080,\
        \"control_port\": 11080,\
        \"ping_interval\": 120,\
        \"timeout\": 60,\
        \"log_file\": \"log_file\",\
        \"log_level\": 1\
    }";
	pgs_config_t *config = pgs_config_parse((const char *)json);
	assert(config != NULL);
	PGS_STREUQAL(config->local_address, "0.0.0.0");
	assert(config->log_file != NULL);
	assert(config->log_file != stderr);
	assert(config->local_port == 1080);
	assert(config->control_port == 11080);
	assert(config->ping_interval == 120);
	assert(config->timeout == 60);
	assert(config->log_level == 1);

	pgs_server_config_t *server = &config->servers[0];
	assert(server != NULL);
	PGS_STREUQAL(server->server_address, "ss.example.com");
	PGS_STREUQAL(server->server_type, "shadowsocks");
	PGS_STREUQAL((const char *)server->password, "password");
	assert(server->password != NULL);
	assert(server->server_port == 10086);

	pgs_config_extra_ss_t *ss_config = server->extra;
	assert(ss_config->method == AEAD_CHACHA20_POLY1305);
	PGS_STREUQAL(ss_config->plugin, "obfs-local");
	PGS_STREUQAL(ss_config->plugin_opts,
		     "obfs=http;obfs-host=www.baidu.com");

	pgs_config_free(config);
}

int main()
{
	test_base_config();
	printf("test_base_config passed\n");

	test_trojan_gfw_config();
	printf("test_trojan_gfw_config passed\n");
	test_trojan_ws_config();
	printf("test_trojan_ws_config passed\n");

	test_v2ray_tcp_config();
	printf("test_v2ray_tcp_config passed\n");
	test_v2ray_tcp_ssl_config();
	printf("test_v2ray_tcp_ssl_config passed\n");
	test_v2ray_ws_config();
	printf("test_v2ray_ws_config passed\n");
	test_v2ray_wss_config();
	printf("test_v2ray_wss_config passed\n");
	test_shadowsocks_config();
	printf("test_shadowsocks_config passed\n");
	return 0;
}
