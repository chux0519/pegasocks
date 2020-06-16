#include <json-c/json.h>
#include <stdio.h>

int main()
{
	char *string =
		"{\"servers\":[{\"server_address\":\"hexyoungs.club\",\"server_type\":\"trojan\",\"server_port\":443,\"password\":\"ysyhl9t\",\"ssl\":{\"cert\":\"cert.pem\"},\"websocket\":{\"enabled\":true,\"path\":\"/trojan\",\"hostname\":\"hexyoungs.club\",\"double_tls\":false}}],\"local_address\":\"0.0.0.0\",\"local_port\":2088,\"timeout\":60,\"log_level\":1}";
	json_object *jobj = json_tokener_parse(string);
	enum json_type type;
	json_object_object_foreach(jobj, key, val)
	{
		printf("%s type: ", key);
		type = json_object_get_type(val);
		switch (type) {
		case json_type_null:
			printf("json_type_null\n");
			break;
		case json_type_boolean:
			printf("json_type_boolean\n");
			break;
		case json_type_double:
			printf("json_type_double\n");
			break;
		case json_type_int:
			printf("json_type_int\n");
			break;
		case json_type_object:
			printf("json_type_object\n");
			break;
		case json_type_array:
			printf("json_type_array\n");
			break;
		case json_type_string:
			printf("json_type_string\n");
			const char *s = json_object_get_string(val);
			printf("value: %s\n", s);
			break;
		}
	}
}
