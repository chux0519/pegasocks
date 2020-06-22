#ifndef _CRM_EV
#define _CRM_EV

#include <event2/listener.h> // listener type
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/dns.h>
#include <event2/bufferevent_ssl.h>

typedef struct evconnlistener crm_listener_t;
typedef struct event_base crm_ev_base_t;
typedef struct evdns_base crm_ev_dns_base_t;
typedef struct bufferevent crm_bev_t;

#define crm_listener_new evconnlistener_new
#define crm_listener_free evconnlistener_free
#define crm_ev_base_new event_base_new
#define crm_ev_base_free event_base_free
#define crm_ev_dns_base_new evdns_base_new
#define crm_ev_dns_base_free evdns_base_free
#define crm_bev_socket_new bufferevent_socket_new
#define crm_bev_socket_free bufferevent_socket_free
#define crm_bev_new bufferevent_new
#define crm_bev_free bufferevent_free
#define crm_bev_get_output bufferevent_get_output
#define crm_bev_get_input bufferevent_get_input
#define crm_bev_setcb bufferevent_setcb
#define crm_bev_enable bufferevent_enable
#define CRM_EVUTIL_SOCKET_ERROR EVUTIL_SOCKET_ERROR
#define crm_evutil_socket_error_to_string evutil_socket_error_to_string
#define crm_ev_base_loopexit event_base_loopexit
#define crm_listener_set_error_cb evconnlistener_set_error_cb
#define crm_ev_base_dispatch event_base_dispatch

#endif
