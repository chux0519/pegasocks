#ifndef _PGS_EV
#define _PGS_EV

#include <event2/listener.h> // listener type
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/dns.h>
#include <event2/bufferevent_ssl.h>

typedef struct evconnlistener pgs_listener_t;
typedef struct event_base pgs_ev_base_t;
typedef struct evdns_base pgs_ev_dns_base_t;
typedef struct bufferevent pgs_bev_t;
typedef struct evbuffer pgs_evbuffer_t;
typedef struct event pgs_event_t;

#define pgs_evtimer_new evtimer_new
#define pgs_evtimer_add evtimer_add
#define pgs_evtimer_del evtimer_del
#define pgs_listener_new evconnlistener_new
#define pgs_listener_free evconnlistener_free
#define pgs_ev_base_new event_base_new
#define pgs_ev_base_free event_base_free
#define pgs_ev_dns_base_new evdns_base_new
#define pgs_ev_dns_base_free evdns_base_free
#define pgs_bev_socket_new bufferevent_socket_new
#define pgs_bev_socket_free bufferevent_socket_free
#define pgs_bev_socket_connect_hostname bufferevent_socket_connect_hostname
#define pgs_bev_openssl_socket_new bufferevent_openssl_socket_new
#define pgs_bev_openssl_get_ssl bufferevent_openssl_get_ssl
#define pgs_bev_openssl_set_allow_dirty_shutdown                               \
	bufferevent_openssl_set_allow_dirty_shutdown
#define pgs_bev_new bufferevent_new
#define pgs_bev_free bufferevent_free
#define pgs_bev_enable bufferevent_enable
#define pgs_bev_get_output bufferevent_get_output
#define pgs_bev_get_input bufferevent_get_input
#define pgs_bev_setcb bufferevent_setcb
#define pgs_bev_enable bufferevent_enable
#define PGS_EVUTIL_SOCKET_ERROR EVUTIL_SOCKET_ERROR
#define pgs_evutil_socket_error_to_string evutil_socket_error_to_string
#define pgs_ev_base_loopexit event_base_loopexit
#define pgs_listener_set_error_cb evconnlistener_set_error_cb
#define pgs_ev_base_dispatch event_base_dispatch
#define pgs_evbuffer_get_length evbuffer_get_length
#define pgs_evbuffer_pullup evbuffer_pullup
#define pgs_evbuffer_expand evbuffer_expand
#define pgs_evbuffer_add evbuffer_add
#define pgs_evbuffer_add_printf evbuffer_add_printf
#define pgs_evbuffer_drain evbuffer_drain
#define pgs_evbuffer_remove evbuffer_remove
#define pgs_evbuffer_new evbuffer_new
#define pgs_evbuffer_free evbuffer_free

#endif
