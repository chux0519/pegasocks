#ifndef _CRM_EV
#define _CRM_EV

#include <event2/listener.h> // listener type
#include <event2/bufferevent.h>
#include <event2/buffer.h>

typedef struct evconnlistener crm_listener_t;
typedef struct event_base crm_ev_base_t;
typedef struct bufferevent crm_bev_t;

#define crm_bev_socket_new bufferevent_socket_new
#define crm_bev_free bufferevent_free

#define ngx_memcpy(dst, src, n) (void)memcpy(dst, src, n)

#endif
