#ifndef _CRM_EV
#define _CRM_EV

#include <event2/listener.h> // listener type
#include <event2/bufferevent.h>
#include <event2/buffer.h>

typedef struct evconnlistener crm_listener_t;
typedef struct event_base crm_ev_base_t;

#endif
