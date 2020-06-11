#include <event2/event.h>
#include <stdio.h>

#ifdef WIN32
int evthread_use_windows_threads(void);
#define EVTHREAD_USE_WINDOWS_THREADS_IMPLEMENTED
#endif
#ifdef _EVENT_HAVE_PTHREADS
int evthread_use_pthreads(void);
#define EVTHREAD_USE_PTHREADS_IMPLEMENTED
#endif

static void ignore_cb(int severity, const char *msg)
{
}

static FILE *logfile = NULL;
static void write_to_file_cb(int severity, const char *msg)
{
	const char *s;
	if (!logfile)
		return;
	switch (severity) {
	case _EVENT_LOG_DEBUG:
		s = "debug";
		break;
	case _EVENT_LOG_MSG:
		s = "msg";
		break;
	case _EVENT_LOG_WARN:
		s = "warn";
		break;
	case _EVENT_LOG_ERR:
		s = "error";
		break;
	default:
		s = "?";
		break; // never reached
	}
	fprintf(logfile, "[%s] %s\n", s, msg);
}

void suppress_logging(void)
{
	event_set_log_callback(ignore_cb);
}

void set_log_file(FILE *f)
{
	logfile = f;
	event_set_log_callback(write_to_file_cb);
}

int main()
{
	struct event_base *base = event_base_new();

	const char **methods = event_get_supported_methods();
	printf("Starting libevent %s, methods: \n", event_get_version());
	for (int i = 0; methods[i] != NULL; i++) {
		printf("\t%s\n", methods[i]);
	}

	event_base_free(base);
	return 0;
}
