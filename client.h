#ifndef CLIENT_H
#define CLIENT_H

#include <sys/socket.h>

#include <netinet/in.h>
#include <stdbool.h>

#include <ev.h>

#include "task.h"

#ifdef USE_TLS
enum tls_state {
	UNKNOWN,
	PLAIN,
	HANDSHAKE,
	READY
};
#endif

struct client {
	bool broken_client;
	ev_io watcher;
	ev_timer timeout;
	struct sockaddr_storage addr;
	socklen_t addrlen;
	int fd;
	char buffer[2048];
	size_t buffer_used;
	enum task task;
	union {
		struct dir_task dt;
		struct txt_task tt;
		struct gph_task gpht;
		struct binary_task bt;
		struct cgi_task ct;
		struct dcgi_task dct;
	} task_data;
#ifdef USE_TLS
	struct tls *tlsctx;
	enum tls_state tlsstate;
#endif
};

struct client *client_new(EV_P_ int fd, struct sockaddr *addr, socklen_t addrlen
#ifdef USE_TLS
		, struct tls *tlsctx
#endif
		);
bool client_printf(struct client *c, const char *fmt, ...);
void client_close(EV_P_ struct client *c);
void client_error(EV_P_ struct client *c, const char *fmt, ...);
bool client_eos(struct client *c);
int client_write(struct client *c, void *buffer, size_t n);
bool client_flush(struct client *c);

#endif
