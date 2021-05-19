#define _POSIX_C_SOURCE 200809L

#include <sys/socket.h>

#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ev.h>
#include <tls.h>

#include "client.h"
#include "common.h"
#include "task.h"

static void child_cb(EV_P_ ev_io *w, int revents)
{
	struct client *c = PTR_FROM_FIELD(struct client, watcher, w);

	if (c->task > TASK_READ) {
		if (!client_flush(c)) {
			client_close(EV_A_ c);
			return;
		}

		if (c->buffer_used)
			return;
	}

	tasks[c->task].update(EV_A_ c, revents);
}

static void child_timeout(EV_P_ ev_timer *w, int revents)
{
	struct client *c = PTR_FROM_FIELD(struct client, timeout, w);

	(void)revents;

	client_close(EV_A_ c);
}

struct client *client_new(EV_P_ int fd, struct sockaddr *addr, socklen_t addrlen
#ifdef USE_TLS
		, struct tls *tlsctx
#endif
		)
{
	struct client *c = malloc(sizeof(*c));

	if (!c)
		return NULL;

	c->fd = fd;
	memcpy(&c->addr, addr, (c->addrlen = addrlen));

	fcntl(c->fd, F_SETFL, O_NONBLOCK);
	fcntl(c->fd, F_SETFD, FD_CLOEXEC);

	c->buffer_used = 0;
	c->task = TASK_READ;
#ifdef USE_TLS
	c->tlsstate = UNKNOWN;
	c->tlsctx = tlsctx;
#endif

	ev_timer_init(&c->timeout, child_timeout, 60.0, 0);
	ev_timer_start(EV_A_ &c->timeout);

	ev_io_init(&c->watcher, child_cb, c->fd, EV_READ);
	ev_io_start(EV_A_ &c->watcher);

	return c;
}

bool client_printf(struct client *c, const char *fmt, ...)
{
	int n = 0;
	va_list args;

	if (c->broken_client) {
		n += snprintf(c->buffer + c->buffer_used, sizeof(c->buffer) - c->buffer_used, "+INFO: ");
		if (c->buffer_used + n >= sizeof(c->buffer))
			return false;
	}

	va_start(args, fmt);
	n += vsnprintf(c->buffer + c->buffer_used + n, sizeof(c->buffer) - c->buffer_used - n, fmt, args);
	va_end(args);

	if (n < 0 || n + c->buffer_used >= sizeof(c->buffer))
		return false;

	c->buffer_used += n;
	return true;
}

void client_error(EV_P_ struct client *c, const char *fmt, ...)
{
	va_list args;
	int n;

	if (tasks[c->task].finish)
		tasks[c->task].finish(EV_A_ c);
	c->task = TASK_ERROR;

	client_printf(c, "3");

	va_start(args, fmt);
	n = vsnprintf(c->buffer + c->buffer_used, sizeof(c->buffer) - c->buffer_used, fmt, args);
	va_end(args);

	if (c->buffer_used + n >= sizeof(c->buffer))
		return;

	c->buffer_used += n;
	c->buffer_used += snprintf(c->buffer + c->buffer_used, sizeof(c->buffer) - c->buffer_used, "\t.\t.\t.\r\n.\r\n");
}

bool client_eos(struct client *c)
{
	const char eos[] = ".\r\n";

	if (c->buffer_used + sizeof(eos) - 1 > sizeof(c->buffer))
		return false;

	memcpy(c->buffer + c->buffer_used, eos, sizeof(eos) - 1);
	c->buffer_used += sizeof(eos) - 1;
	return true;
}

int client_write(struct client *c, void *buffer, size_t n)
{
#ifdef USE_TLS
		if (c->tlsstate == READY)
			return tls_write(c->tlsctx, buffer, n);
#endif
		return write(c->fd, buffer, n);
}

bool client_flush(struct client *c)
{
	int w;

	if (!c->buffer_used)
		return true;

	w = client_write(c, c->buffer, c->buffer_used);

	if (w <= 0)
		return false;

	if ((size_t)w < c->buffer_used) {
		memmove(c->buffer, c->buffer + w, c->buffer_used - w);
		c->buffer_used -= w;
	} else {
		c->buffer_used = 0;
	}

	return true;
}

void client_close(EV_P_ struct client *c)
{
	tasks[c->task].finish(EV_A_ c);
#ifdef USE_TLS
	if (c->tlsstate > PLAIN)
		tls_close(c->tlsctx);
#endif
	ev_timer_stop(EV_A_ &c->timeout);
	ev_io_stop(EV_A_ &c->watcher);
	close(c->fd);
	free(c);
}
