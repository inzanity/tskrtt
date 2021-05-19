#define _POSIX_C_SOURCE 200809L

#include <netinet/in.h>
#include <sys/socket.h>

#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <netdb.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <ev.h>

#ifdef USE_TLS
#include <tls.h>
#endif

#include "arg.h"
#include "client.h"
#include "common.h"

char dfl_hostname[128];
const char dfl_port[] = "70";
const char dfl_gopherroot[] = "/var/gopher";

const char *hostname = dfl_hostname;
const char *gopherroot = dfl_gopherroot;
const char *oport = NULL;

char *argv0;
int logfd = -1;

struct listener {
	ev_io watcher;
	int fd;
#ifdef USE_TLS
	struct tls *tlsctx;
#endif
};

struct listener listen_watcher;
ev_timer timeout_watcher;

static void logprintf(const char *fmt, ...)
{
	va_list args;

	if (logfd < 0)
		return;

	va_start(args, fmt);
	vdprintf(logfd, fmt, args);
	va_end(args);
}

void accesslog(struct client *c, const char *resource, const char *qs, const char *ss)
{
	char tbuf[64] = "";
	char abuf[INET6_ADDRSTRLEN];

	if (logfd < 0)
		return;

	getnameinfo((struct sockaddr *)&c->addr, c->addrlen, abuf, sizeof(abuf), NULL, 0, NI_NUMERICHOST);
	strftime(tbuf, sizeof(tbuf), "%d/%b/%Y:%H:%M:%S %z", localtime(&(time_t){ time(NULL) }));

	logprintf("%s - - [%s] \"%s\" \"%s\" \"%s\"\n",
	    abuf, tbuf, resource, qs ? qs : "", ss ? ss : "");
}

char *cleanup_path(char *path, char **basename, size_t *pathlen)
{
	size_t parts[512];
	size_t np = 0;
	size_t w = 0;
	size_t r = 0;

	while (path[r] == '/' && r < *pathlen)
		r++;

	if (r == *pathlen) {
		*pathlen = 0;
		if (basename)
			*basename = path;
		return path;
	}

	while (r < *pathlen) {
		if (!path[r])
			return NULL;
		if (path[r] == '/') {
			if (w)
				path[w++] = '/';
			do {
				r++;
			} while (path[r] == '/');
			continue;
		} else if (path[r] == '.') {
			if (r + 1 == *pathlen || path[r + 1] == '/') {
				for (r++; r < *pathlen && path[r] == '/'; r++);
				continue;
			} else if (path[r + 1] == '.') {
				if (r + 2 == *pathlen || path[r + 2] == '/') {
					if (!np)
						return NULL;
					w = parts[--np];
					if (r + 2 == *pathlen && w)
						w--;
					for (r += 2; r < *pathlen && path[r] == '/'; r++);
					continue;
				}
			}
		}
		parts[np++] = w;
		while (r < *pathlen && path[r] && path[r] != '/')
			path[w++] = path[r++];
	}

	if (basename) {
		if (np)
			*basename = path + parts[np - 1];
		else
			*basename = path;
	}

	if (w && path[w - 1] == '/')
		w--;
	*pathlen = w;
	return path;
}

static void listen_cb(EV_P_ ev_io *w, int revents)
{
	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof(addr);
	struct listener *l = (struct listener *)w;
	int fd;
	struct client *c;

	(void)revents;

	fd = accept(l->fd, (struct sockaddr *)&addr, &addrlen);

	if (fd < 0)
		return;

	c = client_new(EV_A_ fd, (struct sockaddr *)&addr, addrlen
#ifdef USE_TLS
			, listen_watcher.tlsctx
#endif
			);
	if (!c) {
		close(fd);
		return;
	}
}

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-46d] "
#ifdef USE_TLS
		"[-t key cert] "
#endif
		"[-l logfile] [-b rootdir] [-p port] [-o outport] "
		"[-u user] [-g group] [-h host] [-i listen address]\n",
		argv0);
	exit(1);
}

static void croak(const char *s)
{
	perror(s);
	exit(1);
}

int main (int argc, char *argv[])
{
#ifdef USE_TLS
	struct tls_config *tlscfg;
	const char *keyfile = NULL;
	const char *certfile = NULL;
#endif
	char gopherrootbuf[PATH_MAX];
	struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_flags = AI_PASSIVE, .ai_socktype = SOCK_STREAM };
	struct addrinfo *addrs;
	struct addrinfo *ai;
#if EV_MULTIPLICITY
	EV_P = EV_DEFAULT;
#endif
	const char *bindto = NULL;
	const char *port = dfl_port;
	const char *user = NULL;
	const char *group = NULL;
	const char *logfile = NULL;
	int lfd = -1;
	bool dofork = true;

	signal(SIGPIPE, SIG_IGN);

	ARGBEGIN {
		case '4':
			hints.ai_family = AF_INET;
			break;
		case '6':
			hints.ai_family = AF_INET6;
			break;
		case 'd':
			dofork = false;
			break;
#ifdef USE_TLS
		case 't':
			keyfile = EARGF(usage());
			certfile = EARGF(usage());
			break;
#endif
		case 'h':
			hostname = EARGF(usage());
			break;
		case 'i':
			bindto = EARGF(usage());
			break;
		case 'b':
			gopherroot = EARGF(usage());
			break;
		case 'p':
			port = EARGF(usage());
			break;
		case 'P':
			oport = EARGF(usage());
			break;
		case 'u':
			user = EARGF(usage());
			break;
		case 'g':
			group = EARGF(usage());
			break;
		case 'l':
			logfile = EARGF(usage());
			break;
		default:
			usage();
			break;
	} ARGEND;

	if (!oport)
		oport = port;

	if (hostname == dfl_hostname) {
		if (bindto)
			hostname = bindto;
		else
			gethostname(dfl_hostname, sizeof(dfl_hostname));
	}

	if (getaddrinfo(bindto, port, &hints, &addrs))
		croak("Resolving bind address failed");

	for (ai = addrs; ai; ai = ai->ai_next) {
		lfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

		if (lfd < 0)
			continue;

		setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

		if (!bind(lfd, ai->ai_addr, ai->ai_addrlen))
			break;

		close(lfd);
	}

	if (logfile && (logfd = open(logfile, O_WRONLY | O_APPEND | O_CREAT, 0644)) < 0)
		croak("Log opening failed");

	if (!ai)
		croak("Bind failed");

	freeaddrinfo(addrs);

	if (listen(lfd, 10))
		croak("Listen failed");

#ifdef USE_TLS
	if (keyfile && certfile) {
		tls_init();
		listen_watcher.tlsctx = tls_server();
		if (!(tlscfg = tls_config_new()) ||
		    tls_config_set_key_file(tlscfg, keyfile) ||
		    tls_config_set_cert_file(tlscfg, certfile) ||
		    tls_configure(listen_watcher.tlsctx, tlscfg))
			croak("TLS configuration error");
		tls_config_free(tlscfg);
	} else
		listen_watcher.tlsctx = NULL;
#endif

	if (group) {
		struct group *g = getgrnam(group);
		if (!g)
			croak("No such group");
		if (setgid(g->gr_gid))
			croak("setgid failed");
	}

	if (user) {
		struct passwd *u = getpwnam(user);
		if (!u)
			croak("No such user");
		if (setuid(u->pw_uid))
			croak("setuid failed");
	}

	if (*gopherroot != '/' && getcwd(gopherrootbuf, sizeof(gopherrootbuf))) {
		size_t l = strlen(gopherrootbuf);
		int ll = snprintf(gopherrootbuf + l, sizeof(gopherrootbuf) - l, "/%s", gopherroot);
		if ((l += ll - 1) < sizeof(gopherrootbuf) - 1 && cleanup_path(gopherrootbuf + 1, NULL, &l)) {
			gopherrootbuf[l + 1] = '\0';
			gopherroot = gopherrootbuf;
		}
	}

	if (dofork) {
		if (fork()) {
			close(lfd);
			return 0;
		}
		setsid();
		if (fork()) {
			close(lfd);
			return 0;
		}
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
	}

	listen_watcher.fd = lfd;
	ev_io_init(&listen_watcher.watcher, listen_cb, lfd, EV_READ);
	ev_io_start(EV_A_ &listen_watcher.watcher);

	ev_run(EV_A_ 0);

#ifdef USE_TLS
	if (listen_watcher.tlsctx)
		tls_close(listen_watcher.tlsctx);
#endif
	close(listen_watcher.fd);

	return 0;
}
