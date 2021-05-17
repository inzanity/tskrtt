#define _POSIX_C_SOURCE 200809L
#include <ev.h>
#ifndef ev_io_modify
#define ev_io_modify(ev,events_)             do { (ev)->events = (ev)->events & EV__IOFDSET | (events_); } while (0)
#endif
#include <sys/socket.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <netdb.h>
#include <netdb.h>
#include <stdlib.h>
#include <stddef.h>
#include <dirent.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <time.h>
#ifdef USE_TLS
#include <tls.h>
#endif

#include "arg.h"

char dfl_hostname[128];
const char dfl_port[] = "70";
const char dfl_gopherroot[] = "/var/gopher";

const char *hostname = dfl_hostname;
const char *gopherroot = dfl_gopherroot;
const char *oport = NULL;

char *argv0;
int logfd = -1;

#define FOFFSET(x, y) (ptrdiff_t)(&((x *)NULL)->y)
#define PTR_FROM_FIELD(x, y, z) ((x *)((size_t)z - FOFFSET(x, y)))

enum task {
	TASK_READ,
	TASK_DIR,
	TASK_TXT,
	TASK_GOPHERMAP,
	TASK_GPH,
	TASK_BINARY,
	TASK_ERROR,
	TASK_REDIRECT,
	TASK_CGI,
	TASK_DCGI,
};

struct dir_task {
	struct dirent **entries;
	char *base;
	int n;
	int i;
	int dfd;
};

struct txt_task {
	char linebuf[512];
	int rfd;
	size_t used;
};

struct gph_task {
	char linebuf[512];
	size_t used;
	char *base;
	int rfd;
};

struct binary_task {
	int rfd;
};

struct cgi_task {
	ev_io input_watcher;
	ev_child child_watcher;
	pid_t pid;
	int rfd;
};

struct dcgi_task {
	struct gph_task gpht;
	struct cgi_task ct;
};

struct listener {
	ev_io watcher;
	int fd;
#ifdef USE_TLS
	struct tls *tlsctx;
#endif
};

#ifdef USE_TLS
enum tls_state {
	UNKNOWN,
	PLAIN,
	HANDSHAKE,
	READY
};
#endif

struct client {
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

static void read_dcgi(EV_P_ ev_io *w, int revents);

static void init_dir(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *qs, const char *ss);
static void init_text(EV_P_ struct client *, int fd, struct stat *sb, const char *path, const char *fn, const char *qs, const char *ss);
static void init_gph(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *qs, const char *ss);
static void init_gophermap(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *qs, const char *ss);
static void init_binary(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *qs, const char *ss);
static void init_error(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *qs, const char *ss);
static void init_redirect(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *qs, const char *ss);
static void init_cgi(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *qs, const char *ss);
static void init_dcgi(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *qs, const char *ss);

static void update_read(EV_P_ struct client *c, int events);
static void update_dir(EV_P_ struct client *c, int events);
static void update_text(EV_P_ struct client *c, int events);
static void update_gophermap(EV_P_ struct client *c, int events);
static void update_gph(EV_P_ struct client *c, int events);
static void update_binary(EV_P_ struct client *c, int events);
static void update_error(EV_P_ struct client *c, int events);
static void update_redirect(EV_P_ struct client *c, int events);
static void update_cgi(EV_P_ struct client *c, int events);
static void update_dcgi(EV_P_ struct client *c, int events);

static void finish_read(EV_P_ struct client *c);
static void finish_dir(EV_P_ struct client *c);
static void finish_text(EV_P_ struct client *c);
static void finish_gophermap(EV_P_ struct client *c);
static void finish_gph(EV_P_ struct client *c);
static void finish_binary(EV_P_ struct client *c);
static void finish_error(EV_P_ struct client *c);
static void finish_redirect(EV_P_ struct client *c);
static void finish_cgi(EV_P_ struct client *c);
static void finish_dcgi(EV_P_ struct client *c);

static const struct {
	void (*init)(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *qs, const char *ss);
	void (*update)(EV_P_ struct client *c, int events);
	void (*finish)(EV_P_ struct client *c);
} tasks[] = {
	{ NULL, update_read, finish_read },
	{ init_dir, update_dir, finish_dir },
	{ init_text, update_text, finish_text },
	{ init_gophermap, update_gophermap, finish_gophermap },
	{ init_gph, update_gph, finish_gph },
	{ init_binary, update_binary, finish_binary },
	{ init_error, update_error, finish_error },
	{ init_redirect, update_redirect, finish_redirect },
	{ init_cgi, update_cgi, finish_cgi },
	{ init_dcgi, update_dcgi, finish_dcgi },
};

struct listener listen_watcher;
ev_timer timeout_watcher;

static bool strsfx_(const char *haystack, const char *needle, size_t needlelen)
{
	size_t hsl = strlen(haystack);

	if (hsl < needlelen)
		return false;
	return !strncmp(haystack + hsl - needlelen, needle, needlelen);
}
#define strsfx(x, y) strsfx_(x, y, sizeof(y) - 1)

static char *strnpfx_(const char *haystack, size_t hsl, const char *needle, size_t needlelen)
{
	if (hsl >= needlelen && !strncmp(haystack, needle, needlelen))
		return (char *)haystack + needlelen;
	return NULL;
}
#define strnpfx(x, y, z) strnpfx_(x, y, z, sizeof(z) - 1)

bool strpfx(const char *haystack, const char *needle)
{
	while (*needle && *haystack++ == *needle++);
	return !*needle;
}

static inline void *xmemdup(const void *p, size_t l)
{
	return memcpy(malloc(l), p, l);
}

static int filterdot(const struct dirent *e)
{
	return strcmp(e->d_name, ".") && strcmp(e->d_name, "..");
}

static int xfdscandir(int dfd, struct dirent ***namelist, int (*filter)(const struct dirent *), int compar(const struct dirent **, const struct dirent **))
{
	size_t n = 0;
	size_t sz = 64;
	DIR *d;
	struct dirent *e;

	d = fdopendir(dfd);
	if (!d)
		return 0;

	*namelist = malloc(sz * sizeof(**namelist));

	while ((e = readdir(d))) {
		size_t nl = strlen(e->d_name);
		if (filter && !filter(e))
			continue;
		if (n == sz)
			*namelist = realloc(*namelist, (sz *= 2) * sizeof(**namelist));
		(*namelist)[n++] = xmemdup(e, FOFFSET(struct dirent, d_name) + nl + 1);
	}
	closedir(d);

	*namelist = realloc(*namelist, n * sizeof(**namelist));
	qsort(*namelist, n, sizeof(**namelist), (int (*)(const void *, const void *))compar);

	return n;
}

static char *dupensurepath(const char *w)
{
	size_t l = strlen(w);
	char *rv;

	if (!l)
		return strdup("");
	if (w[l - 1] == '/')
		l--;
	rv = memcpy(malloc(l + 2), w, l);
	rv[l++] = '/';
	rv[l] = '\0';
	return rv;
}

static char *dupdirname(const char *w)
{
	char *rv;
	char *ls = strrchr(w, '/');

	if (!ls++)
		return strdup("");
	rv = memcpy(malloc(ls - w + 1), w, ls - w);
	rv[ls - w] = '\0';
	return rv;
}

static bool tryfileat(int *fd, const char *fn)
{
	int f = openat(*fd, fn, O_RDONLY);

	if (f < 0)
		return false;
	close(*fd);
	*fd = f;

	return true;
}

static char *joinstr(const char *a, const char *b, char separator)
{
	char *rv;
	if (!a || !*a)
		return strdup(b);
	if (!b)
		return strdup(a);
	rv = malloc(strlen(a) + strlen(b) + 2);
	sprintf(rv, "%s%c%s", a, separator, b);
	return rv;
}

void guess_task(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *qs, const char *ss)
{
	char *t = NULL;

	(void)qs;

	if (sb->st_mode & S_IFDIR) {
		if (tryfileat(&fd, "gophermap")) {
			c->task = TASK_GOPHERMAP;
			sb = NULL;
		} else if (tryfileat(&fd, "index.gph")) {
			path = t = joinstr(path, "index.gph", '/');
			c->task = TASK_GPH;
			sb = NULL;
		} else if (!faccessat(fd, "index.cgi", X_OK, 0)) {
			path = t = joinstr(path, "index.cgi", '/');
			c->task = TASK_CGI;
		} else if (!faccessat(fd, "index.dcgi", X_OK, 0)) {
			path = t = joinstr(path, "index.dcgi", '/');
			c->task = TASK_DCGI;
		} else {
			c->task = TASK_DIR;
		}
	} else if (!strcmp(fn, "gophermap")) {
		c->task = TASK_GOPHERMAP;
	} else if (strsfx(fn, ".gph")) {
		c->task = TASK_GPH;
	} else if (strsfx(fn, ".txt")) {
		c->task = TASK_TXT;
	} else {
		c->task = TASK_BINARY;
	}

	tasks[c->task].init(EV_A_ c, fd, sb, path, fn, qs, ss);

	if (t)
		free(t);
}

static void client_close(EV_P_ struct client *c)
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

static void logprintf(const char *fmt, ...)
{
	va_list args;

	if (logfd < 0)
		return;

	va_start(args, fmt);
	vdprintf(logfd, fmt, args);
	va_end(args);
}

static void accesslog(struct client *c, const char *resource, const char *qs, const char *ss)
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

static bool client_printf(struct client *c, const char *fmt, ...)
{
	int n;
	va_list args;
	va_start(args, fmt);
	n = vsnprintf(c->buffer + c->buffer_used, sizeof(c->buffer) - c->buffer_used, fmt, args);
	va_end(args);

	if (n < 0 || (size_t)n > sizeof(c->buffer) - c->buffer_used)
		return false;

	c->buffer_used += n;
	return true;
}

static int client_write(struct client *c, void *buffer, size_t n)
{
#ifdef USE_TLS
		if (c->tlsstate == READY)
			return tls_write(c->tlsctx, buffer, n);
#endif
		return write(c->fd, buffer, n);
}

static bool client_flush(struct client *c)
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


static char *cleanup_path(char *path, char **basename, size_t *pathlen)
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

static char guess_type(struct dirent *e, struct stat *s)
{
	if (s->st_mode & S_IFDIR)
		return '1';
	if (strsfx(e->d_name, ".txt"))
		return '0';
	if (strsfx(e->d_name, ".html") ||
	    strsfx(e->d_name, ".xhtml"))
		return 'h';
	if (strsfx(e->d_name, ".gif"))
		return 'g';
	if (strsfx(e->d_name, ".jpg") ||
	    strsfx(e->d_name, ".png") ||
	    strsfx(e->d_name, ".jpeg"))
		return 'I';

	return '9';
}

static void init_dir(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *qs, const char *ss)
{
	(void)sb;
	(void)qs;
	(void)ss;

	c->task_data.dt.base = dupensurepath(path);
	if (*path) {
		char b[fn - path];
		memcpy(b, path, fn - path);
		client_printf(c, "1..\t/%.*s\t%s\t%s\r\n", (int)(fn - path), b, hostname, oport);
	}
	c->task_data.dt.dfd = dup(fd);
	c->task_data.dt.n = xfdscandir(fd, &c->task_data.dt.entries, filterdot, alphasort);
	c->task_data.dt.i = 0;
}

static void init_text(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *qs, const char *ss)
{
	(void)sb;
	(void)path;
	(void)fn;
	(void)qs;
	(void)ss;
	c->task_data.tt.rfd = fd;
	c->task_data.tt.used = 0;
}

static void init_gophermap(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *qs, const char *ss)
{
	(void)sb;
	(void)path;
	(void)fn;
	(void)qs;
	(void)ss;
	c->task_data.tt.rfd = fd;
	c->task_data.tt.used = 0;
}

static void init_gph(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *qs, const char *ss)
{
	(void)sb;
	(void)fn;
	(void)qs;
	(void)ss;
	c->task_data.gpht.rfd = fd;
	c->task_data.gpht.base = dupdirname(path);
	c->task_data.gpht.used = 0;
}

static void init_binary(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *qs, const char *ss)
{
	int sbsz = 0;

	(void)path;
	(void)fn;
	(void)qs;
	(void)ss;

	getsockopt(c->fd, SOL_SOCKET, SO_SNDBUF, &sbsz, &(socklen_t){ sizeof(sbsz) });

	c->task_data.bt.rfd = fd;
	if (sb->st_size * 2 < sbsz) {
		void *data = mmap(NULL, sb->st_size, PROT_READ, MAP_PRIVATE, c->task_data.bt.rfd, 0);
		ssize_t wr = 0;
		int w;

		if (!data)
			return;

		while (wr < sb->st_size) {
			if ((w = client_write(c, data + wr, sb->st_size - wr)) <= 0)
				break;
			wr += w;
		}

		munmap(data, sb->st_size);

		client_close(EV_A_ c);
	}
}

static void init_error(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *qs, const char *ss)
{
	(void)c;
	(void)fd;
	(void)sb;
	(void)path;
	(void)fn;
	(void)qs;
	(void)ss;
}

static void init_redirect(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *qs, const char *ss)
{
	(void)fd;
	(void)sb;
	(void)path;
	(void)qs;
	(void)ss;

	size_t fnl = strlen(fn);
	char b[fnl + 1];
	strcpy(b, fn);
	c->buffer_used = sprintf(c->buffer,
				 "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">\r\n"
				 "<html>\r\n"
				 "	<head>\r\n"
				 "		<title>Redirect</title>\r\n"
				 "		<meta http-equiv=\"refresh\" content=\"0;url=%s\">\r\n"
				 "	</head>\r\n"
				 "	<body>\r\n"
				 "		<p>Redirecting to <a href=\"%s\">%s</a></p>\r\n"
				 "	</body>\r\n"
				 "</html>\r\n",
				 b, b, b);
}

static char *envstr(const char *key, const char *value)
{
	return joinstr(key, value ? value : "", '=');
}

static void read_cgi(EV_P_ ev_io *w, int revents)
{
	struct client *c = PTR_FROM_FIELD(struct client, task_data.ct.input_watcher, w);
	int r = read(c->task_data.ct.rfd, c->buffer + c->buffer_used, sizeof(c->buffer) - c->buffer_used);

	(void)revents;

	if (r <= 0) {
		close(c->task_data.ct.rfd);
		c->task_data.ct.rfd = -1;
		ev_io_start(EV_A_ &c->watcher);

		return;
	}

	c->buffer_used += r;

	if (c->buffer_used == sizeof(c->buffer))
		ev_io_stop(EV_A_ &c->task_data.ct.input_watcher);
	ev_io_start(EV_A_ &c->watcher);
}


static void reap_cgi(EV_P_ ev_child *w, int revent)
{
	struct cgi_task *ct = PTR_FROM_FIELD(struct cgi_task, input_watcher, w);

	(void)revent;

	ct->pid = 0;
}

static void init_cgi_common(EV_P_ struct client *c, struct cgi_task *ct, int fd, struct stat *sb, const char *path, const char *fn, const char *qs, const char *ss, void (*read_cb)(EV_P_ ev_io *w, int revents))
{
	int pfd[2];
	int nfd;
	size_t nenv = 0;
	char *env[20];
	char abuf[INET6_ADDRSTRLEN];
	char *file;

	(void)sb;
	(void)fn;

	if (pipe(pfd)) {
		client_close(EV_A_ c);
		return;
	}

	switch ((ct->pid = fork())) {
	case 0:
		break;
	case -1:
		close(pfd[0]);
		close(pfd[1]);
		client_close(EV_A_ c);
		return;
	default:
		close(fd);
		close(pfd[1]);
		ct->rfd = pfd[0];

		ev_io_init(&ct->input_watcher, read_cb, pfd[0], EV_READ);
		ev_child_init(&ct->child_watcher, reap_cgi, ct->pid, 0);
		ev_io_start(EV_A_ &ct->input_watcher);

		return;
	}

	close(pfd[0]);
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	nfd = open("/dev/null", O_RDONLY);
	if (nfd != STDIN_FILENO) {
		dup2(nfd, STDIN_FILENO);
		close(nfd);
	}

	dup2(pfd[1], STDOUT_FILENO);
	close(pfd[1]);

	nfd = open("/dev/null", O_WRONLY);
	if (nfd != STDERR_FILENO) {
		dup2(nfd, STDERR_FILENO);
		close(nfd);
	}

	file = joinstr(gopherroot, path, '/');
	fchdir(fd);
	close(fd);

	getnameinfo((struct sockaddr *)&c->addr, c->addrlen, abuf, sizeof(abuf), NULL, 0, NI_NUMERICHOST);
	env[nenv++] = envstr("GATEWAY_INTERFACE", "CGI/1.1");
	env[nenv++] = envstr("PATH_INFO", path);
	env[nenv++] = envstr("PATH_TRANSLATED", file);
	env[nenv++] = envstr("QUERY_STRING", qs);
	env[nenv++] = envstr("SELECTOR", qs);
	env[nenv++] = envstr("REQUEST", qs);
	env[nenv++] = envstr("REMOTE_ADDR", abuf);
	env[nenv++] = envstr("REMOTE_HOST", abuf);
	env[nenv++] = envstr("REDIRECT_STATUS", "");
	env[nenv++] = envstr("REQUEST_METHOD", "GET");
	env[nenv++] = envstr("SCRIPT_NAME", file);
	env[nenv++] = envstr("SERVER_NAME", hostname);
	env[nenv++] = envstr("SERVER_PORT", oport);
	env[nenv++] = envstr("SERVER_PROTOCOL", "gopher/1.0");
	env[nenv++] = envstr("X_GOPHER_SEARCH", ss);
	env[nenv++] = envstr("SEARCHREQUEST", ss);

#ifdef USE_TLS
	if (c->tlsstate == READY) {
		env[nenv++] = envstr("GOPHERS", "on");
		env[nenv++] = envstr("HTTPS", "on");
	}
#endif
	env[nenv++] = NULL;

	execle(file, file, ss ? ss : "", qs ? qs : "", hostname, oport, (char *)NULL, env);
	exit(1);
}

static void init_cgi(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *qs, const char *ss)
{
	init_cgi_common(EV_A_ c, &c->task_data.ct, fd, sb, path, fn, qs, ss, read_cgi);
}

static void init_dcgi(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *qs, const char *ss)
{
	init_cgi_common(EV_A_ c, &c->task_data.dct.ct, fd, sb, path, fn, qs, ss, read_dcgi);
	init_gph(EV_A_ c, -1, sb, path, fn, qs, ss);
}

static const char *format_size(off_t bytes)
{
	static char buf[64];
	const char *mult = "kMGTPEZY";
	if (bytes < 1024) {
		sprintf(buf, "%ju", (uintmax_t)bytes);
	}
	else {
		double b;
		for (b = bytes / 1024;
		     b >= 1024 && mult[1];
		     mult++)
			b /= 1024;
		snprintf(buf, sizeof(buf), "%.1f%c", b, *mult);
	}
	return buf;
}

static const char *format_time(time_t t)
{
	static char buf[64];
	strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M %Z", localtime(&t));
	return buf;
}

static void update_dir(EV_P_ struct client *c, int revents)
{
	(void)revents;

	if (c->task_data.dt.i == c->task_data.dt.n + 1) {
		client_close(EV_A_ c);
		return;
	}

	for (; c->task_data.dt.i < c->task_data.dt.n; c->task_data.dt.i++) {
		struct stat sb = { 0 };
		fstatat(c->task_data.dt.dfd, c->task_data.dt.entries[c->task_data.dt.i]->d_name, &sb, 0);
		if (!client_printf(c, "%c%-50.50s %6s %-21s\t/%s%s\t%s\t%s\r\n",
				   guess_type(c->task_data.dt.entries[c->task_data.dt.i], &sb),
				   c->task_data.dt.entries[c->task_data.dt.i]->d_name,
				   format_size(sb.st_size),
				   format_time(sb.st_mtim.tv_sec),
				   c->task_data.dt.base,
				   c->task_data.dt.entries[c->task_data.dt.i]->d_name,
				   hostname, oport)) {
			if (c->buffer_used)
				return;
			client_printf(c, "3Filename too long\r\n");
		}
		free(c->task_data.dt.entries[c->task_data.dt.i]);
	}

	if (client_printf(c, ".\r\n"))
		c->task_data.dt.i++;
}

static void update_binary(EV_P_ struct client *c, int revents)
{
	int r = read(c->task_data.bt.rfd, c->buffer + c->buffer_used, sizeof(c->buffer) - c->buffer_used);

	(void)revents;

	if (r <= 0)
		client_close(EV_A_ c);

	c->buffer_used += r;
}

static void update_error(EV_P_ struct client *c, int revents)
{
	(void)revents;
	client_close(EV_A_ c);
}

static void update_redirect(EV_P_ struct client *c, int revents)
{
	(void)revents;
	client_close(EV_A_ c);
}

static bool line_foreach(EV_P_ int fd, char *buffer, size_t buffer_size, size_t *buffer_used, bool (*line_cb)(EV_P_ struct client *c, char *line, size_t linelen), struct client *c)
{
	int r;
	char *nl;
	char *bp;

	if (*buffer_used < buffer_size) {
		r = read(fd, buffer + *buffer_used, buffer_size - *buffer_used);
		if (r <= 0) {
			if (*buffer_used)
				return !line_cb(EV_A_ c, buffer, *buffer_used);
			return false;
		}

		*buffer_used += r;
	}

	nl = memchr(buffer, '\n', *buffer_used);

	if (!nl) {
		if (*buffer_used == buffer_size && line_cb(EV_A_ c, buffer, buffer_size))
			*buffer_used = 0;
		return true;
	}

	bp = buffer;
	do {
		char *t = nl;
		if (t > bp && t[-1] == '\r')
			t--;

		if (!line_cb(EV_A_ c, bp, t - bp))
			break;

		bp = nl + 1;
	} while ((nl = memchr(bp, '\n', *buffer_used - (bp - buffer))));

	memmove(buffer, bp, *buffer_used - (bp - buffer));
	*buffer_used -= bp - buffer;

	return true;
}

static bool process_text_line(EV_P_ struct client *c, char *line, size_t linelen)
{
	if (linelen == 1 && *line == '.')
		return client_printf(c, "..\r\n");
	return client_printf(c, "%.*s\r\n", (int)linelen, line);
}

static void update_text(EV_P_ struct client *c, int revents)
{
	(void)revents;

	if (c->task_data.tt.rfd < 0) {
		client_close(EV_A_ c);
		return;
	}

	if (!line_foreach(EV_A_ c->task_data.tt.rfd, c->task_data.tt.linebuf, sizeof(c->task_data.tt.linebuf), &c->task_data.tt.used, process_text_line, c)) {
		if (!client_printf(c, ".\r\n"))
			return;

		close(c->task_data.tt.rfd);
		c->task_data.tt.rfd = -1;
	}
}

static size_t strnchrcnt(const char *haystack, char needle, size_t hsl)
{
	size_t n = 0;
	while (hsl--)
		n += *haystack++ == needle;
	return n;
}

static bool process_gophermap_line(EV_P_ struct client *c, char *line, size_t linelen)
{
	size_t tabcount = strnchrcnt(line, '\t', linelen);
	const char *tabstr = "\t.\t.\t.";
	if (*line == 'i' || *line == '3')
		return client_printf(c, "%.*s%s\r\n", (int)linelen, line, tabcount < 3 ? tabstr + 2 * tabcount : "");
	else if (tabcount > 2)
		return client_printf(c, "%.*s\r\n", (int)linelen, line);
	else if (tabcount > 1)
		return client_printf(c, "%.*s\t70\r\n", (int)linelen, line);
	else if (tabcount)
		return client_printf(c, "%.*s\t%s\t%s\r\n", (int)linelen, line, hostname, oport);
	return client_printf(c, "i%.*s\t.\t.\t.\r\n", (int)linelen, line);
}

static void update_gophermap(EV_P_ struct client *c, int revents)
{
	(void)revents;

	if (c->task_data.tt.rfd < 0) {
		client_close(EV_A_ c);
		return;
	}

	if (!line_foreach(EV_A_ c->task_data.tt.rfd, c->task_data.tt.linebuf, sizeof(c->task_data.tt.linebuf), &c->task_data.tt.used, process_gophermap_line, c)) {
		if (!client_printf(c, ".\r\n"))
			return;

		close(c->task_data.tt.rfd);
		c->task_data.tt.rfd = -1;
	}
}

static char *strunesctok(char *str, char *delim, char esc)
{
	static char *state = NULL;
	char *w;
	char *rv;

	if (str)
		state = str;
	if (!state)
		return NULL;

	rv = state;

	for (w = state; *state && !strchr(delim, *state);) {
		if (*state == esc && state[1] &&
		    (state[1] == esc ||
		    strchr(delim, state[1])))
			state++;
		*w++ = *state++;
	}

	if (!*state)
		state = NULL;
	else
		state++;

	*w = '\0';

	return rv;
}

static bool process_gph_line(EV_P_ struct client *c, char *line, size_t linelen)
{
	line[linelen] = '\0';

	if (*line != '[' || *line == 't') {
		if (*line == 't')
			line++;
		return client_printf(c, "i%s\t.\t.\t.\r\n", line);
	} else {
		const char *type = strunesctok(line + 1, "|", '\\');
		const char *desc = strunesctok(NULL, "|", '\\');
		const char *resource = strunesctok(NULL, "|", '\\');
		const char *server = strunesctok(NULL, "|", '\\');
		const char *port = strunesctok(NULL, "|", '\\');

		if (line[linelen - 1] == ']')
			line[--linelen] = '\0';

		if (!*type)
			type = "i";
		if (*type == 'i' || *type == '3') {
			if (!resource)
				resource = ".";
			if (!server)
				server = ".";
			if (!port)
				port = ".";
		}

		if (!resource)
			return client_printf(c, "3Invalid line\r\n");

		if (!server || !*server || !strcmp(server, "server"))
			server = hostname;
		else if (!port || !*port)
			port = dfl_port;

		if (!port || !*port || !strcmp(port, "port"))
			port = oport;

		if (strpfx(resource, "URI:") || strpfx(resource, "URL:") || *resource == '/' || strcmp(server, hostname) || strcmp(port, oport))
			return client_printf(c, "%s%s\t%s\t%s\t%s\r\n", type, desc, resource, server, port);

		return client_printf(c, "%s%s\t/%s%s\t%s\t%s\r\n", type, desc, c->task_data.gpht.base, resource, server, port);
	}
}

static void update_gph(EV_P_ struct client *c, int revents)
{
	(void)revents;

	if (c->task_data.gpht.rfd < 0) {
		client_close(EV_A_ c);
		return;
	}

	if (!line_foreach(EV_A_ c->task_data.gpht.rfd, c->task_data.gpht.linebuf, sizeof(c->task_data.gpht.linebuf) - 1, &c->task_data.gpht.used, process_gph_line, c)) {
		if (!client_printf(c, ".\r\n"))
			return;

		close(c->task_data.gpht.rfd);
		c->task_data.gpht.rfd = -1;
	}
}

static void update_read(EV_P_ struct client *c, int revents)
{
	int r;
	char *nl;

	(void)revents;

#ifdef USE_TLS
	if (c->buffer_used == 0 && !listen_watcher.tlsctx)
		c->tlsstate = PLAIN;
	else if (c->buffer_used == 0 && c->tlsstate == UNKNOWN) {
		char byte0;
		if (recv(c->fd, &byte0, 1, MSG_PEEK) < 1) {
			client_close(EV_A_ c);
			return;
		}

		if (byte0 == 22) {
			if (tls_accept_socket(listen_watcher.tlsctx, &c->tlsctx, c->fd) < 0) {
				client_close(EV_A_ c);
				return;
			}
			c->tlsstate = HANDSHAKE;
		} else {
			c->tlsstate = PLAIN;
		}
	}

	if (c->tlsstate == HANDSHAKE) {
		switch (tls_handshake(c->tlsctx)) {
		case TLS_WANT_POLLIN:
			ev_io_stop(EV_A_ &c->watcher);
			ev_io_modify(&c->watcher, EV_READ);
			ev_io_start(EV_A_ &c->watcher);
			return;
		case TLS_WANT_POLLOUT:
			ev_io_stop(EV_A_ &c->watcher);
			ev_io_modify(&c->watcher, EV_WRITE);
			ev_io_start(EV_A_ &c->watcher);
			break;
		case 0:
			ev_io_stop(EV_A_ &c->watcher);
			ev_io_modify(&c->watcher, EV_READ);
			ev_io_start(EV_A_ &c->watcher);
			c->tlsstate = READY;
			break;
		default:
			client_close(EV_A_ c);
			return;
		}
	}

	if (c->tlsstate == READY) {
		switch ((r = tls_read(c->tlsctx, c->buffer + c->buffer_used, sizeof(c->buffer) - c->buffer_used))) {
		case TLS_WANT_POLLIN:
			ev_io_modify(&c->watcher, EV_READ);
			return;
		case TLS_WANT_POLLOUT:
			ev_io_modify(&c->watcher, EV_WRITE);
			return;
		default:
			break;
		}
	} else
#endif
		r = read(c->fd, c->buffer + c->buffer_used, sizeof(c->buffer) - c->buffer_used);

	if (r <= 0) {
		client_close(EV_A_ c);
		return;
	}

	if ((nl = memchr(c->buffer + c->buffer_used, '\n', r))) {
		char *p;
		char *bn;
		char *qs;
		char *ss;
		const char *uri;
		size_t rl;

		ev_io_stop(EV_A_ &c->watcher);
		ev_io_modify(&c->watcher, EV_WRITE);
		ev_io_start(EV_A_ &c->watcher);

		if (nl > c->buffer && nl[-1] == '\r')
			nl--;
		*nl = '\0';

		ss = memchr(c->buffer, '\t', nl - c->buffer);

		if (ss) {
			rl = ss - c->buffer;
			*ss++ = '\0';
		} else
			rl = nl - c->buffer;

		qs = memchr(c->buffer, '?', rl);

		if (qs) {
			rl = qs - c->buffer;
			*qs++ = '\0';
		}

		c->buffer[rl] = '\0';
		accesslog(c, c->buffer, qs, ss);

		if ((uri = strnpfx(c->buffer, rl, "URI:")) || (uri = strnpfx(c->buffer, rl, "URL:"))) {
			c->task = TASK_REDIRECT;
			tasks[c->task].init(EV_A_ c, -1, NULL, c->buffer, uri, qs, ss);
			return;
		}

		p = cleanup_path(c->buffer, &bn, &rl);
		if (!p) {
			client_close(EV_A_ c);
			return;
		}

		p[rl] = '\0';

		int dfd = open(gopherroot, O_RDONLY | O_DIRECTORY);
		if (dfd >= 0) {
			if (strsfx(bn, ".cgi") && !faccessat(dfd, p, X_OK, 0)) {
				c->task = TASK_CGI;
				tasks[c->task].init(EV_A_ c, dfd, NULL, p, bn, qs, ss);
			} else if (strsfx(bn, ".dcgi") && !faccessat(dfd, p, X_OK, 0)) {
				c->task = TASK_DCGI;
				tasks[c->task].init(EV_A_ c, dfd, NULL, p, bn, qs, ss);
			} else {
				int ffd = openat(dfd, rl ? p : ".", O_RDONLY);
				if (ffd >= 0) {
					struct stat sb;

					fstat(ffd, &sb);

					c->buffer_used = 0;
					guess_task(EV_A_ c, ffd, &sb, p, bn, qs, ss);
				} else {
					c->buffer_used = sprintf(c->buffer, "3Resource not found\r\n.\r\n");
					c->task = TASK_ERROR;
				}
			}
			close(dfd);
		} else {
			c->buffer_used = sprintf(c->buffer, "3Internal server error\r\n.\r\n");
			c->task = TASK_ERROR;
		}

		return;
	}

	c->buffer_used += r;

	if (c->buffer_used == sizeof(c->buffer)) {
		c->buffer_used = sprintf(c->buffer, "3Request size too large\r\n.\r\n");
		client_close(EV_A_ c);
	}
}

static void update_cgi(EV_P_ struct client *c, int revents)
{
	(void)revents;

	if (c->task_data.ct.rfd < 0) {
		client_close(EV_A_ c);
		return;
	}

	ev_io_stop(EV_A_ &c->watcher);
	ev_io_start(EV_A_ &c->task_data.ct.input_watcher);
}

static void read_dcgi(EV_P_ ev_io *w, int revents)
{
	struct client *c = PTR_FROM_FIELD(struct client, task_data.dct.ct.input_watcher, w);

	(void)revents;

	if (!line_foreach(EV_A_ c->task_data.dct.ct.rfd, c->task_data.dct.gpht.linebuf, sizeof(c->task_data.dct.gpht.linebuf) - 1, &c->task_data.dct.gpht.used, process_gph_line, c)) {
		if (!client_printf(c, ".\r\n"))
			return;

		close(c->task_data.dct.ct.rfd);
		c->task_data.dct.ct.rfd = -1;
	}

	ev_io_stop(EV_A_ &c->task_data.dct.ct.input_watcher);
	ev_io_start(EV_A_ &c->watcher);
}

static void update_dcgi(EV_P_ struct client *c, int revents)
{
	(void)revents;

	if (c->task_data.dct.ct.rfd < 0) {
		client_close(EV_A_ c);
		return;
	}

	ev_io_stop(EV_A_ &c->watcher);
	ev_io_start(EV_A_ &c->task_data.dct.ct.input_watcher);
}

static void finish_read(EV_P_ struct client *c)
{
	(void)c;
}

static void finish_dir(EV_P_ struct client *c)
{
	for (; c->task_data.dt.i < c->task_data.dt.n; c->task_data.dt.i++)
		free(c->task_data.dt.entries[c->task_data.dt.i]);
	free(c->task_data.dt.entries);
	free(c->task_data.dt.base);
	close(c->task_data.dt.dfd);
}

static void finish_text(EV_P_ struct client *c)
{
	if (c->task_data.tt.rfd >= 0)
		close(c->task_data.tt.rfd);
}

static void finish_gophermap(EV_P_ struct client *c)
{
	if (c->task_data.tt.rfd >= 0)
		close(c->task_data.tt.rfd);
}

static void finish_gph(EV_P_ struct client *c)
{
	if (c->task_data.gpht.rfd >= 0)
		close(c->task_data.gpht.rfd);
	free(c->task_data.gpht.base);
}

static void finish_binary(EV_P_ struct client *c)
{
	close(c->task_data.bt.rfd);
}

static void finish_error(EV_P_ struct client *c)
{
	(void)c;
}

static void finish_redirect(EV_P_ struct client *c)
{
	(void)c;
}

static void finish_cgi_common(EV_P_ struct cgi_task *ct)
{
	if (ct->pid)
		kill(ct->pid, SIGINT);
	if (ct->rfd >= 0)
		close(ct->rfd);
	ev_io_stop(EV_A_ &ct->input_watcher);
	ev_child_stop(EV_A_ &ct->child_watcher);
}

static void finish_cgi(EV_P_ struct client *c)
{
	finish_cgi_common(EV_A_ &c->task_data.ct);
}

static void finish_dcgi(EV_P_ struct client *c)
{
	finish_gph(EV_A_ c);
	finish_cgi_common(EV_A_ &c->task_data.dct.ct);
}

static void child_timeout(EV_P_ ev_timer *w, int revents)
{
	struct client *c = PTR_FROM_FIELD(struct client, timeout, w);

	(void)revents;

	client_close(EV_A_ c);
}

static void listen_cb(EV_P_ ev_io *w, int revents)
{
	struct listener *l = (struct listener *)w;
	struct client *c = malloc(sizeof(*c));

	c->addrlen = sizeof(c->addr);

	(void)revents;

	c->fd = accept(l->fd, (struct sockaddr *)&c->addr, &c->addrlen);

	fcntl(c->fd, F_SETFL, O_NONBLOCK);
	c->buffer_used = 0;
	c->task = TASK_READ;
#ifdef USE_TLS
	c->tlsstate = UNKNOWN;
#endif

	ev_timer_init(&c->timeout, child_timeout, 60.0, 0);
	ev_timer_start(EV_A_ &c->timeout);

	ev_io_init(&c->watcher, child_cb, c->fd, EV_READ);
	ev_io_start(EV_A_ &c->watcher);
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
	struct ev_loop *loop = EV_DEFAULT;
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
	ev_io_start(loop, &listen_watcher.watcher);

	ev_run (loop, 0);

#ifdef USE_TLS
	if (listen_watcher.tlsctx)
		tls_close(listen_watcher.tlsctx);
#endif
	close(listen_watcher.fd);

	return 0;
}
