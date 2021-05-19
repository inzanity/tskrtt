#define _POSIX_C_SOURCE 200809L
#include <ev.h>
#ifdef USE_TLS
#include <tls.h>
#endif

#include <sys/mman.h>

#include <dirent.h>
#include <fcntl.h>
#include <netdb.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "client.h"
#include "task.h"
#include "common.h"

static void read_dcgi(EV_P_ ev_io *w, int revents);

static void init_dir(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *pi, const char *qs, const char *ss);
static void init_text(EV_P_ struct client *, int fd, struct stat *sb, const char *path, const char *fn, const char *pi, const char *qs, const char *ss);
static void init_gph(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *pi, const char *qs, const char *ss);
static void init_gophermap(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *pi, const char *qs, const char *ss);
static void init_binary(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *pi, const char *qs, const char *ss);
static void init_error(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *pi, const char *qs, const char *ss);
static void init_redirect(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *pi, const char *qs, const char *ss);
static void init_cgi(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *pi, const char *qs, const char *ss);
static void init_dcgi(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *pi, const char *qs, const char *ss);

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

static char *xbasename(char *file)
{
	char *rv = strrchr(file, '/');

	if (!rv)
		return file;
	return rv + 1;
}

static char *dupdirname(const char *w)
{
	char *rv;
	char *ls = strrchr(w, '/');

	if (!ls++)
		return strdup("");
	rv = malloc(ls - w + 1);
	if (!rv)
		return rv;
	memcpy(rv, w, ls - w);
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
	if (!rv)
		return NULL;
	sprintf(rv, "%s%c%s", a, separator, b);
	return rv;
}

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
	if (strsfx(e->d_name, ".cgi") ||
	    strsfx(e->d_name, ".dcgi") ||
	    strsfx(e->d_name, ".gph"))
		return '1';

	return '9';
}

static char *dupensurepath(const char *w)
{
	size_t l = strlen(w);
	char *rv;

	if (!l)
		return strdup("");
	if (w[l - 1] == '/')
		l--;
	rv = malloc(l + 2);
	if (!rv)
		return rv;
	memcpy(rv, w, l);
	rv[l++] = '/';
	rv[l] = '\0';
	return rv;
}

static int filterdot(const struct dirent *e)
{
	return strcmp(e->d_name, ".") && strcmp(e->d_name, "..");
}

static inline void *xmemdup(const void *p, size_t l)
{
	void *m = malloc(l);
	if (!m)
		return NULL;
	return memcpy(m, p, l);
}


static int xfdscandir(int dfd, struct dirent ***namelist, int (*filter)(const struct dirent *), int compar(const struct dirent **, const struct dirent **))
{
	size_t n = 0;
	size_t sz = 64;
	DIR *d;
	struct dirent *e;

	d = fdopendir(dfd);
	if (!d) {
		*namelist = NULL;
		return 0;
	}

	*namelist = malloc(sz * sizeof(**namelist));

	if (!*namelist)
		goto err;

	while ((e = readdir(d))) {
		size_t nl = strlen(e->d_name);
		if (filter && !filter(e))
			continue;
		if (n == sz) {
			void *np = realloc(*namelist, (sz *= 2) * sizeof(**namelist));
			if (!np)
				goto err;
			*namelist = np;
		}
		if (!((*namelist)[n] = xmemdup(e, FOFFSET(struct dirent, d_name) + nl + 1)))
			goto err;
		n++;
	}

	closedir(d);

	qsort(*namelist, n, sizeof(**namelist), (int (*)(const void *, const void *))compar);

	return n;

err:
	while (n--)
		free((*namelist)[n]);
	free(*namelist);
	*namelist = NULL;

	closedir(d);

	return 0;
}

static char *xdupprintf(const char *fmt, ...)
{
	va_list args;
	int n;
	char *rv;

	va_start(args, fmt);
	n = vsnprintf(NULL, 0, fmt, args);
	va_end(args);

	if (!(rv = malloc(n + 1)))
		return rv;

	va_start(args, fmt);
	vsnprintf(rv, n + 1, fmt, args);
	va_end(args);

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

	tasks[c->task].init(EV_A_ c, fd, sb, path, fn, NULL, qs, ss);

	if (t)
		free(t);
}

const struct task_ tasks[] = {
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

static void init_dir(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *pi, const char *qs, const char *ss)
{
	EV_UNUSED;
	(void)sb;
	(void)qs;
	(void)ss;
	(void)pi;

	c->task_data.dt.base = dupensurepath(path);
	if (*path)
		client_printf(c, "1..\t/%.*s\t%s\t%s\r\n", (int)(fn - path), path, hostname, oport);
	c->task_data.dt.dfd = fd;
	c->task_data.dt.n = xfdscandir(dup(fd), &c->task_data.dt.entries, filterdot, alphasort);
	c->task_data.dt.i = 0;
}

static void init_text(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *pi, const char *qs, const char *ss)
{
	EV_UNUSED;
	(void)sb;
	(void)path;
	(void)fn;
	(void)qs;
	(void)ss;
	(void)pi;

	c->task_data.tt.rfd = fd;
	c->task_data.tt.used = 0;
}

static void init_gophermap(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *pi, const char *qs, const char *ss)
{
	EV_UNUSED;
	(void)sb;
	(void)path;
	(void)fn;
	(void)qs;
	(void)ss;
	(void)pi;

	c->task_data.tt.rfd = fd;
	c->task_data.tt.used = 0;
}

static void init_gph(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *pi, const char *qs, const char *ss)
{
	EV_UNUSED;
	(void)sb;
	(void)fn;
	(void)qs;
	(void)ss;
	(void)pi;

	c->task_data.gpht.rfd = fd;
	c->task_data.gpht.base = dupdirname(path);
	c->task_data.gpht.used = 0;
}

static void init_binary(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *pi, const char *qs, const char *ss)
{
	int sbsz = 0;

	(void)path;
	(void)fn;
	(void)qs;
	(void)ss;
	(void)pi;

	getsockopt(c->fd, SOL_SOCKET, SO_SNDBUF, &sbsz, &(socklen_t){ sizeof(sbsz) });

	c->task_data.bt.rfd = fd;
	if (sb->st_size * (c->tlsstate == READY ? 2 : 1) <= sbsz) {
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

static void init_error(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *pi, const char *qs, const char *ss)
{
	EV_UNUSED;
	(void)c;
	(void)fd;
	(void)sb;
	(void)path;
	(void)fn;
	(void)qs;
	(void)ss;
	(void)pi;
}

static void init_redirect(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *pi, const char *qs, const char *ss)
{
	EV_UNUSED;
	(void)fd;
	(void)sb;
	(void)path;
	(void)qs;
	(void)ss;
	(void)pi;

	client_printf(c,
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
				 fn, fn, fn);
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
		ev_io_stop(EV_A_ &c->task_data.ct.input_watcher);
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

	EV_UNUSED;
	(void)revent;

	ct->pid = 0;
}

static void init_cgi_common(EV_P_ struct client *c, struct cgi_task *ct, int fd, struct stat *sb, const char *path, const char *fn, const char *pi, const char *qs, const char *ss, void (*read_cb)(EV_P_ ev_io *w, int revents))
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
		client_error(EV_A_ c, "Internal server error");
		return;
	}

	switch ((ct->pid = fork())) {
	case 0:
		break;
	case -1:
		close(fd);
		close(pfd[0]);
		close(pfd[1]);
		client_error(EV_A_ c, "Internal server error");
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

	/* chdir may fail, but there's not much we can do about it */
	if (fchdir(fd)) {}
	close(fd);

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

	if (!pi)
		pi = "";
	else
		pi = xdupprintf("/%s", pi);

	path = xdupprintf("/%s", path);

	getnameinfo((struct sockaddr *)&c->addr, c->addrlen, abuf, sizeof(abuf), NULL, 0, NI_NUMERICHOST);
	env[nenv++] = envstr("GATEWAY_INTERFACE", "CGI/1.1");
	env[nenv++] = envstr("PATH_INFO", pi);
	env[nenv++] = envstr("SCRIPT_FILENAME", file);
	env[nenv++] = envstr("QUERY_STRING", qs);
	env[nenv++] = envstr("SELECTOR", qs);
	env[nenv++] = envstr("REQUEST", qs);
	env[nenv++] = envstr("REMOTE_ADDR", abuf);
	env[nenv++] = envstr("REMOTE_HOST", abuf);
	env[nenv++] = envstr("REDIRECT_STATUS", "");
	env[nenv++] = envstr("REQUEST_METHOD", "GET");
	env[nenv++] = envstr("SCRIPT_NAME", path);
	env[nenv++] = envstr("SERVER_NAME", hostname);
	env[nenv++] = envstr("SERVER_PORT", oport);
	env[nenv++] = envstr("SERVER_PROTOCOL", "gopher/1.0");
	env[nenv++] = envstr("SERVER_SOFTWARE", "tskrtt");
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
	if (&c->task_data.ct == ct)
		printf("3Internal server error\t.\t.\t.\r\n.\r\n");
	else
		printf("[3|Internal server error]");
	exit(1);
}

static void init_cgi(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *pi, const char *qs, const char *ss)
{
	init_cgi_common(EV_A_ c, &c->task_data.ct, fd, sb, path, fn, pi, qs, ss, read_cgi);
}

static void init_dcgi(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *pi, const char *qs, const char *ss)
{
	init_cgi_common(EV_A_ c, &c->task_data.dct.ct, fd, sb, path, fn, pi, qs, ss, read_dcgi);
	if (pi) {
		/* TODO: make this nicer */
		((char *)pi)[-1] = '/';
		fn = xbasename((char *)path);
	}
	init_gph(EV_A_ c, -1, sb, path, fn, NULL, qs, ss);
}

static const char *format_size(off_t bytes)
{
	static char buf[64];
	const char *mult = "kMGTPEZY";
	if (bytes < 1024) {
		sprintf(buf, "%ju", (uintmax_t)bytes);
	} else {
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
		/*
		int n = mbstowcs(NULL, c->task_data.dt.entries[c->task_data.dt.i]->d_name, 0);
		wchar_t mbs[n + 1];
		printf("%s\n", c->task_data.dt.entries[c->task_data.dt.i]->d_name);
		mbstowcs(mbs, c->task_data.dt.entries[c->task_data.dt.i]->d_name, n + 1);
		printf("%d: %ls\n", n, mbs);
		*/
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
			client_printf(c, "3Filename too long\t.\t.\t.\r\n");
		}
		free(c->task_data.dt.entries[c->task_data.dt.i]);
	}

	if (client_eos(c))
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

static bool line_foreach(int fd, char *buffer, size_t buffer_size, size_t *buffer_used, bool (*line_cb)(struct client *c, char *line, size_t linelen), struct client *c)
{
	int r;
	char *nl;
	char *bp;

	if (*buffer_used < buffer_size) {
		r = read(fd, buffer + *buffer_used, buffer_size - *buffer_used);
		if (r <= 0) {
			if (*buffer_used)
				return !line_cb(c, buffer, *buffer_used);
			return false;
		}

		*buffer_used += r;
	}

	nl = memchr(buffer, '\n', *buffer_used);

	if (!nl) {
		if (*buffer_used == buffer_size && line_cb(c, buffer, buffer_size))
			*buffer_used = 0;
		return true;
	}

	bp = buffer;
	do {
		char *t = nl;
		if (t > bp && t[-1] == '\r')
			t--;

		if (!line_cb(c, bp, t - bp))
			break;

		bp = nl + 1;
	} while ((nl = memchr(bp, '\n', *buffer_used - (bp - buffer))));

	memmove(buffer, bp, *buffer_used - (bp - buffer));
	*buffer_used -= bp - buffer;

	return true;
}

static bool process_text_line(struct client *c, char *line, size_t linelen)
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

	if (!line_foreach(c->task_data.tt.rfd, c->task_data.tt.linebuf, sizeof(c->task_data.tt.linebuf), &c->task_data.tt.used, process_text_line, c)) {
		if (!client_eos(c))
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

static bool process_gophermap_line(struct client *c, char *line, size_t linelen)
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

	if (!line_foreach(c->task_data.tt.rfd, c->task_data.tt.linebuf, sizeof(c->task_data.tt.linebuf), &c->task_data.tt.used, process_gophermap_line, c)) {
		if (!client_eos(c))
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

static bool process_gph_line(struct client *c, char *line, size_t linelen)
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
			return client_printf(c, "3Invalid line\t.\t.\t.\r\n");

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

	if (!line_foreach(c->task_data.gpht.rfd, c->task_data.gpht.linebuf, sizeof(c->task_data.gpht.linebuf) - 1, &c->task_data.gpht.used, process_gph_line, c)) {
		if (!client_eos(c))
			return;

		close(c->task_data.gpht.rfd);
		c->task_data.gpht.rfd = -1;
	}
}

static void swaptoscriptdir(int *dfd, char *p, char *bn)
{
	int t;

	if (bn == p)
		return;

	bn[-1] = '\0';
	if ((t = openat(*dfd, p, O_RDONLY | O_DIRECTORY)) >= 0) {
		close(*dfd);
		*dfd = t;
	}
	bn[-1] = '/';
}

static char *splitaccessat(int dfd, char *path, const char *delim, size_t off, int mode, int flags)
{
	char *p;
	char t;

	if (!(p = strstr(path, delim)))
		return NULL;
	t = p[off];
	p[off] = '\0';
	if (faccessat(dfd, path, mode, flags)) {
		p[off] = t;
		return NULL;
	}
	return p + off + 1;
}

static void update_read(EV_P_ struct client *c, int revents)
{
	int r;
	char *nl;

	(void)revents;

#ifdef USE_TLS
	if (c->buffer_used == 0 && !c->tlsctx)
		c->tlsstate = PLAIN;
	else if (c->buffer_used == 0 && c->tlsstate == UNKNOWN) {
		char byte0;
		if (recv(c->fd, &byte0, 1, MSG_PEEK) < 1) {
			client_close(EV_A_ c);
			return;
		}

		if (byte0 == 22) {
			struct tls *tc;
			if (tls_accept_socket(c->tlsctx, &tc, c->fd) < 0) {
				client_close(EV_A_ c);
				return;
			}
			c->tlsctx = tc;
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
		char buffer[nl - c->buffer + 1];
		char *p;
		char *bn;
		char *qs;
		char *ss;
		char *pi;
		const char *uri;
		size_t rl;
		int ffd;

		memcpy(buffer, c->buffer, nl - c->buffer);
		nl += buffer - c->buffer;
		c->buffer_used = 0;
		c->broken_client = false;

		ev_io_stop(EV_A_ &c->watcher);
		ev_io_modify(&c->watcher, EV_WRITE);
		ev_io_start(EV_A_ &c->watcher);

		if (nl > buffer && nl[-1] == '\r')
			nl--;
		*nl = '\0';

		ss = memchr(buffer, '\t', nl - buffer);

		if (ss) {
			rl = ss - buffer;
			*ss++ = '\0';
		} else
			rl = nl - buffer;

		qs = memchr(buffer, '?', rl);

		if (qs) {
			rl = qs - buffer;
			*qs++ = '\0';
		}

		buffer[rl] = '\0';

		accesslog(c, buffer, qs, ss);

		if (ss && !strcmp(ss, "$")) {
			client_printf(c, "+-1\r\n");
			c->broken_client = true;
		}

		if ((uri = strnpfx(buffer, rl, "URI:")) || (uri = strnpfx(buffer, rl, "URL:"))) {
			c->task = TASK_REDIRECT;
			tasks[c->task].init(EV_A_ c, -1, NULL, buffer, uri, NULL, qs, ss);
			return;
		}

		p = cleanup_path(buffer, &bn, &rl);
		if (!p) {
			client_error(EV_A_ c, "Invalid path");
			return;
		}

		p[rl] = '\0';

		int dfd = open(gopherroot, O_RDONLY | O_DIRECTORY);
		if (dfd >= 0) {
			if (strsfx(bn, ".cgi") && !faccessat(dfd, p, X_OK, 0)) {
				c->task = TASK_CGI;
				swaptoscriptdir(&dfd, p, bn);
				tasks[c->task].init(EV_A_ c, dfd, NULL, p, bn, NULL, qs, ss);
			} else if (strsfx(bn, ".dcgi") && !faccessat(dfd, p, X_OK, 0)) {
				c->task = TASK_DCGI;
				swaptoscriptdir(&dfd, p, bn);
				tasks[c->task].init(EV_A_ c, dfd, NULL, p, bn, NULL, qs, ss);
			} else if ((ffd = openat(dfd, rl ? p : ".", O_RDONLY)) >= 0) {
				struct stat sb;

				fstat(ffd, &sb);
				guess_task(EV_A_ c, ffd, &sb, p, bn, qs, ss);
			} else if ((pi = splitaccessat(dfd, p, ".cgi/", 4, X_OK, 0))) {
				c->task = TASK_CGI;
				bn = xbasename(p);
				swaptoscriptdir(&dfd, p, bn);
				tasks[c->task].init(EV_A_ c, dfd, NULL, p, bn, pi, qs, ss);
			} else if ((pi = splitaccessat(dfd, p, ".dcgi/", 5, X_OK, 0))) {
				c->task = TASK_DCGI;
				bn = xbasename(p);
				swaptoscriptdir(&dfd, p, bn);
				tasks[c->task].init(EV_A_ c, dfd, NULL, p, bn, pi, qs, ss);
			} else {
				client_error(EV_A_ c, "Resource not found");
			}
			close(dfd);
		} else {
			client_error(EV_A_ c, "Internal server error");
		}

		return;
	}

	c->buffer_used += r;

	if (c->buffer_used == sizeof(c->buffer)) {
		c->buffer_used = 0;
		client_error(EV_A_ c, "Request size too large");
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

	if (!line_foreach(c->task_data.dct.ct.rfd, c->task_data.dct.gpht.linebuf, sizeof(c->task_data.dct.gpht.linebuf) - 1, &c->task_data.dct.gpht.used, process_gph_line, c)) {
		if (!client_eos(c))
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
	EV_UNUSED;
	(void)c;
}

static void finish_dir(EV_P_ struct client *c)
{
	EV_UNUSED;
	for (; c->task_data.dt.i < c->task_data.dt.n; c->task_data.dt.i++)
		free(c->task_data.dt.entries[c->task_data.dt.i]);
	free(c->task_data.dt.entries);
	free(c->task_data.dt.base);
	close(c->task_data.dt.dfd);
}

static void finish_text(EV_P_ struct client *c)
{
	EV_UNUSED;
	if (c->task_data.tt.rfd >= 0)
		close(c->task_data.tt.rfd);
}

static void finish_gophermap(EV_P_ struct client *c)
{
	EV_UNUSED;
	if (c->task_data.tt.rfd >= 0)
		close(c->task_data.tt.rfd);
}

static void finish_gph(EV_P_ struct client *c)
{
	EV_UNUSED;
	if (c->task_data.gpht.rfd >= 0)
		close(c->task_data.gpht.rfd);
	free(c->task_data.gpht.base);
}

static void finish_binary(EV_P_ struct client *c)
{
	EV_UNUSED;
	close(c->task_data.bt.rfd);
}

static void finish_error(EV_P_ struct client *c)
{
	EV_UNUSED;
	(void)c;
}

static void finish_redirect(EV_P_ struct client *c)
{
	EV_UNUSED;
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

