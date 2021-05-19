#ifndef TASK_H
#define TASK_H

struct client;

enum task {
	TASK_READ = 0,
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

struct task_ {
	void (*init)(EV_P_ struct client *c, int fd, struct stat *sb, const char *path, const char *fn, const char *pi, const char *qs, const char *ss);
	void (*update)(EV_P_ struct client *c, int events);
	void (*finish)(EV_P_ struct client *c);
};

extern const struct task_ tasks[];

#endif
