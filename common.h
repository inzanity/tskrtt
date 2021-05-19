#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>

#if EV_MULTIPLICITY
# define EV_UNUSED (void)EV_A
#else
# define EV_UNUSED
#endif

#define FOFFSET(x, y) (ptrdiff_t)(&((x *)NULL)->y)
#define PTR_FROM_FIELD(x, y, z) ((x *)((size_t)z - FOFFSET(x, y)))

#ifndef ev_io_modify
#define ev_io_modify(ev,events_)             do { (ev)->events = (ev)->events & EV__IOFDSET | (events_); } while (0)
#endif

extern const char *hostname;
extern const char *oport;
extern const char dfl_port[];
extern const char *gopherroot;

void accesslog(struct client *c, const char *resource, const char *qs, const char *ss);
char *cleanup_path(char *path, char **basename, size_t *pathlen);

#endif
