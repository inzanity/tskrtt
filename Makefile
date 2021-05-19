LIBEV_CFLAGS =
LIBEV_LIBS = -lev
TLS_CFLAGS = -I/usr/local/include -DUSE_TLS
TLS_LIBS = -L/usr/local/lib -ltls
LDFLAGS = ${LIBEV_LIBS} ${TLS_LIBS}
CFLAGS = -W -Wall -std=c99 -DUSE_TLS
SOURCES = main.c task.c client.c
OBJS = ${SOURCES:.c=.o}

all: tskrtt

tskrtt: ${OBJS}
	${CC} ${CFLAGS} -o $@ ${OBJS} ${LDFLAGS} ${LIBEV_LIBS} ${TLS_LIBS}

.c.o:
	${CC} ${CFLAGS} ${LIBEV_CFLAGS} ${TLS_CFLAGS} -c $< -o $@

clean:
	rm -f ${OBJS}

client.o: client.h common.h task.h
main.o: arg.h client.h common.h
task.o: common.h client.h task.h
