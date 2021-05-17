LDFLAGS = -L/usr/local/lib -lev -ltls
CFLAGS = -W -Wall -std=c99 -DUSE_TLS -I/usr/local/include
SOURCES := main.c
OBJS := ${SOURCES:.c=.o}

all: tskrtt

tskrtt: ${OBJS}
	${CC} ${CFLAGS} -o $@ ${OBJS} ${LDFLAGS}

.c.o:
	${CC} ${CFLAGS} -c $< -o $@

clean:
	rm -f ${OBJS}
