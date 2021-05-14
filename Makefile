LDFLAGS += -lev -ltls
CFLAGS += -W -Wall -std=c99 -DUSE_TLS
SOURCES := main.c
OBJS := $(patsubst %.c,%.o,$(SOURCES))

all: tskrtt

tskrtt: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)


%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
