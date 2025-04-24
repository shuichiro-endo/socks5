CC      = gcc
SRCS1   = server.c
TARGET1 = server
SRCS2   = client.c
TARGET2 = client

INCDIR  = -I./include -I.
LIBDIR  = -L./lib
LIBS    = -pthread -lcares

CFLAGS  = $(INCDIR)
LDFLAGS = $(LIBDIR) $(LIBS) -static

OBJS1   = $(SRCS1:.c=.o)
OBJS2   = $(SRCS2:.c=.o)


all: clean $(TARGET1) $(TARGET2)

$(TARGET1): $(OBJS1)
	$(CC) $^ -o $@ $(LDFLAGS)

$(TARGET2): $(OBJS2)
	$(CC) $^ -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o *~ $(TARGET1) $(TARGET2)

.PHONY: all clean
