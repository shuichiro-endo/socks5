CC		= gcc
CFLAGS	=
LDFLAGS	= -lmbedtls -lmbedx509 -lmbedcrypto -pthread
LIBS		=
SRCS1		= server.c
OBJS1		= $(SRCS1:.c=.o)
TARGET1	= server
SRCS2		= client.c
OBJS2		= $(SRCS2:.c=.o)
TARGET2	= client


all:		clean $(TARGET1) $(TARGET2)

$(TARGET1):	$(OBJS1)
		$(CC) $^ $(LDFLAGS) $(LIBS) -o $@

$(TARGET2):	$(OBJS2)
		$(CC) $^ $(LDFLAGS) $(LIBS) -o $@

clean:;		rm -f *.o *~ $(TARGET1) $(TARGET2)

