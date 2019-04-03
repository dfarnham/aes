RM           = rm -f
CC           = gcc
CFLAGS       = -I.
EXTRA_CFLAGS = -O2 -Wall
SRCS         = libcryptochallenge.c libaes.c libaestest.c
OBJS         = $(SRCS:.c=.o)
LIB          = libcryptochallenge.a

all: $(LIB)

$(LIB): $(OBJS)
	ar -rc $(LIB) $(OBJS)

$(OBJS): $(SRCS) libcryptochallenge.h
	$(CC) -c $(CFLAGS) $(EXTRA_CFLAGS) $(SRCS)

clean:
	$(RM) $(OBJS)

spotless: clean
	$(RM) $(LIB)

