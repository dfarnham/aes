RM           = rm -f
CC           = gcc
LIBS         = ../lib/libcryptochallenge.a
CFLAGS       = -I. -I../lib
EXTRA_CFLAGS = -O2 -Wall
SRCS         = aes.c
OBJS         = $(SRCS:.c=.o)
EXE          = aes

all: $(EXE)

$(EXE): $(OBJS)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(OBJS) $(LIBS) -o $(EXE)

$(OBJS): $(SRCS)
	$(CC) -c $(CFLAGS) $(EXTRA_CFLAGS) $(SRCS)

test: spotless all
	@ECHO "-~-~-~-~-~-~-~-~TEST~-~-~-~-~-~-~-~-~-~-"
	@$(EXE) -128 -ecb -decrypt -base64 --hexkey='59454c4c4f57205355424d4152494e45' --file=7.txt

itest: spotless all
	@$(EXE) -test128 -test192 -test256

nist-test: spotless all
	@nistVectorTest.pl NIST_TEST_VECTORS/*.rsp

clean:
	$(RM) $(OBJS)

spotless: clean
	$(RM) $(EXE)

