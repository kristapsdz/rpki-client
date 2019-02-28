OBJS	 = cms.o \
	   io.o \
	   log.o \
	   mft.o \
	   roa.o \
	   rsync.o \
	   tal.o \
	   cert.o
ALLOBJS	 = $(OBJS) \
	   main.o \
	   test-mft.o \
	   test-roa.o \
	   test-tal.o \
	   test-cert.o
BINS	 = rpki-client \
	   test-mft \
	   test-roa \
	   test-tal \
	   test-cert
CFLAGS	+= -O0 -g -W -Wall -Wextra -Wno-unused-parameter

CFLAGS	+= -I/usr/local/include/eopenssl
LDADD	 = /usr/local/lib/eopenssl/libssl.a \
	   /usr/local/lib/eopenssl/libcrypto.a

all: $(BINS)

rpki-client: $(OBJS) main.o
	$(CC) -o $@ main.o $(OBJS) $(LDFLAGS) $(LDADD)

test-tal: $(OBJS) test-tal.o
	$(CC) -o $@ test-tal.o $(OBJS) $(LDFLAGS) $(LDADD)

test-mft: $(OBJS) test-mft.o
	$(CC) -o $@ test-mft.o $(OBJS) $(LDFLAGS) $(LDADD)

test-roa: $(OBJS) test-roa.o
	$(CC) -o $@ test-roa.o $(OBJS) $(LDFLAGS) $(LDADD)

test-cert: $(OBJS) test-cert.o
	$(CC) -o $@ test-cert.o $(OBJS) $(LDFLAGS) $(LDADD)

clean:
	rm -f $(BINS) $(ALLOBJS)

$(ALLOBJS): extern.h
