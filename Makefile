OBJS	 = as.o \
	   cert.o \
	   cms.o \
	   crl.o \
	   io.o \
	   ip.o \
	   log.o \
	   mft.o \
	   output-bgpd.o \
	   roa.o \
	   rsync.o \
	   tal.o \
	   validate.o \
	   x509.o
ALLOBJS	 = $(OBJS) \
	   main.o \
	   test-cert.o \
	   test-ip.o \
	   test-mft.o \
	   test-roa.o \
	   test-tal.o
BINS	 = rpki-client \
	   test-cert \
	   test-ip \
	   test-mft \
	   test-roa \
	   test-tal
CFLAGS	+= -O0 -g -W -Wall -Wextra -Wno-unused-parameter

CFLAGS	+= -I/usr/local/include/eopenssl
LDADD	 = /usr/local/lib/eopenssl/libssl.a \
	   /usr/local/lib/eopenssl/libcrypto.a

all: $(BINS)

rpki-client: $(OBJS) main.o
	$(CC) -o $@ main.o $(OBJS) $(LDFLAGS) $(LDADD)

test-tal: $(OBJS) test-tal.o
	$(CC) -o $@ test-tal.o $(OBJS) $(LDFLAGS) $(LDADD)

test-ip: $(OBJS) test-ip.o
	$(CC) -o $@ test-ip.o $(OBJS) $(LDFLAGS) $(LDADD)

test-mft: $(OBJS) test-mft.o
	$(CC) -o $@ test-mft.o $(OBJS) $(LDFLAGS) $(LDADD)

test-roa: $(OBJS) test-roa.o
	$(CC) -o $@ test-roa.o $(OBJS) $(LDFLAGS) $(LDADD)

test-cert: $(OBJS) test-cert.o
	$(CC) -o $@ test-cert.o $(OBJS) $(LDFLAGS) $(LDADD)

clean:
	rm -f $(BINS) $(ALLOBJS)

$(ALLOBJS): extern.h
