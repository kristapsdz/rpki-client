include Makefile.configure

OBJS	 = as.o \
	   cert.o \
	   cms.o \
	   compats.o \
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

# Linux.
#OPENSSL	 = openssl
#LDADD	+= -lresolv

# OpenBSD.
OPENSSL = eopenssl

CFLAGS	+= `pkg-config --cflags $(OPENSSL)`
LDADD	+= `pkg-config --libs $(OPENSSL)`


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

$(ALLOBJS): extern.h config.h
