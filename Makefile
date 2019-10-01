include Makefile.configure

OBJS	 = as.o \
	   asn1.o \
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
	   test-core.o \
	   validate.o \
	   x509.o
ALLOBJS	 = $(OBJS) \
	   main.o \
	   test-cert.o \
	   test-crl.o \
	   test-mft.o \
	   test-roa.o \
	   test-tal.o
BINS	 = rpki-client \
	   test-cert \
	   test-crl \
	   test-mft \
	   test-roa \
	   test-tal

ARCH=$(shell uname -s|tr A-Z a-z)
ifeq ($(ARCH), linux)
	# Linux.
	LDADD += `pkg-config --libs openssl` -lresolv
	CFLAGS += `pkg-config --cflags openssl`
else
	# OpenBSD.
	CFLAGS += -I/usr/local/include/eopenssl
	LDADD += /usr/local/lib/eopenssl/libssl.a /usr/local/lib/eopenssl/libcrypto.a
endif

all: $(BINS)

install: all
	mkdir -p $(DESTDIR)$(BINDIR)
	mkdir -p $(DESTDIR)$(MANDIR)/man8
	$(INSTALL_PROGRAM) rpki-client $(DESTDIR)$(BINDIR)
	$(INSTALL_MAN) rpki-client.8 $(DESTDIR)$(MANDIR)/man8

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/rpki-client
	rm -f $(DESTDIR)$(MANDIR)/man8/rpki-client.8

rpki-client: main.o $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(LDADD)

test-tal: test-tal.o $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(LDADD)

test-mft: test-mft.o $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(LDADD)

test-roa: test-roa.o $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(LDADD)

test-cert: test-cert.o $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(LDADD)

test-crl: test-crl.o $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(LDADD)

clean:
	rm -f $(BINS) $(ALLOBJS)

distclean: clean
	rm -f config.h config.log Makefile.configure

$(ALLOBJS): extern.h config.h
