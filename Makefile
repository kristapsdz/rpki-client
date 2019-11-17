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
	   output-bird.o \
	   output-bgpd.o \
	   output-csv.o \
	   output-json.o \
	   roa.o \
	   rsync.o \
	   tal.o \
	   validate.o \
	   x509.o
ALLOBJS	 = $(OBJS) \
	   main.o \
	   test-cert.o \
	   test-mft.o \
	   test-roa.o \
	   test-tal.o
BINS	 = rpki-client \
	   test-cert \
	   test-mft \
	   test-roa \
	   test-tal
RSYNC 	 = openrsync

# Our rsync binary defaulting to openrsync.

CFLAGS	+= -DRSYNC=\"$(RSYNC)\"

all: $(BINS) rpki-client.install.8

install: all
	mkdir -p $(DESTDIR)$(BINDIR)
	mkdir -p $(DESTDIR)$(MANDIR)/man8
	$(INSTALL_PROGRAM) rpki-client $(DESTDIR)$(BINDIR)
	$(INSTALL_MAN) rpki-client.install.8 $(DESTDIR)$(MANDIR)/man8/rpki-client.8

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/rpki-client
	rm -f $(DESTDIR)$(MANDIR)/man8/rpki-client.8

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
	rm -f $(BINS) $(ALLOBJS) rpki-client.install.8

distclean: clean
	rm -f config.h config.log Makefile.configure

$(ALLOBJS): extern.h config.h

rpki-client.install.8: rpki-client.8
	sed "s!@RSYNC@!$(RSYNC)!g" rpki-client.8 >$@
