AR ?= ar
RANLIB ?= ranlib

TARGETS = libcrypto.a hash-test cipher-test
CFLAGS  = -O6
CFLAGS += -I"$(CURDIR)" -I"$(CURDIR)"/hash -I"$(CURDIR)"/cipher

all: $(TARGETS)

clean:
	rm -f *.o hash/*.o cipher/*.o $(TARGETS)

PREFIX ?= /usr/local

install: $(TARGETS)
	install -D -d $(DESTDIR)/$(PREFIX)/bin
	install -s -m 0755 $^ $(DESTDIR)/$(PREFIX)/bin

test: hash-test cipher-test
	expect selftest

libcrypto.a: core.o hash-core.o hmac-core.o
libcrypto.a: hash/md5-core.o hash/sha1-core.o hash/stribog-core.o
libcrypto.a: cipher/kuznechik-core.o cipher/magma-core.o
	$(AR) rc $@ $^
	$(RANLIB) $@

hash-test: libcrypto.a
cipher-test: libcrypto.a
