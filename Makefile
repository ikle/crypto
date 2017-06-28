AR ?= ar
RANLIB ?= ranlib

TARGETS = libcrypto.a hash-test
CFLAGS = -O6

all: $(TARGETS)

clean:
	rm -f *.o $(TARGETS)

PREFIX ?= /usr/local

install: $(TARGETS)
	install -D -d $(DESTDIR)/$(PREFIX)/bin
	install -s -m 0755 $^ $(DESTDIR)/$(PREFIX)/bin

libcrypto.a: core.o md5-core.o sha1-core.o hash-core.o stribog-core.o
	$(AR) rc $@ $^
	$(RANLIB) $@

hash-test: libcrypto.a
