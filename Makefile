AR ?= ar
RANLIB ?= ranlib

TARGETS = libcrypto.a
CFLAGS = -O6

all: $(TARGETS)

clean:
	rm -f *.o $(TARGETS)

PREFIX ?= /usr/local

install: $(TARGETS)
	install -D -d $(DESTDIR)/$(PREFIX)/bin
	install -s -m 0755 $^ $(DESTDIR)/$(PREFIX)/bin

libcrypto.a: core.o md5-core.o
	$(AR) rc $@ $^
	$(RANLIB) $@
