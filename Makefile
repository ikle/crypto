AR ?= ar
RANLIB ?= ranlib

TARGETS = libcrypto.a hash-test cipher-test
CFLAGS = -O6 -I"$(CURDIR)"/include

OBJECTS = $(patsubst %.c,%.o, $(wildcard hash/*.c cipher/*.c mac/*.c))

all: $(TARGETS)

clean:
	rm -f *.o $(OBJECTS) $(TARGETS)

PREFIX ?= /usr/local

install: $(TARGETS)
	install -D -d $(DESTDIR)/$(PREFIX)/bin
	install -s -m 0755 $^ $(DESTDIR)/$(PREFIX)/bin

test: hash-test cipher-test
	expect selftest

libcrypto.a: core.o hash-core.o $(OBJECTS)
	$(AR) rc $@ $^
	$(RANLIB) $@

hash-test: libcrypto.a
cipher-test: libcrypto.a
