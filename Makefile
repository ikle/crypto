AR ?= ar
RANLIB ?= ranlib

TARGETS = libcrypto.a
CFLAGS = -O6 -I"$(CURDIR)"/include

OBJECTS = $(patsubst %.c,%.o, $(wildcard hash/*.c cipher/*.c mac/*.c))
TESTS = $(patsubst %.c,%, $(wildcard test/*.c))

all: $(TARGETS)

.PHONY: clean install test

clean:
	rm -f *.o $(OBJECTS) $(TESTS) $(TARGETS)

PREFIX ?= /usr/local

install: $(TARGETS)
	install -D -d $(DESTDIR)/$(PREFIX)/bin
	install -s -m 0755 $^ $(DESTDIR)/$(PREFIX)/bin

test: $(TESTS)
	(cd $@ && expect selftest)

libcrypto.a: core.o hash-core.o $(OBJECTS)
	$(AR) rc $@ $^
	$(RANLIB) $@

$(TESTS): libcrypto.a
