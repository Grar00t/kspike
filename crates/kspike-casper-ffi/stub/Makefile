CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11 -fPIC
LDFLAGS ?= -shared

ifeq ($(shell uname -s),Darwin)
  TARGET := libcasper.dylib
else
  TARGET := libcasper.so
endif

all: $(TARGET)

$(TARGET): libcasper_stub.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

install: $(TARGET)
	install -m 0755 -d $(DESTDIR)/usr/local/lib
	install -m 0644 $(TARGET) $(DESTDIR)/usr/local/lib/$(TARGET)
	-ldconfig 2>/dev/null || true

clean:
	rm -f $(TARGET)

.PHONY: all install clean
