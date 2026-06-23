QEMU_SRC ?=

CC = gcc

PLUGIN_CFLAGS = -fPIC -shared -Wall -O2 -g $(shell pkg-config --cflags glib-2.0)
PLUGIN_LIBS   = $(shell pkg-config --libs glib-2.0)

ifneq ($(QEMU_SRC),)
	PLUGIN_CFLAGS += -I$(QEMU_SRC)/include -I$(QEMU_SRC)/include/plugins
endif

TARGET = libbrtrace.so
SRCS   = $(wildcard *.c)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(PLUGIN_CFLAGS) $^ -o $@ $(PLUGIN_LIBS)

clean:
	rm -f $(TARGET)
