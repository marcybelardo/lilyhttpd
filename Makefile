CC?=gcc
CFLAGS?=-O

all: lilyhttpd

marigold: lilyhttpd.c
	$(CC) $(CFLAGS) lilyhttpd.c -o $@

clean:
	rm -f lilyhttpd

.PHONY: all clean
