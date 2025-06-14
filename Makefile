CC?=gcc
CFLAGS?=-O

all: marigold

marigold: marigold.c
	$(CC) $(CFLAGS) marigold.c -o $@

clean:
	rm -f marigold

.PHONY: all clean
