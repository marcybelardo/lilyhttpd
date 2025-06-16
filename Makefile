CC=gcc
CFLAGS=-Wall -Wextra -O2 -g

TARGET=lilyhttpd
SRC=lilyhttpd.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
