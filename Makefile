.POSIX:
.SUFFIXES:

CC=cc
CFLAGS=
LDFLAGS=
TEXHTML_CFLAGS=-std=c17 -Wall -Wextra -Wpedantic -Wshadow
TEXHTML_LDFLAGS=
SRC=texhtml.c

texhtml: $(SRC)
	$(CC) $(SRC) -o $@ $(TEXHTML_CFLAGS) $(CFLAGS)

debug: $(SRC)
	$(CC) $(SRC) -o $@ $(TEXHTML_CFLAGS) -O0 -g -fsanitize=undefined -fsanitize=address -DDEBUG

.PHONY: install
install: texhtml
	mkdir -p /usr/local/bin
	cp $< /usr/local/bin

.PHONY: uninstall
uninstall:
	rm /usr/local/bin/texhtml

.PHONY: clean
clean:
	rm -f texhtml debug
