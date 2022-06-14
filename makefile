.POSIX:

cc:=cc
cflags:=-std=c17 -Wall -Wextra -Werror -Wshadow
src:=texhtml.c

debug: $(src)
	$(cc) $< -o $@ $(cflags) -O0 -g -fsanitize=undefined -fsanitize=address -DDEBUG

texhtml: $(src)
	$(cc) $< -o $@ $(cflags) -O3

.PHONY: install
install: texhtml
	mkdir -p /usr/local/bin
	cp $< /usr/local/bin

.PHONY: uninstall
uninstall:
	rm /usr/local/bin/texhtml

.PHONY: clean
clean:
	rm -f debug texhtml
