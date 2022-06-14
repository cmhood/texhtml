.POSIX:

cc:=cc
cflags:=-std=c17 -Wall -Wextra -Werror -Wshadow
src:=texhtml.c

debug: $(src)
	$(cc) $< -o $@ $(cflags) -O0 -g -fsanitize=undefined -fsanitize=address -DDEBUG

texhtml: $(src)
	$(cc) $< -o $@ $(cflags) -O3

clean:
	rm -f debug texhtml
