CC=gcc
CFLAGS=-Wall -pedantic -g

.PHONY: clean

leaker: leaker.c
	${CC} ${CFLAGS} $^ -o $@
clean:
	@rm -f leaker
