CC = gcc
CFLAGS += -maes -O3 -Wall -Wextra --std=c11 -march=native -mtune=native -D_POSIX_C_SOURCE=199309L -pthread

all: aesham2 aesham2.s gminer

%.s: %.c
	$(CC) $(CFLAGS) -S $^ -fverbose-asm -g

%: %.go
	go build -o $@ $^

clean:
	rm -rf aesham2 aesham2.s gminer

mine: all
	./gminer $(ARGS)

money: mine

.PHONY: all clean mine money
