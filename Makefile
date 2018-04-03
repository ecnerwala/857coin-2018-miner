CFLAGS += -maes -O2 -Wall -Wextra --std=c11 -march=native -mtune=native

all: aesham2 aesham2.s

%.s: %.c
	$(CC) $(CFLAGS) -S $^ -fverbose-asm -g

clean:
	rm -rf aesham2 aesham2.s

.PHONY: all clean
