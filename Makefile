CFLAGS += -maes -O3 -Wall -Wextra --std=c11 -march=native -mtune=native

all: aesham2 aesham2.s gminer

%.s: %.c
	$(CC) $(CFLAGS) -S $^ -fverbose-asm -g

%: %.go
	go build -o $@ $^

clean:
	rm -rf aesham2 aesham2.s gminer

.PHONY: all clean
