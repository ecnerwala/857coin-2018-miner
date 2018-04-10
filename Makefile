CC = gcc
CFLAGS += -maes -O3 -Wall -Wextra --std=c11 -march=native -mtune=native -D_POSIX_C_SOURCE=199309L -pthread
NVCC = /opt/cuda/bin/nvcc
NVCFLAGS += -arch=sm_37 --std=c++14 -Xcompiler -maes,-O3,-Wall,-Wextra,-march=native,-mtune=native,-D_POSIX_C_SOURCE=199309L,-pthread

all: aesham2 aesham2.s gminer aesham2-gpu

%.s: %.c
	$(CC) $(CFLAGS) -S $^ -fverbose-asm -g

%: %.go
	go build -o $@ $^

%: %.cu
	$(NVCC) $(NVCFLAGS) -o $@ $^

clean:
	rm -rf aesham2 aesham2.s gminer

mine: all
	./gminer $(ARGS)

money: mine

.PHONY: all clean mine money
