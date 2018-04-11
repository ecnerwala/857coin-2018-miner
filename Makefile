CC = gcc
CFLAGS += -maes -O3 -Wall -Wextra --std=c11 -march=native -mtune=native -D_POSIX_C_SOURCE=199309L -pthread
NVCC = nvcc
NVCFLAGS += -arch=sm_37 --std=c++11 -Xcompiler -maes,-O3,-Wall,-Wextra,-march=native,-mtune=native,-D_POSIX_C_SOURCE=199309L,-pthread

export PATH := $(PATH):/opt/cuda/bin
export PATH := $(PATH):/usr/local/cuda/bin

all: aesham2 aesham2.s gminer
gpu: aesham2-gpu

%.s: %.c
	$(CC) $(CFLAGS) -S $^ -fverbose-asm -g

%: %.go
	go build -o $@ $^

%: %.cu
	$(NVCC) $(NVCFLAGS) -o $@ $^

clean:
	rm -rf aesham2 aesham2.s aesham2-gpu gminer

mine: all
	./gminer $(ARGS)

mine-gpu: gpu
	./gminer -gpu $(ARGS)

money: mine
money-gpu: mine-gpu

.PHONY: all clean mine money
