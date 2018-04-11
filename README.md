# 6857Coin Miner!

Mining 6857Coin! This is broken up into 3 pieces of code in 3 languages.

* `gminer.go` is a miner written in go. This is the good one.
* `aesham2.c` is an optimized hashing program in C.
* `miner.py` is the old Python 2 miner. Don't use this anymore.

To build things, you need [Go](https://golang.org/dl/) and
[GCC](https://gcc.gnu.org/install/binaries.html).
Then, run
    make
to compile the code, and/or
    make mine
to run the actual miner. Don't run it multiple times, it already uses multiple
threads.

The actual hash functions and blockchain specification is [here](6857Coin.md).

## GPU

We now have a GPU miner! It's lightly optimized, and it's about 3x faster on a
K80s than my 4-core CPU, which isn't a huge gain. It does pretty much the same
thing as the CPU miner. Build with `make gpu` and mine with `make mine-gpu` (or
pass the `-gpu` flag directly to `gminer`).
