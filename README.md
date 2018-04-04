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
