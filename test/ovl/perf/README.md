# Xcluster/ovl - perf

Playground for testing perf scripts

## Build perf
Build perf from kernel source, this is a pre-requisite for all tests in this ovl.
```
./perf.sh build
```

## Mount debugfs
sudo mount -t debugfs -o mode=755 nodev /sys/kernel/debug

## Usage
It is *recommended* to setup `xcluster` in a
[netns](https://github.com/Nordix/xcluster/blob/master/doc/netns.md)
for these tests.

Basic tests;
```
. ./Envsettings
./perf.sh build
./perf.sh test start
```
