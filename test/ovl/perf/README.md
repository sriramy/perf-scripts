# Xcluster/ovl - perf

Playground for testing perf scripts

## Build perf
Build perf from kernel source, this is a pre-requisite for all tests in this ovl.
```
./perf.sh build
```

## Get perf-scripts
```
mkdir -p $GOPATH/src/github.com/sriramy
cd $GOPATH/src/github.com/sriramy
git clone git@github.com:sriramy/perf-scripts.git
```

## Mount debugfs
sudo mount -t debugfs -o mode=755 nodev /sys/kernel/debug

## Running scripts
cd ~sriramy/xc/xcluster
. Envsettings
cdo packet

eval $($XCLUSTER env | grep -E '^KERNELDIR|__kver')
export PERF_EXEC_PATH=$KERNELDIR/$__kver/tools/perf/

$PERF_EXEC_PATH/perf report -f --kallsyms kallsyms
$PERF_EXEC_PATH/perf script -f --kallsyms kallsyms

$PERF_EXEC_PATH/perf script -f -g python
$PERF_EXEC_PATH/perf script -f -s perf-script.py --kallsyms kallsyms
$PERF_EXEC_PATH/perf script -f -s tx-latency.py --kallsyms kallsyms

hotspot --kallsyms kallsyms

## Usage
Basic tests;
```
test -n "$log" || log=/tmp/$USER/xc-perf-scripts.log
./perf.sh test > $log
```

It is *recommended* to setup `xcluster` in a
[netns](https://github.com/Nordix/xcluster/blob/master/doc/netns.md)
for these tests.

Setup xcluster;
```
XCLUSTER_HOME=$HOME/xc/xcluster
GIT_TOP=$(git rev-parse --show-toplevel)

cd $XCLUSTER_HOME
. ./Envsettings
export XCLUSTER_OVLPATH=$XCLUSTER_HOME/ovl:$GIT_TOP/test/ovl
cd -
```
