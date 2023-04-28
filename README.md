# perf-scripts
Some random perf scripts that I use

## Mount debugfs
sudo mount -t debugfs -o mode=755 nodev /sys/kernel/debug

## General directions
sudo -s
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

## netdev-times

