# perf-scripts
Some random perf scripts that I use

## Kernel config
Note: **PERF_EXEC_PATH must be set if custom kernel is used.**

The following config needs to be enabled to get kprobe/uprobe/ftrace/dynamic trace support.
```
CONFIG_KPROBES=y
CONFIG_KPROBES_ON_FTRACE=y
CONFIG_UPROBES=y
CONFIG_KRETPROBES=y
CONFIG_KRETPROBE_ON_RETHOOK=y
CONFIG_HAVE_KPROBES=y
CONFIG_HAVE_KRETPROBES=y
CONFIG_HAVE_RETHOOK=y
CONFIG_RETHOOK=y
CONFIG_HAVE_FUNCTION_TRACER=y
CONFIG_HAVE_FUNCTION_GRAPH_TRACER=y
CONFIG_HAVE_DYNAMIC_FTRACE=y
CONFIG_HAVE_DYNAMIC_FTRACE_WITH_REGS=y
CONFIG_HAVE_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y
CONFIG_FTRACE=y
CONFIG_FUNCTION_TRACER=y
CONFIG_FUNCTION_GRAPH_TRACER=y
CONFIG_DYNAMIC_FTRACE=y
CONFIG_DYNAMIC_FTRACE_WITH_REGS=y
CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y
CONFIG_DYNAMIC_FTRACE_WITH_ARGS=y
CONFIG_KPROBE_EVENTS=y
```


## Mount debugfs
sudo mount -t debugfs -o mode=755 nodev /sys/kernel/debug

## Using xcluster tests
It is *recommended* to setup `xcluster` in a
[netns](https://github.com/Nordix/xcluster/blob/master/doc/netns.md)
for these tests.

```
cd test/ovl/perf
. ./Envsettings
./perf.sh build
./perf.sh test start
```

## netdev-times
```
cd netdev-times
./bin/netdev-times-report -i /tmp/perf.data --kallsyms /tmp/kallsyms

RX
==
7.309333sec cpu=0
  irq_entry(+0.000msec irq=26:virtio1-input.0)
         |
  softirq_entry(+0.031msec)
         |
         |---netif_receive_skb(+0.146msec skb=ffff888005aa6300 len=56)
         |            |
         |      skb_copy_datagram_iovec(+0.197msec 0:swapper)
         |
  napi_poll_exit(+0.202msec eth1)

TX
==
   dev    len      Qdisc               netdevice             free
   eth0    70      7.406276sec        0.009msec             0.199msec
   eth1    70      7.406223sec        0.045msec             0.243msec
  net11   114      7.646432sec        0.108msec             0.210msec
  net13   114      7.646437sec        0.101msec             0.219msec
```

## tx-latency
```
cd tx-latency
./bin/tx-latency-report -i /tmp/perf.data --kallsyms /tmp/kallsyms

         queue            xmit            free
     7.433254sec        0.008msec        0.731msec
     7.434754sec        0.006msec        0.519msec
     7.434814sec        0.027msec        0.561msec
```

## task-analyzer
```
cd task-analyzer
./bin/task-analyzer-report -i /tmp/perf.data --kallsyms /tmp/kallsyms
