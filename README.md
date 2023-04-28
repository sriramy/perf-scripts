# perf-scripts
Some random perf scripts that I use

## Mount debugfs
sudo mount -t debugfs -o mode=755 nodev /sys/kernel/debug

## Using xcluster default kernel settings
cd $XCLUSTER_HOME
. Envsettings
eval $($XCLUSTER env | grep -E '^KERNELDIR|__kver')
export PERF_EXEC_PATH=$KERNELDIR/$__kver/tools/perf/
$PERF_EXEC_PATH/perf script -f -g python

## netdev-times
'''
cd netdev-times
./bin/netdev-times-report -i <perf.data>
'''
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

## tx-latency
'''
cd tx-latency
./bin/tx-latency -i <perf.data>

         queue            xmit            free
     7.433254sec        0.008msec        0.731msec
     7.434754sec        0.006msec        0.519msec
     7.434814sec        0.027msec        0.561msec
'''