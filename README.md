# Prerequisites

You need to have flex and bison installed in order to compile this project.
Also, needless to say, compiler tools and GNU make must be available. To
actually communicate with real network interfaces, you also need netmap, but
more on that later.

# Compilation

To compile, type `make -j4` where the number after `-j` is the number of cores.

To run unit tests, run `make unit`. Note that using `-j` with `make unit` is
not recommended.

# Netmap support

To compile with netmap support, edit the file `opts.mk` (generated as empty
file automatically after successful `make`), and add the lines:

```
WITH_NETMAP=yes
NETMAP_INCDIR=/home/YOURUSERNAME/netmap/sys
```

But before this, you need to clone netmap:

```
cd /home/YOURUSERNAME
git clone https://github.com/luigirizzo/netmap
cd netmap
./configure --no-drivers
make
insmod ./netmap.ko
```

Successfully compiling netmap requires that you have your kernel headers
installed.

# Netmap drivers

If you want higher performance, you can compile netmap with drivers:

```
cd /home/YOURUSERNAME
rm -rf netmap
git clone https://github.com/luigirizzo/netmap
cd netmap
./configure
make
rmmod netmap
rmmod ixgbe
rmmod i40e
insmod ./netmap.ko
insmod ./ixgbe-5.0.4/src/ixgbe.ko
insmod ./i40e-2.0.19/src/i40e.ko
```

Adjust paths as needed to have the correct version of the driver.

# Netmap testing

Then, after netmap is installed, compile with `make -j4` as usual.

You can try netmap with the following commands to be run in two terminal
windows:

```
./synproxy/netmapproxy vale0:1{0 vale1:1
taskset -c 3 ./synproxy/netmapsend vale0:1}0
```

# Netmap with full kernel sources

Some netmap drivers require full kernel sources. On Ubuntu 16.04 LTS, they
can be installed in the following way: first, uncomment deb-src lines in
`/etc/apt/sources.list`. Then, type these commands:

```
cd /home/YOURUSERNAME
apt-get update
apt-get source linux-image-$(uname -r)
rm -rf netmap
git clone https://github.com/luigirizzo/netmap
cd netmap
./configure --kernel-sources=/home/WHATEVER/linux-hwe-4.8.0
rmmod netmap
insmod ./netmap.ko
```

Then, you may load for example netmap specific veth driver:

```
cd /home/YOURUSERNAME/netmap
rmmod veth
insmod ./veth.ko
```

# Testing with veth

Veth interfaces have poor performance. The netmap-specific veth driver is
supposed to help this, but actually on the test laptop where it was tested, it
made things even slower. Nevertheless, if you want to use veth, you can do it
in this way:

```
ip link add veth0 type veth peer name veth1
ip link add veth2 type veth peer name veth3
ifconfig veth0 up
ifconfig veth1 up
ifconfig veth2 up
ifconfig veth3 up
```

Then run these two commands in two terminal windows:
```
./synproxy/netmapproxy netmap:veth1 netmap:veth2
taskset -c 3 ./synproxy/netmapsend netmap:veth0
```

# Testing with real network interfaces

Let's assume you have eth0 and eth1 inserted as an inline pair to an Ethernet
network. You want to bridge traffic between eth0 and eth1 and SYN proxy
incoming connections from eth1 into eth0. You must first set both interfaces to
promiscuous mode:

```
ip link set eth0 promisc on
ip link set eth1 promisc on
```

It is also recommended to turn off offloads:

```
ethtool -K eth0 rx off tx off tso off gso off gro off lro off
ethtool -K eth1 rx off tx off tso off gso off gro off lro off
```

If the `ethtool` reports an error about being unable to change certain offload,
remove the offload setting from the command line and try with the other
settings.

It is also recommended to turn off flow control:

```
ethtool -A eth0 rx off tx off autoneg off
ethtool -A eth1 rx off tx off autoneg off
```

Then you must start netmapproxy:
```
./synproxy/netmapproxy netmap:eth0 netmap:eth1
```

Note that the order interfaces are specified matters. The first is the LAN
interface. The second is the WAN interface. Only connections from WAN to LAN
are SYN proxied.
