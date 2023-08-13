microps
=======

microps is an implementation of a small TCP/IP protocol stack for learning.

+ If you love the Go language: https://github.com/pandax381/lectcp
+ Porting to xv6: https://github.com/pandax381/xv6-net
+ Porting to MikanOS: https://github.com/pandax381/mikanos-net

Documents

+ [Step by Step Development Guides](https://drive.google.com/drive/folders/1k2vymbC3vUk5CTJbay4LLEdZ9HemIpZe) (Japanese) 

## Features

Abstraction Layer

- [x] Physical device abstraction
  - [x] Define structure for physical device abstraction (`struct net_device`)
  - [x] Support multiple link protocols and physical devices
- [x] Logical interface abstraction
  - [x] Define structure for logical interface abstraction (`struct net_iface`)
  - [x] Support multiple address family and logical interfaces

Devices

- [x] Null
- [x] Loopback
- [x] Ethernet
  - [x] TUN/TAP (Linux)
  - [x] PF_PACKET (Linux)

Protocols

- [x] Ethernet
- [x] ARP
- [x] IP
- [x] ICMP
- [x] UDP
- [x] TCP

API

- [x] Socket like API

Logs

```
18:43:46.153 [I] net_protocol_register: registerd, type=ARP(0x0806) (net.c:223)
18:43:46.153 [I] net_timer_register: registerd: ARP Timer interval={1, 0} (net.c:257)
18:43:46.153 [I] net_protocol_register: registerd, type=IP(0x0800) (net.c:223)
18:43:46.153 [I] ip_protocol_register: registerd, type=ICMP(0x01) (ip.c:440)
18:43:46.153 [I] ip_protocol_register: registerd, type=UDP(0x11) (ip.c:440)
18:43:46.153 [I] ip_protocol_register: registerd, type=TCP(0x06) (ip.c:440)
18:43:46.153 [I] net_timer_register: registerd: TCP Timer interval={0, 100000} (net.c:257)
18:43:46.153 [I] net_device_register: registerd, dev=net0, type=0x0000 (net.c:74)
18:43:46.153 [D] null_init: initialized, dev=net0 (driver/null.c:46)
18:43:46.153 [I] net_device_register: registerd, dev=net1, type=0x0001 (net.c:74)
18:43:46.153 [D] loopback_init: initialized, dev=net1 (driver/loopback.c:49)
18:43:46.153 [I] ip_route_add: network=127.0.0.0, netmask=255.0.0.0, nexthop=0.0.0.0, iface=127.0.0.1 dev=net1 (ip.c:136)
18:43:46.153 [I] ip_iface_register: registerd: dev=net1, unicast=127.0.0.1, netmask=127.0.0.1, broadcast=255.0.0.0 (ip.c:233)
18:43:46.153 [I] net_device_register: registerd, dev=net2, type=0x0002 (net.c:74)
18:43:46.153 [D] ether_tap_init: ethernet device initialized, dev=net2 (driver/ether_tap_linux.c:174)
18:43:46.153 [I] ip_route_add: network=192.0.2.0, netmask=255.255.255.0, nexthop=0.0.0.0, iface=192.0.2.2 dev=net2 (ip.c:136)
18:43:46.153 [I] ip_iface_register: registerd: dev=net2, unicast=192.0.2.2, netmask=192.0.2.2, broadcast=255.255.255.0 (ip.c:233)
18:43:46.153 [I] ip_route_add: network=0.0.0.0, netmask=0.0.0.0, nexthop=192.0.2.1, iface=192.0.2.2 dev=net2 (ip.c:136)
18:43:46.153 [D] net_run: open all devices... (net.c:314)
18:43:46.153 [I] net_device_open: dev=net2, state=up (net.c:92)
18:43:46.153 [I] net_device_open: dev=net1, state=up (net.c:92)
18:43:46.153 [I] net_device_open: dev=net0, state=up (net.c:92)
18:43:46.153 [D] net_run: create background thread... (net.c:318)
18:43:46.154 [D] net_run: running... (net.c:324)
18:43:57.931 [D] ether_poll_helper: dev=net2, type=ARP(0x0806), len=42 (ether.c:127)
        src: 0e:4e:af:bc:64:c6
        dst: ff:ff:ff:ff:ff:ff
       type: 0x0806 (ARP)
18:43:57.931 [D] net_input_handler: queue pushed (num:1), dev=net2, type=ARP(0x0806), len=28 (net.c:191)
18:43:57.931 [D] net_thread: queue poped (num:0), dev=net2, type=ARP(0x0806), len=28 (net.c:286)
18:43:57.931 [D] arp_input: dev=net2, opcode=Request(0x0001), len=28 (arp.c:239)
        hrd: 0x0001
        pro: 0x0800
        hln: 6
        pln: 4
         op: 0x0001 (Request)
        sha: 0e:4e:af:bc:64:c6
        spa: 192.0.2.1
        tha: 00:00:00:00:00:00
        tpa: 192.0.2.2
18:43:57.931 [D] arp_cache_insert: INSERT: pa=192.0.2.1, ha=0e:4e:af:bc:64:c6 (arp.c:163)
18:43:57.931 [D] arp_reply: dev=net2, opcode=Reply(0x0002), len=28 (arp.c:213)
        hrd: 0x0001
        pro: 0x0800
        hln: 6
        pln: 4
         op: 0x0002 (Reply)
        sha: 00:00:5e:00:53:01
        spa: 192.0.2.2
        tha: 0e:4e:af:bc:64:c6
        tpa: 192.0.2.1
18:43:57.931 [D] net_device_output: dev=net2, type=ARP(0x0806), len=28 (net.c:156)
18:43:57.931 [D] ether_transmit_helper: dev=net2, type=ARP(0x0806), len=60 (ether.c:101)
        src: 00:00:5e:00:53:01
        dst: 0e:4e:af:bc:64:c6
       type: 0x0806 (ARP)
18:43:57.931 [D] ether_poll_helper: dev=net2, type=IP(0x0800), len=98 (ether.c:127)
        src: 0e:4e:af:bc:64:c6
        dst: 00:00:5e:00:53:01
       type: 0x0800 (IP)
18:43:57.931 [D] net_input_handler: queue pushed (num:1), dev=net2, type=IP(0x0800), len=84 (net.c:191)
18:43:57.932 [D] net_thread: queue poped (num:0), dev=net2, type=IP(0x0800), len=84 (net.c:286)
18:43:57.932 [D] ip_input: dev=net2, iface=192.0.2.2, protocol=ICMP(0x01), len=84 (ip.c:303)
        vhl: 0x45 [v: 4, hl: 5 (20)]
        tos: 0x00
      total: 84 (payload: 64)
         id: 41026
     offset: 0x4000 [flags=2, offset=0]
        ttl: 64
   protocol: 1 (ICMP)
        sum: 0x1663 (0x1663)
        src: 192.0.2.1
        dst: 192.0.2.2
18:43:57.932 [D] icmp_input: 192.0.2.1 => 192.0.2.2, type=Echo(8), len=64, iface=192.0.2.2 (icmp.c:100)
       type: 8 (Echo)
       code: 0
        sum: 0xb692 (0xb692)
         id: 55
        seq: 1
18:43:57.932 [D] icmp_output: 192.0.2.2 => 192.0.2.1, type=EchoReply(0), len=64 (icmp.c:138)
       type: 0 (EchoReply)
       code: 0
        sum: 0xbe92 (0xbe92)
         id: 55
        seq: 1
18:43:57.932 [D] ip_output_core: dev=net2, iface=192.0.2.1, protocol=ICMP(0x01), len=84 (ip.c:357)
        vhl: 0x45 [v: 4, hl: 5 (20)]
        tos: 0x00
      total: 84 (payload: 64)
         id: 128
     offset: 0x0000 [flags=0, offset=0]
        ttl: 255
   protocol: 1 (ICMP)
        sum: 0x3725 (0x3725)
        src: 192.0.2.2
        dst: 192.0.2.1
18:43:57.932 [D] arp_resolve: resolved, pa=192.0.2.1, ha=0e:4e:af:bc:64:c6 (arp.c:301)
18:43:57.932 [D] net_device_output: dev=net2, type=IP(0x0800), len=84 (net.c:156)
18:43:57.932 [D] ether_transmit_helper: dev=net2, type=IP(0x0800), len=98 (ether.c:101)
        src: 00:00:5e:00:53:01
        dst: 0e:4e:af:bc:64:c6
       type: 0x0800 (IP)
^C18:44:01.605 [D] net_shutdown: terminate background thread... (net.c:334)
18:44:01.606 [D] net_shutdown: close all devices... (net.c:341)
18:44:01.606 [I] net_device_close: dev=net2, state=down (net.c:110)
18:44:01.606 [I] net_device_close: dev=net1, state=down (net.c:110)
18:44:01.606 [I] net_device_close: dev=net0, state=down (net.c:110)
18:44:01.606 [D] net_shutdown: shutdown (net.c:345)
```

## Tutorial

#### 1. Build

```
$ git clone git@github.com:pandax381/microps.git
$ cd microps
$ make
```

#### 2. Prepare Tap device

```
$ sudo ip tuntap add mode tap user $USER name tap0
$ sudo ip addr add 192.0.2.1/24 dev tap0
$ sudo ip link set tap0 up
```

> It is temporary and will disappear after reboot.

#### 3. Run sample application

```
$ ./app/tcps.exe 7
11:48:55.884 [I] net_protocol_register: registerd, type=ARP(0x0806) (net.c:223)
11:48:55.884 [I] net_timer_register: registerd: ARP Timer interval={1, 0} (net.c:257)
11:48:55.884 [I] net_protocol_register: registerd, type=IP(0x0800) (net.c:223)
...
11:48:55.884 [D] net_run: running... (net.c:324)
11:48:55.884 [D] tcp_bind: success: addr=0.0.0.0, port=7 (tcp.c:1156)
```

> TCP Echo Server start on port 7. (default address is 192.0.2.2/24)

#### 4. Test (Operate in another terminal)

+ Ping

```
$ ping 192.0.2.2
PING 192.0.2.2 (192.0.2.2) 56(84) bytes of data.
64 bytes from 192.0.2.2: icmp_seq=1 ttl=255 time=0.660 ms
64 bytes from 192.0.2.2: icmp_seq=2 ttl=255 time=0.688 ms
64 bytes from 192.0.2.2: icmp_seq=3 ttl=255 time=0.574 ms
...
```

+ TCP communication
```
$ nc 192.0.2.2 7
foo
foo
bar
bar
```

> Sending text will be sent back by the Echo Server.

## License

microps is under the MIT License: See [LICENSE](./LICENSE) file.
