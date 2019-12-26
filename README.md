microps
=======

Tiny TCP/IP protocol stack for lectures.

If you love the Go language, [see here](https://github.com/pandax381/lectcp).

## Features

Supports multiple raw access methods.

+ TUN/TAP
+ PF_PACKET (Linux)
+ BPF (macOS)

Supports multiple link protocols.

+ Ethernet
+ SLIP

Other features.

+ Supports multiple interfaces
+ Supports IP forwarding
+ Automatic IP configuration by DHCP client

## Build

Build sample applications and test programs

```
$ make
``` 

with debug output

```
$ CFLAGS=-DDEBUG make
```

## Sample applications

TCP Echo server (with dynamic address)

```
 $ sudo apps/tcp_echo eth0 00:00:de:ad:be:ef dhcp
```

UDP Echo server (with static address)

```
 $ sudo apps/tcp_echo eth0 static 172.16.100.2 255.255.255.0 172.16.100.1
```

Both application listen on port 7.
 
## Test programs

test/raw_test
```
$ sudo test/raw_test eth0
```

test/ethernet_test
```
$ sudo test/ethernet_test eth0
```

test/slip_test
```
$ sudo test/slip_test /dev/ttyXXX
```

test/arp_test
```
$ sudo test/arp_test eth0 00:00:de:ad:be:ef 172.16.100.2
```

## RAW devices

You can select a Link-Level RAW device.

+ raw_socket
+ raw_tap
+ raw_bpf

It can change in the Makefile.

## License

microps is under the MIT License: See [LICENSE](./LICENSE) file.
