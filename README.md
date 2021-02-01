microps
=======

microps is an implementation of a small TCP/IP protocol stack for learning.

+ Old master branch: https://github.com/pandax381/microps/tree/master
+ If you love the Go language: https://github.com/pandax381/lectcp
+ Porting to xv6: https://github.com/pandax381/xv6-net


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

Protocols

- [x] Ethernet
- [x] ARP
- [x] IP
- [x] ICMP
- [x] UDP
- [x] TCP

API

- [x] Socket like API

## License

microps is under the MIT License: See [LICENSE](./LICENSE) file.
