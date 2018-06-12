microps
=======

Micro TCP/IP Protocol Stack

## build

```
 $ make
```

## usage

***Note: Currently the address information is written directly in the source code***

example (echo_server):

```
 $ sudo ./echo_server
```

arp test:

```
 $ sudo arping 192.168.0.100
```

ping test:

```
 $ ping 192.168.0.100
```

echo test:

```
 $ nc -u 192.168.0.100 7
```

## microps DPDK effective version

### preparation

build DPDK and setup your machine to use DPDK. (please see http://dpdk.org/)

### build

```
 $ USE_DPDK=1 make
```

### usage

example (echo_server):  

```
$ sudo ./build/echo_server
```

ping test:  

```
$ ping 10.0.0.1
```
