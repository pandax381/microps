microps
=======

Micro TCP/IP Protocol Stack

build:

 $ make


usage:

 $ sudo ./echo_server device-name ethernet-addr ip-addr netmask default-gw


example (echo_server):

 $ sudo ./echo_server eth0 02:00:00:00:00:01 192.168.0.100 255.255.255.0 192.168.0.1


arp test:

 $ sudo arping 192.168.0.100


ping test:

 $ ping 192.168.0.100


echo test:

 $ nc -u 192.168.0.100 7

