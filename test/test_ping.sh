ip link delete tap0
ip tuntap add dev tap0 mode tap user $USER
ip addr add 192.0.2.1/24 dev tap0
ip link set tap0 up