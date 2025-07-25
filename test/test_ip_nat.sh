bash -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
iptables -A FORWARD -o tap0 -j ACCEPT
iptables -A FORWARD -i tap0 -j ACCEPT
iptables -t nat -A POSTROUTING -s 192.0.2.0/24 -o eth0 -j MASQUERADE