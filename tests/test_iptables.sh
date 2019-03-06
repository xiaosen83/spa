#!/bin/bash

iptables -F

iptables -P OUTPUT ACCEPT
iptables -P INPUT DROP
iptables -P FORWARD ACCEPT

iptables -X KNOCKING
iptables -N KNOCKING
iptables -X LOGNEW
iptables -N LOGNEW

iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -j LOGNEW

iptables -I LOGNEW -p tcp -m tcp -m tcp -s 10.103.61.0/24 -m state --state NEW  -j LOG --log-level 1 --log-prefix "cwang-new: "
iptables -A LOGNEW -j KNOCKING

iptables -I KNOCKING -p tcp -s 10.103.61.0/24 -j ACCEPT
iptables -A KNOCKING -j DROP



#####add rule#########
#iptables -I LOGNEW 1 -p tcp --dport 22 -m tcp -m tcp -s 10.103.220.130 -m state --state NEW  -j LOG --log-level 1 --log-prefix "cwang-new: "
#iptables -I KNOCKING 1 -p tcp --dport 22 -s 10.103.220.130 -j ACCEPT

#####delete rule######
#sudo iptables -D LOGNEW -s 10.103.220.130/32 -p tcp --dport 22 -m tcp -m tcp -m state --state NEW -j LOG --log-prefix "cwang-new: " --log-level 1
#sudo iptables -D KNOCKING -s 10.103.220.130/32 -p tcp --dport 22 -j ACCEPT