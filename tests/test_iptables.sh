#!/bin/bash

sudo iptables -F
sudo iptables -A INPUT -s 10.103.61.0/24 -j ACCEPT
sudo iptables -A INPUT -s 127.0.0.1 -j ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD ACCEPT