#!/bin/bash

echo "Setting up IP addresses..."
sudo ip addr add 10.0.0.1/32 dev lo 2>/dev/null
sudo ip addr add 192.168.1.10/32 dev lo 2>/dev/null
sudo ip addr add 192.168.1.11/32 dev lo 2>/dev/null

echo "Starting backend servers on 8080..."
setsid nc -lk 192.168.1.10 8080 > server_10.log 2>&1 &
setsid nc -lk 192.168.1.11 8080 > server_11.log 2>&1 &

echo "Environment Ready!"
echo "VIP: 10.0.0.1:80"
echo "RIP1: 192.168.1.10:8080"
echo "RIP2: 192.168.1.11:8080"
echo "Check logs at server_*.log"
