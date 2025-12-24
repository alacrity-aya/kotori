#!/bin/bash

echo "Cleaning up IP addresses..."
sudo ip addr del 10.0.0.1/32 dev lo 2>/dev/null
sudo ip addr del 192.168.1.10/32 dev lo 2>/dev/null
sudo ip addr del 192.168.1.11/32 dev lo 2>/dev/null

echo "Stopping nc backend processes..."
sudo fuser -k 8080/tcp 2>/dev/null
rm -f *.log

echo "Cleanup complete."
