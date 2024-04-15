#!/usr/bin/bash

useradd -c 'judge user' -m -s /bin/bash judge
useradd -c 'judge executor' -d / -M -s /sbin/nologin judgeexec
useradd -c 'judge compiler' -d /home/judges/compile -M -s /sbin/nologin judgecompile
adduser judge judgecompile

mkdir -p /opt/judge/container
cd /opt/judge/container
mkdir empty var
mkdir -p home/judges/compile
tar cf - /etc | tar xf -
tar cf - /dev | tar xf -
tar cf - /root | tar xf -
