#!/usr/bin/bash

BASE=$(whiptail --title  "Base user" --inputbox  "What is your base user's name?" 10 60 3>&1 1>&2 2>&3)
mkdir -p /opt/judge/bin
chown -R $BASE:$BASE /opt/judge
gcc container.c -o /opt/judge/bin/container
chmod ug+s /opt/judge/bin/container
mkdir -p /opt/judge/container/empty
cd /opt/judge/container/
tar cf - /etc | tar xf -
tar cf - /dev | tar xf -
tar cf - /root | tar xf -
mkdir var

useradd -c 'judge user' -m -s /bin/bash judge
useradd -c 'judge executor' -d / -M -s /sbin/nologin exec
