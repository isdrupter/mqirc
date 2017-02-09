#!/bin/bash
# Proof of concept mqtt to irc bridge in shell
host='localhost'
user='admin'
ident='admin'
password=''
topic='data/out'

mkfifo tkout >/dev/null 2>&1
(sleep 3;echo '/join #mqtt' ;\
mosquitto_sub -h $host\
 -u $user -P $password \
-t "$topic" -q 0)|base64 -d 2>/dev/null |tee|./irctk -i 0\
 bot@localhost:6667 '#mqtt' >tkout &

echo 'daemon running'
authuser="shellz"
while read "line";do
  if echo "$line"|grep "\[#mqtt\]"|grep "<$authuser>"|grep -q "@cmd";then
    echo $line|sed "s:\[\#mqtt\] <$authuser> @cmd::"|\
    sed 's/@cmd//'|base64 -w 0|mosquitto_pub \
    -h $host -u $user -i $ident -P $password -t data/in -q 1 -s
fi
done <tkout

