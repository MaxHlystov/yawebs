#!/bin/bash

if [[ $# -ge 1 ]]
then
	maxi=$1
else
	maxi=1000
fi

echo "Start load test. We will connect to web-server $maxi times."


i=0
while [[ $i -lt $maxi ]]
do
	curl -s -0 -X GET 127.0.0.1:12345?i=$i > /dev/null
	let	"i += 1"
	
	let "p = i % 50"
	if [[ $p -eq 0 ]]
	then
		echo "Test #$i"
	fi
done

echo "End load test"
