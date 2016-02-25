#!/bin/bash

echo "Start load test. We will connect to web-server 1000 times."
maxi=1000
i=0
while [[ $i -lt $maxi ]]
do
	echo "Test: $i"
	curl -s -0 -X GET 127.0.0.1:12345?i=$i > /dev/null
	let	"i += 1"
	
	let "p = i % 50"
	if [[ $p -eq 0 ]]
	then
		echo "Test #$i"
	fi
done

echo "End load test"
