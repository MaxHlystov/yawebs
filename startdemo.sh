#!/bin/bash
webdir=`pwd`
$webdir/final -h 127.0.0.1 -p 12345 -d "$webdir" > /dev/null
echo "Wait while server has started..."
sleep 1
echo "To test in command line use: curl -0 -X GET 127.0.0.1:12345"
echo "To test in your web browser go to address: 127.0.0.1:12345"
echo
wspid=`cat "/tmp/yawebs.lock"`
echo "To stop server use: stopdemo.sh"
echo "                or: kill $wspid"
echo

