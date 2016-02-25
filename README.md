# yawebs
Yet another web server

Compile:
cmake .
make

Demo:
- start demo server: ./startdemo.sh
- you cat open link in web browser: http://127.0.0.1:12345
- in command line: curl -0 -X GET 127.0.0.1:12345
- load test (runs curl 100 times): ./loadtest.sh
- end demo server: ./stopdemo.sh 

Useage
./final --help
./final --version
./final -h <ip address to listen to> -p <port> -d <web directory>

To debug use option --debug 20
