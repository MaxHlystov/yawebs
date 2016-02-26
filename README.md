# Yawebs
Yet another web server

Yawebs is simple HTTP 1.0 server works in several process and threads.
It waits GET requests (POST - is planned in future releases) and answer with 200, 403 and 404.
Supports following files and MIME-types:
	- gif, image/gif,
	- jpg, image/jpg,
	- jpeg,image/jpeg,
	- png, image/png,
	- ico, image/ico,
	- htm, text/html,
	- html,text/html,
	- txt, text/html.
It not shows items of directories, only accessable files content.

When starts yawebs daemonize and create four worker process.
Each of them creates two worker threads.
Get incoming connection master process pass it to some worker process,
which runs worker thread to deal with incoming request.

-----------
Compile:
cmake .
make

Demo:
- start demo server: ./startdemo.sh
- you cat open link in web browser: http://127.0.0.1:12345
- in command line: curl -0 -X GET 127.0.0.1:12345
- load test (runs curl 100 times): ./loadtest.sh
- end demo server: ./stopdemo.sh 

Useage:
- ./final --help
- ./final --version
- ./final -h "ip address to listen to" -p "port" -d "path to web directory"

To debug use option --debug 20 or -g 20

-----------
In plans:
- user can specify counts of running worker processes and threads.

- POST requests

- Keep-alive
Under HTTP 1.0, there is no official specification for how keepalive operates. It was, in essence, added to an existing protocol. If the client supports keep-alive, it adds an additional header to the request:
Connection: keep-alive
Then, when the server receives this request and generates a response, it also adds a header to the response:
Connection: keep-alive
Following this, the connection is not dropped, but is instead kept open. When the client sends another request, it uses the same connection. This will continue until either the client or the server decides that the conversation is over, and one of them drops the connection.
