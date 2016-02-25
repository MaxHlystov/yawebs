/* Yawebs (yet another web server) - is simple multiprocess web-server.
*/

#ifndef YAWEBS_HPP

	#define YAWEBS_HPP
	
	#include <stdarg.h>
	#include <stdio.h>
	#include <stdlib.h>
	#include <errno.h>
	#include <string.h>
	#include <getopt.h>
	#include <pthread.h>
	#include <time.h>
	#include <unistd.h>
	#include <syslog.h>
	#include <fcntl.h>
	#include <signal.h>
	#include <sys/types.h>
	#include <sys/stat.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>

	#include <queue>
	
	//#define USESYSLOG
	
	#define VERSION "001"

	#define LOCK_FILE_NAME "/tmp/yawebs.lock"
	
	#define PROCESSNUM 4
	#define THREADNUM 2
	
	#define STRSIZE 256
	#define BUFSIZE 8096

	#define OK 200
	#define BADREQUEST 400
	#define FORBIDDEN 403
	#define NOTFOUND  404
	#define INTERNALSERVERERROR 500
	#define NOTIMPLEMENTED 501

	const char* http_header = "HTTP/1.0 %d %s\nContent-Length: %d\nConnection: close\nContent-Type: text/html\n\n";
	const char* Forbidden_message = "<html><head>\n<title>403 Forbidden</title>\n</head><body>\n<h1>Forbidden</h1>\nThe requested URL, file type or operation is not allowed on yawebs.\n</body></html>\n";
	const char* NotFound_message = "<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\nThe requested URL was not found on yawebs.\n</body></html>\n";
	
	struct WebExt{
		const char *ext;
		const char *filetype;
	};
	
	// arguments for function
	struct webthreadargs{
		int thrd_num; // thread number
	};
	
	typedef std::queue<int> fd_queue_type; // queue for incoming socket descriptors. it reads by web-worker-threads to manage to.
	
	class Yawebs{
		private:
			char* ip_str;	// ip addres of the server
			char* dir;		// root directory of documents
			int port;			// port of the server
			
			Yawebs(): ip_str(NULL), dir(NULL), port(0) {};
			
		public:
			Yawebs(char* ip_str, char* dir, int port);
			virtual ~Yawebs() {};
	};
	
	// Parse args and returned needed values.
	// Parameters:
	//	- argc, argv - from main function;
	//	- ip_str - will be filled with string of ip-adress. You will have to free memory, after use.
	//	- port - will be filled with port.
	//	- dir - will be filled with string of directory with documents.
	//		There is always '/' on the end of the dir.
	//		You will have to free memory, after use.
	// If error showes user a message and return -1.
	// If success return 0.
	int ParseArgs(int argc, char** argv, char** ip_str, int* port, char**dir);
	int ParseArgs_Sort(int argc, char** argv, char** ip_str, int* port, char**dir);
	
	// Shows help message to user
	void ShowHelp(void);
	
	// Make current process a daemon
	int Daemonize(char* dir);
	
	// make some clean operations
	void EndServer(void);
	
	// socket descriptor passing
	ssize_t sock_fd_read(int sock, void *buf, ssize_t bufsize, int *fd);
	ssize_t sock_fd_write(int sock, void *buf, ssize_t buflen, int fd);
	
	// Manage worker process
	void StartWorker(int prc, int socket_in);
	
	// make some clean operations
	void EndWorker(void);
	
	// In infinit cycle try to get socket fd, and then WebProcess it
	// *arg - is a structure webthreadargs (see above)
	void* Thread_WebProcess(void *arg);
	
	// read HTTP query from socket and answer it
	// Args:
	//	thrd_num - number of calling thread;
	//	con_num - number of connection of calling thread;
	//	fd - socket descriptor.
	void WebProcess(int thrd_num, int con_num, int fd);
	
	// post HTTP message to socket
	void WebMessage(int type, int socket_fd);
	
	// Catch signals for master
	void master_signal_handler(int sig);
	
	// Catch signals for worker
	void worker_signal_handler(int sig);
	
	// Matches string to ip address (*.*.*.*)
	// If cs is an ip address it returns 1.
	// Otherwise it returns 0.
	int is_ip(const char* const cs);
	
	// Checks is path to dir not contains "..".
	// Checks is dir exists.
	// If dir is correct, return 1.
	// else return 0.
	int is_good_web_dir(const char* dir);
	
	// Start working process:
	//	watch incoming messages, and process received sockets.
	void StartWork();
	
	// Logging to file or syslog (if define USESYSLOG)
	// Args:
	//	worker - number of worker 0..PROCESSNUM, or -1 if it is main process;
	//	type - by priority of syslog() arg;
	//	format,... - format string and args (analogue to printf, syslog).
	void mylog(int type, const char* format, ...);
	void criticallog(const char* format, ...);
	void mylog_init(void);
	void mylog_end(void);
#endif
