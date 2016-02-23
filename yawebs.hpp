/* Yawebs (yet another web server) - is simple multiprocess web-server.
*/

#ifndef YAWEBS_HPP

	#define YAWEBS_HPP
	
	#include <stdio.h>
	#include <stdlib.h>
	#include <errno.h>
	#include <string.h>
	#include <getopt.h>
	#include <unistd.h>
	#include <syslog.h>
	#include <fcntl.h>
	#include <signal.h>
	#include <sys/types.h>
	#include <sys/stat.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>

	#define VERSION "001"

	#define PROCESSNUM 4
	
	#define STRSIZE 256
	#define BUFSIZE 8096

	#define OK 200
	#define BADREQUEST 400
	#define FORBIDDEN 403
	#define NOTFOUND  404
	#define INTERNALSERVERERROR 500
	#define NOTIMPLEMENTED 501

	struct WebExt{
		const char *ext;
		char *filetype;
	};
	
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

	// Shows help message to user
	void ShowHelp(void);
	
	// Make current process a daemon
	int Daemonize(char* dir);
	
	// socket descriptor passing
	ssize_t sock_fd_read(int sock, void *buf, ssize_t bufsize, int *fd);
	ssize_t sock_fd_write(int sock, void *buf, ssize_t buflen, int fd);
	
	// Manage worker process
	void StartWorker(int prc, int socket_in);
	
	void WebProcess(int prc, int con_num, int fd);
	
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
#endif