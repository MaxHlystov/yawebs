#include "yawebs.hpp"

// debug level is set by --debug option
// 0 - non debug messages, 1 - main(), 2 - args, 3 - daemonize,
// 4 - signal check, 5 - working process creation and maintenance,
// 6 - working process debug, 7 - socket listening debug,
// 8 - soket fd passing, 9 -
static int debug_level = 20; 

pid_t m_pid = 0; // pid of master process

int prc_count = 0; // Number of working processes
pid_t prc[PROCESSNUM]; // PID's of working processes
int out_sock[PROCESSNUM]; // out socket pair to working process

int worker_num = 0; // number of current worker for logging

#ifndef USESYSLOG
int logfd; // descriptors of log files of master and workers
#endif

struct WebExt extensions [] = {
		{"gif", "image/gif" },
		{"jpg", "image/jpg" },
		{"jpeg","image/jpeg"},
		{"png", "image/png" },
		{"ico", "image/ico" },
		{"htm", "text/html" },
		{"html","text/html" },
		{"txt", "text/html" },  
		{0,0} };
		
int main(int argc, char** argv){
	char* ip_str = NULL;	// ip addres of the server
	char* dir = NULL;		// root directory of documents
	int port = 0;			// port of the server
	
	if(debug_level >= 1) printf("Start main()\n");
	
	int res = ParseArgs(argc, argv, &ip_str, &port, &dir);
	if(res < 0){
		return 1; // Error parse args
	}
	
	if(chdir(dir) == -1){ 
		fprintf(stderr, "Can't change to directory %s\n", dir);
		return 2;
	}

	if(debug_level >= 1) printf("Starts with args: ip \"%s\", port %d.\n\tWeb directory is \"%s\"\n", ip_str, port, dir);
	
	// Try to be a daemon
	if(debug_level >= 1) printf("Transformation to a daemon\n");
	
	res = fork();
	if(res == -1){
		perror("Could not fork");
		return 3;
	}
	if(res > 0){
		// It's a starter process. Exit to shell.
		if(debug_level >= 1) printf("End starter\n");
		return 0;
	}
	
	// It's a new master process. Process die, viva process!
	m_pid = getpid(); // pid of new master process
	worker_num = -1; // worker number for master process
	
	if(debug_level >= 1) printf("New porcess pid is %d\n", m_pid);
	
	res = Daemonize(dir);
	if(res != 0){
		if(debug_level >= 1) mylog(LOG_ERR, "Error demonizing with code %d. Finish work", res);
		return res;
	}
	
	// Create working process
	mylog(LOG_NOTICE, "Going to create %d work process", PROCESSNUM);
	
	int sv[2]; // socket pair
	while(prc_count < PROCESSNUM){
		if (socketpair(AF_LOCAL, SOCK_STREAM, 0, sv) < 0) {
			perror("socketpair");
			exit(1);
		}
		
		res = fork();
		if(res == -1){
			mylog(LOG_ERR, "Could not fork");
			return 4;
		}
		if(res == 0){
			// It's a worker process
			close(sv[0]);
			StartWorker(prc_count, sv[1]);
			exit(0);
		}
		
		// Main process
		prc[prc_count] = res;
		close(sv[1]);
        out_sock[prc_count] = sv[0];
		
		++prc_count;
	}
	
	// Starts listening and give out incoming sockets to work process
	mylog(LOG_NOTICE, "Listen on ip \"%s\", port %d. Web directory is \"%s\"", ip_str, port, dir);
	
	int listenfd = 0;
	if((listenfd = socket(AF_INET, SOCK_STREAM,0)) <0){
		mylog(LOG_ERR, "Could not create socket");
		exit(1);
	}
	
	static struct sockaddr_in serv_addr;
	serv_addr.sin_family = AF_INET;
	inet_pton(AF_INET, ip_str, &serv_addr.sin_addr);
	serv_addr.sin_port = htons(port);
	if(bind(listenfd, (struct sockaddr *)&serv_addr,sizeof(serv_addr)) <0){
		mylog(LOG_ERR,"Error binding socket on address %s:%d", ip_str, port);
		exit(1);
	}
	if(listen(listenfd, 0) < 0){
		mylog(LOG_ERR, "Error listen on address %s:%d", ip_str, port);
		exit(1);
	}
	
	int next_proc = 0; // Next process to work for
	int socketfd = 0;
	static struct sockaddr_in cli_addr;
	while(1) {
		socklen_t length = sizeof(cli_addr);
		if((socketfd = accept(listenfd, (struct sockaddr *)&cli_addr, &length)) < 0){
			mylog(LOG_ERR,"Error accepting");
			exit(1);
		}
		
		// Pass socket fd
		if(debug_level >= 1){
			mylog(LOG_DEBUG,
				"Accept connection socket fd is %d. Send to worker #%d with PID %d",
				socketfd, next_proc, prc[next_proc]);
		}
		sock_fd_write(out_sock[next_proc], (void *)"i", 1, socketfd);
		
		//close(listenfd);
		
		++next_proc;
		if(next_proc == PROCESSNUM) next_proc = 0;
	}
	
	// End master process by signal, this will never run
	
	return 0;
}

void EndServer(void){
	
	for(int i = 0; i < PROCESSNUM; ++i)	kill(prc[i], SIGTERM);
	
	#ifdef USESYSLOG
		closelog();
	#else
		if(logfd >= 0) close(logfd);
	#endif
	
	if(debug_level >= 1) mylog(LOG_NOTICE, "Daemon ends\n");
}

void StartWorker(int prc_num, int socket_in){
	worker_num = prc_num; // save global number of process
	
	int fd; // socket descriptor for web-connection
    char buf[16];
    ssize_t size;
	int con_num = 0; // connection number
	
	if(debug_level >= 5) mylog(LOG_DEBUG, "Worker process #%d starts with pid %d, socket #%d", prc_num, getpid(), socket_in);
	
	signal(SIGTTIN,SIG_IGN);
	signal(SIGCHLD, SIG_IGN); // if child death we need to recreate new child
	signal(SIGTERM, worker_signal_handler);
	
	while(1){
		++con_num;
		
		sleep(1);
		
		size = sock_fd_read(socket_in, buf, sizeof(buf), &fd);
		if (size <= 0){
			mylog(LOG_ERR, "Worker #%d. Error reading socket", prc_num);
			continue;
		}
		
		if(buf[0] == 'e'){
			mylog(LOG_DEBUG, "Worker #%d finish", prc_num);
			close(socket_in);
			exit(1);
		}
		
		if (fd != -1) WebProcess(prc_num, con_num, fd);
		
		sleep(1);
		close(fd);
	}
}

void WebProcess(int prc_num, int con_num, int fd){
	int j, file_fd, buflen;
	long i, ret, len;
	char* fstr;
	static char buffer[BUFSIZE+1];

	if(debug_level >= 6) 
		mylog(LOG_NOTICE, "Incoming connection worker #%d conn #%d",	prc_num, con_num);
				
	ret = read(fd, buffer, BUFSIZE); // read Web request
	if(ret == 0 || ret == -1) {	// read failure stop now
		WebMessage(FORBIDDEN, fd);
		if(debug_level >= 6) 
			mylog(LOG_DEBUG,
				"FORBIDDEN: failed to read browser request worker #%d conn #%d",
				prc_num, con_num); 
		return;
	}
	if(ret > 0 && ret < BUFSIZE) // return code is valid chars
		buffer[ret]=0; // terminate the buffer
	else buffer[0]=0;
	
	for(i=0; i < ret; ++i) // remove CF and LF characters
		if(buffer[i] == '\r' || buffer[i] == '\n') buffer[i] = '*';
		
	if(debug_level >= 6)
		mylog(LOG_DEBUG, "Worker #%d conn #%d. HTTP Request: %s", prc_num, con_num, buffer);
	
	if( strncmp(buffer, "GET ", 4) && strncmp(buffer, "get ", 4) ) {
		WebMessage(FORBIDDEN, fd);
		if(debug_level >= 6) 
			mylog(LOG_DEBUG,
				"FORBIDDEN: only simple GET operation supported worker #%d conn #%d",
				prc_num, con_num); 
		return;
	}
	
	for(i = 4; i < BUFSIZE; ++i) { // null terminate after the second space to ignore extra stuff
		if(buffer[i] == ' ') { // string is "GET URL " +lots of other stuff
			buffer[i] = 0;
			break;
		}
	}
	for(j = 0; j < i-1; j++) // check for illegal parent directory use ..
		if(buffer[j] == '.' && buffer[j+1] == '.') {
			WebMessage(FORBIDDEN, fd);
			if(debug_level >= 6) 
				mylog(LOG_DEBUG,
					"FORBIDDEN: parent directory (..) path names not supported worker #%d conn #%d",
					prc_num, con_num);
			return;
		}
	
	// cat '?' and args after it
	for(int t = 4; t < BUFSIZE; ++t)
		if(buffer[t] == '?'){
			buffer[t] = '\0';
			break;
		}
	
	// convert no filename to index file
	if( !strncmp(&buffer[0], "GET /\0", 6) || !strncmp(&buffer[0], "get /\0", 6) ) 
		strcpy(buffer, "GET /index.html");

	// work out the file type and check we support it
	buflen=strlen(buffer);
	fstr = (char *)NULL;
	for(i = 0; extensions[i].ext != 0; i++) {
		len = strlen(extensions[i].ext);
		if( !strncmp(&buffer[buflen-len], extensions[i].ext, len)) {
			fstr = (char*)extensions[i].filetype;
			break;
		}
	}
	if(fstr == NULL){
		WebMessage(FORBIDDEN, fd);
		if(debug_level >= 6) 
			mylog(LOG_DEBUG,
				"FORBIDDEN: file extension type not supported worker #%d conn #%d file %s",
				prc_num, con_num, &buffer[5]);
		return;
	}

	if(( file_fd = open(&buffer[5], O_RDONLY)) == -1) { // open the file for reading
		WebMessage(NOTFOUND, fd);
		if(debug_level >= 6)
				mylog(LOG_DEBUG,
					"NOT FOUND: failed to open file worker #%d conn #%d \"%s\"",
					prc_num, con_num, &buffer[5]);
		return;
	}
	
	if(debug_level >= 6) mylog(LOG_DEBUG, "SEND conn #%d: %s", con_num, &buffer[5]);
	
	len = (long)lseek(file_fd, (off_t)0, SEEK_END); // lseek to the file end to find the length
	      lseek(file_fd, (off_t)0, SEEK_SET); // lseek back to the file start ready for reading
          sprintf(buffer,
			"HTTP/1.0 200 OK\nServer: yawebs/%s\nContent-Length: %ld\nConnection: close\nContent-Type: %s\n\n",
			VERSION, len, fstr); // Header + a blank line
			
	if(debug_level >= 6) mylog(LOG_DEBUG, "Header conn #%d: %s", con_num, buffer);
	
	write(fd, buffer, strlen(buffer));

	/* send file in 8KB block - last block may be smaller */
	while (	(ret = read(file_fd, buffer, BUFSIZE)) > 0 ) {
		write(fd, buffer, ret);
	}
}

void WebMessage(int type, int socket_fd){
	char logbuffer[BUFSIZE];
	
	switch (type) {
	case FORBIDDEN:
		sprintf(logbuffer, http_header, FORBIDDEN, "Forbidden", strlen(Forbidden_message));
		write(socket_fd, logbuffer, strlen(logbuffer));
		write(socket_fd, Forbidden_message, strlen(Forbidden_message));
		break;
	case NOTFOUND: 
		sprintf(logbuffer, http_header, NOTFOUND, "Not Found", strlen(NotFound_message));
		write(socket_fd, logbuffer, strlen(logbuffer));
		write(socket_fd, NotFound_message, strlen(NotFound_message));
		break;
	}	
}

void ShowHelp(void){
	printf("Simple multiprocess http-server. Usage:\n");
	printf("	yawebs -h <ip> -p <port> -d <directory>\n");
	printf("Options\n");
	printf(" -h <ip>        - is ip adress on which web server will listen connections\n");
	printf("   --host       - is similar to -h\n");
	printf(" -p <port>      - is port on which we listen to\n");
	printf("   --port       - is similar to -p\n");
	printf(" -d <directory> - is a directory with web-documents\n");
	printf("   --directory  - is similar to -d\n");
	printf(" --help         - show this help and exit)\n");
	printf(" --version      - show version of web-server and exit\n");
}

int ParseArgs(int argc, char** argv, char** ip_str, int* port, char**dir){
	if (argc < 3) {
		fprintf(stderr, "Error: too few args!\n");
        ShowHelp();
		return -1;
    }
	
	char* ipp = NULL;
	char* portp = NULL;
	char* dirp = NULL;
	
	opterr = 0; // Prevent error messages of getopt
	
	int c;
    static struct option long_options[] = {
        {"directory", 1, 0, 'd'},
        {"help", 0, 0, 0},
		{"host", 1, 0, 'h'},
        {"port", 1, 0, 'p'},
        {"version", 0, 0, 0},
		{"debug", 1, 0, 0},
        {NULL, 0, NULL, 0}
    };
    int option_index = 0;
    while ((c = getopt_long(argc, argv, "d:h:p:d:",
                 long_options, &option_index)) != -1) {
        int this_option_optind = optind ? optind : 1;
		switch (c) {
		case 0:
			switch (option_index) {
			case 0: // dir
				if(debug_level >= 2) printf ("option --directory '%s'\n", optarg);
				dirp = optarg;
				break;
			case 1: // help
				if(debug_level >= 2) printf ("option --help\n");
				ShowHelp();
				return -1;
			case 2: // host
				if(debug_level >= 2) printf ("option --host '%s'\n", optarg);
				ipp = optarg;
				break;
			case 3: // port
				if(debug_level >= 2) printf ("option --port with value '%s'\n", optarg);
				portp = optarg;
			case 4: // version
				if(debug_level >= 2) printf("Yawebs version %d\n", VERSION);
				return -1;
			case 5: // debug
				debug_level = atoi(optarg);
				if(debug_level >= 2) printf("Yawebs starts debug with debug level %d\n", debug_level);
				break;
			}
			break;
		case 'p':
			if(debug_level >= 2) printf ("option -p with value '%s'\n", optarg);
			portp = optarg;
			break;
		case 'h':
			if(debug_level >= 2) printf ("option -h with value '%s'\n", optarg);
			ipp = optarg;
			break;
		case 'd':
			if(debug_level >= 2) printf ("option -d with value '%s'\n", optarg);
			dirp = optarg;
			break;
        }
    }
	
    if (optind < argc) {
		if(debug_level >= 2) {
			printf ("non-option ARGV-elements: ");
			while (optind < argc)
				printf ("%s ", argv[optind++]);
			printf ("\n");
		}
        ShowHelp();
		return -1;
    }
	
	if(debug_level >= 2) printf("Convert arguments\n");
	
	// port
	if(portp == NULL){
		fprintf(stderr, "You must specify port number!\n");
		ShowHelp();
		return -1;
	}
	
	int convport = (int)strtol(portp, NULL, 0);
	if(convport < 1 || convport > 65536){
		fprintf(stderr, "You must specify port number in range [1, 65535]!\n");
		return -1;
	}
	
	*port = convport;
	if(debug_level >= 2) printf("Port number %d\n", *port);

	// host ip string
	if(ipp == NULL || !is_ip(ipp)){
		fprintf(stderr, "IP adress is not correct!\n");
		return -1;
	}
	
	size_t str_len = strlen(ipp);
	*ip_str = (char *)malloc(str_len+1);
	if(*ip_str == NULL){
		fprintf(stderr, "Fail in memory alloc for ip adress string!\n");
		return -1;
	}
	strncpy(*ip_str, ipp, str_len+1);
	
	// directory string
	if(dirp == NULL || !is_good_web_dir(dirp)){
		fprintf(stderr, "Directory is not correct!\n");
		return -1;
	}
	
	str_len = strlen(dirp);
	int flAddSlash = 0;
	if(dirp[str_len-1] != '/') flAddSlash = 1;
	*dir = (char *)malloc(str_len + flAddSlash + 1);
	if(*dir == NULL){
		fprintf(stderr, "Fail in memory alloc for web-server path string!\n");
		return -1;
	}
	strncpy(*dir, dirp, str_len+1);
	if(flAddSlash){
		(*dir)[str_len+1] = '\0';
		(*dir)[str_len] = '/';
	}
	return 0;
}

int is_ip(const char* cs) {
	size_t len = strlen(cs);
	char* next = NULL;
	char* prev = (char*)cs;
	for (int count = 1; count <= 4; ++count){
		int num = 0;
		
		num = (int)strtol(prev, &next, 0);

		if(debug_level >= 2){
			for (char* pt = prev; pt < next; ++pt) printf("%c", *pt);
			printf(": %d, %d\n", num, next);
		}

		if (count == 4){
			if ((cs + len) != next){
				if(debug_level >= 2) printf("Too long: end of string %p\nNext char to look up %p\n", (cs + len), next);
				return 0;
			}
		}
		else if (*next != '.') return 0;

		if (num < 0 || num > 255) return 0;

		prev = next + 1;
	}

	return 1;
}

int is_good_web_dir(const char* dir) {
	if(dir == NULL){
		fprintf(stderr, "Directory name is empty\n");
		return 0;
	}
	
	size_t str_len = strlen(dir);
	
	for(int i = 0; i < str_len-1; ++i){
		if(dir[i] == '.' && dir[i+1] == '.') {
			if(debug_level >= 2) printf("Parent directory (..) path names not support\n");
			return 0;
		}
	}
	
	
	if( !strncmp(dir, "/"   , 2 ) || !strncmp(dir, "/etc", 5 ) ||
	    !strncmp(dir, "/bin", 5 ) || !strncmp(dir, "/lib", 5 ) ||
	    !strncmp(dir, "/dev", 5 ) || !strncmp(dir, "/usr", 5 ) ||
	    !strncmp(dir, "/sbin",6 )) {
		if(debug_level >= 2) printf("Directory could't strts with /, /bin, /etc, /dev, /lib, /usr, /sbin\n");
		return 0;
	}
	
	// Checks if dir is directory
	struct stat sb;
	if(stat(dir, &sb) == -1){
		if(debug_level >= 2) printf("Directory is not found or not accessable\n");
		return 0;
    }

    if(!S_ISDIR(sb.st_mode)){
		if(debug_level >= 2) printf("It is not directory: %s\n", dir);
		return 0;
	}
	
	return 1;
}

int Daemonize(char *dir){
	char buf[STRSIZE];
	memset(buf, 0, STRSIZE);
	
	if(debug_level >= 2) printf("Start daemonizing. See syslog to next messages.\n");
	
	// Go to new group
	setpgrp(); 
	
	// Make it silent
	for(int i = getdtablesize(); i>=0; --i) close(i);
	int nullfd = open("/dev/null", O_RDWR);
	dup(nullfd); // stdout
	dup(nullfd); // stderr
	
	// Run only one copy of daemon
	int lockfp = open("/tmp/yawebs.lock", O_RDWR|O_CREAT, 0640);
	if(lockfp < 0) return 5;
	if(lockf(lockfp, F_TLOCK, 0) < 0) return 6;
	
	sprintf(buf,"%d\n", m_pid);
	write(lockfp, buf, strlen(buf));
	
	#ifdef USESYSLOG
		// Strart logging to syslog
		setlogmask (LOG_UPTO (LOG_DEBUG));
		openlog ("yawebs", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	#else
		logfd = -1;
	#endif
	
	mylog(LOG_NOTICE, "Yawebs started with PID %d.", m_pid); // LOG_ERR,LOG_WARNING,LOG_NOTICE,LOG_INFO,LOG_DEBUG
	
	// Manage to signals
	signal(SIGHUP,SIG_IGN);
	signal(SIGTSTP,SIG_IGN);
	signal(SIGTTOU,SIG_IGN);
	signal(SIGTTIN,SIG_IGN);
	signal(SIGCHLD, master_signal_handler); // if child death we need to recreate new child
	signal(SIGTERM, master_signal_handler); // catch kill signal to kill daemon

	umask(027); // for more safety
	
	if(debug_level >= 2) mylog(LOG_DEBUG, "Finish daemonization.\n");
	
	return 0;
}

void master_signal_handler(int sig){
	switch(sig){
		case SIGCHLD:
			mylog(LOG_NOTICE, "Child jast has died");
			// make new process
			break;
		case SIGTERM:
			mylog(LOG_NOTICE, "Yawebs server shutdown.");
			EndServer();
			exit(0);
			break;
	}
}

void worker_signal_handler(int sig){
	switch(sig){
		case SIGTERM:
			mylog(LOG_NOTICE, "Yawebs worker shutdown.");
			exit(0);
			break;
	}
}

ssize_t sock_fd_write(int sock, void *buf, ssize_t buflen, int fd){
    ssize_t size;
    struct msghdr msg;
    struct iovec iov;
    union {
        struct cmsghdr cmsghdr;
        char control[CMSG_SPACE(sizeof (int))];
    } cmsgu;
    struct cmsghdr  *cmsg;

    iov.iov_base = buf;
    iov.iov_len = buflen;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    if (fd != -1) {
        msg.msg_control = cmsgu.control;
        msg.msg_controllen = sizeof(cmsgu.control);

        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_len = CMSG_LEN(sizeof (int));
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;

        if(debug_level >= 3) mylog(LOG_DEBUG, "Passing fd %d", fd);
        *((int *) CMSG_DATA(cmsg)) = fd;
    } else {
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        mylog(LOG_ERR, "Not passing socket fd");
    }

    size = sendmsg(sock, &msg, 0);

    if (size < 0)
        mylog(LOG_ERR, "Error sendmsg");
    return size;
}

ssize_t sock_fd_read(int sock, void *buf, ssize_t bufsize, int *fd){
    ssize_t     size;

    if (fd) {
        struct msghdr msg;
        struct iovec iov;
        union {
            struct cmsghdr cmsghdr;
            char control[CMSG_SPACE(sizeof (int))];
        } cmsgu;
        struct cmsghdr  *cmsg;

        iov.iov_base = buf;
        iov.iov_len = bufsize;

        msg.msg_name = NULL;
        msg.msg_namelen = 0;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsgu.control;
        msg.msg_controllen = sizeof(cmsgu.control);
        size = recvmsg (sock, &msg, 0);
        if (size < 0) {
            mylog(LOG_ERR, "Error recieving socket");
            exit(1);
        }
        cmsg = CMSG_FIRSTHDR(&msg);
        if (cmsg && cmsg->cmsg_len == CMSG_LEN(sizeof(int))) {
            if (cmsg->cmsg_level != SOL_SOCKET) {
                mylog(LOG_ERR, "invalid cmsg_level %d\n", cmsg->cmsg_level);
                exit(1);
            }
            if (cmsg->cmsg_type != SCM_RIGHTS) {
                mylog(LOG_ERR, "invalid cmsg_type %d\n", cmsg->cmsg_type);
                exit(1);
            }

            *fd = *((int *) CMSG_DATA(cmsg));
            if(debug_level >= 3) mylog(LOG_DEBUG, "Received fd %d\n", *fd);
        } else
            *fd = -1;
    } else {
        size = read (sock, buf, bufsize);
        if (size < 0) {
            mylog(LOG_ERR, "Error read");
            exit(1);
        }
    }
    return size;
}

void mylog(int type, const char* format, ...){
	va_list ap;
	va_start(ap, format);
	
	#ifdef USESYSLOG
		vsyslog(type, format, ap);
	#else
		// write log to file
		char logbuffer[BUFSIZE];
		
		pid_t pid = getpid();
		if(logfd == -1){
			if(worker_num == -1){
				// this is master process
				logfd = open("yawebs.log", O_CREAT | O_WRONLY | O_APPEND, 0644);
				if(logfd < 0){
					criticallog("Error opening file \"yawebs.log\"");
					return;	
				}
			}
			else{
				sprintf(logbuffer, "worker%d.log", worker_num);
				logfd = open(logbuffer, O_CREAT | O_WRONLY | O_APPEND, 0644);
				if(logfd < 0){
					criticallog("Worker %d. Error opening file \"%s\"", worker_num, logbuffer);
					return;	
				}
			}
		}
		
		// Write current date and time
		time_t now = time(0);
		struct tm* tm_info = localtime(&now);
		strftime(logbuffer, 80, "%Y:%m:%d %H:%M:%S", tm_info);
		write(logfd,logbuffer,strlen(logbuffer));
		
		// Write PID
		sprintf(logbuffer, " PID %d ", pid);
		write(logfd, logbuffer, strlen(logbuffer));
		
		// Write type of message
		switch(type){
			case LOG_DEBUG: write(logfd, "DEBUG: ", 7);
				break;
			case LOG_INFO: write(logfd, "INFO: ", 6);
				break;
			case LOG_NOTICE: write(logfd, "NOTICE: ", 8);
				break;
			case LOG_WARNING: write(logfd, "WARNING: ", 9);
				break;
			case LOG_ERR: write(logfd, "ERROR: ", 7);
				break;
			case LOG_CRIT: write(logfd, "CRITICAL: ", 10);
				break;
			default:
				write(logfd, "CRITICAL: ", 10);
		}
		
		// Write user message
		vsprintf(logbuffer, format, ap);
		write(logfd, logbuffer, strlen(logbuffer)); 
		write(logfd, "\n", 1);
		
		close(logfd);
		logfd = -1;
		
	#endif
}

void criticallog(const char* format, ...){
	va_list ap;
	va_start(ap, format);
	
	#ifdef USESYSLOG
		vsyslog(LOG_CRIT, format, ap);
	#else
		// write log to file
		char logbuffer[BUFSIZE];
		int fd = open("critical.log", O_CREAT | O_WRONLY | O_APPEND, 0644);
		
		if(fd < 0) return;	
		
		pid_t pid = getpid();
		
		// Write current date and time
		time_t now = time(0);
		struct tm* tm_info = localtime(&now);
		strftime(logbuffer, 80, "%Y:%m:%d %H:%M:%S", tm_info);
		write(fd,logbuffer,strlen(logbuffer));
			
		// Write PID
		sprintf(logbuffer, " PID %d ", pid);
		write(fd, logbuffer, strlen(logbuffer));
		write(fd, "CRITICAL: ", 10);
		// Write user message
		vsprintf(logbuffer, format, ap);
		write(fd, logbuffer, strlen(logbuffer)); 
		write(fd, "\n", 1);
			
		close(fd);
		
	#endif
}

Yawebs::Yawebs(char* ip_str, char* dir, int port){
	
}