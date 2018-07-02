#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include <fcntl.h>
#include <sys/time.h>
#include <time.h>

#ifdef WIN32

#include <windows.h>
#include <sys/types.h>

#else

#include <errno.h>
#include <sched.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#endif

#ifndef  uint32_t
typedef unsigned int uint32_t;
#endif

#include "debug.h"
#include "threads.h"


#ifndef WIN32 

int create_thread(pthread_t *tid, threadfn func, void *arg)
{
	if (pthread_create (tid, NULL, func, arg) < 0) {
		fprintf (stderr, "pthread_create error\n");
		//exit (1);
		return 0;
	}
	pthread_detach(*tid);
	return 1;
}

#else

int create_thread(pthread_t *tid, threadfn func, void *arg)
{
	CreateThread (NULL, 0, (LPTHREAD_START_ROUTINE) func, NULL, 0, tid);
	return 1;
}

#endif
