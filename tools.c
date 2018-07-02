#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef WIN32

#include <windows.h>
//#include <sys/types.h>

#else

#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <errno.h>

#endif

#include "tools.h"

struct timeval startime;

#ifdef WIN32

void usleep( int count )
{
  unsigned long int Ticks = GetTickCount() + count/1000;
  while (Ticks>GetTickCount()) ;
}

#else

uint64_t GetTickCount()
{
    struct timeval tv;
    gettimeofday( &tv, NULL );
    // this will rollover ~ every 49.7 days
    return (unsigned int)( (tv.tv_sec-startime.tv_sec) * 1000 + tv.tv_usec / 1000);
}

unsigned int GetuTickCount()
{
    struct timeval tv;
    gettimeofday( &tv, NULL );
    // this will rollover ~ every 49.7 days
    return (unsigned int)( (tv.tv_sec-startime.tv_sec) * 1000000 + tv.tv_usec);
}

unsigned int GetTicks(struct timeval *tv)
{
    return (unsigned int)( (tv->tv_sec-startime.tv_sec) * 1000 + tv->tv_usec/1000 );
}

#endif

unsigned int getseconds()
{
    struct timeval tv;
    gettimeofday( &tv, NULL );
    // this will rollover ~ every 49.7 days
    return (unsigned int)(tv.tv_sec-startime.tv_sec);
}


void tabavg_init(struct table_average *t)
{
	memset(t, 0, sizeof(struct table_average) );
}

void tabavg_add(struct table_average *t, uint32_t value)
{
	t->tab[t->itab] = value;
	t->itab++; if (t->itab>=100) t->itab =0;
}

uint32_t tabavg_get(struct table_average *t)
{
	uint32_t min = t->tab[0];
	int i;
	for (i=1; i<100; i++) if (min>t->tab[i]) min = t->tab[i];
	if (min==0) return 0xffffffff;

	int sum = 0;
	for (i=1; i<100; i++) sum += (t->tab[i]-min);
	return (sum/100);
}

