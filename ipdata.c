#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>

#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include "ipdata.h"
#include "tools.h"

#ifdef IPLIST

struct ip_hacker_data *iplist_find( struct ip_hacker_data *iplist, uint32_t ip )
{
	while (iplist) {
		if (iplist->ip==ip) return iplist;
		iplist = iplist->next;
	}
	return NULL;
}

struct ip_hacker_data *iplist_add( uint32_t ip )
{
	struct ip_hacker_data *iplist = malloc( sizeof(struct ip_hacker_data) );
	memset(iplist, 0, sizeof(struct ip_hacker_data) );
	iplist->ip = ip;
	return iplist;
}

void iplist_newlogin( struct ip_hacker_data *iplist )
{
	if ( (iplist->lastseen+500000) < GetTickCount() ) iplist->nblogin = 0;

	iplist->lastseen = GetTickCount();
	iplist->nblogin++;
}

void iplist_goodlogin( struct ip_hacker_data *iplist )
{
	iplist->nblogin = 0;
}

int iplist_accept( struct ip_hacker_data *iplist )
{
	if (iplist->nblogin>5) {
		if ( (iplist->lastseen+180000) < GetTickCount() ) return 1;
		else return 0;
	}
	else return 1;
}

#endif
