#include "common.h"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>


#ifdef WIN32

#include <windows.h>
#include <sys/types.h>
#include <sys/_default_fcntl.h>
#include <sys/poll.h>
#include <cygwin/types.h>
#include <cygwin/socket.h>
#include <sys/errno.h>
#include <cygwin/in.h>
#include <sched.h>
#include <netdb.h>
#include <netinet/tcp.h>

#else

#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>

#endif


#include "debug.h"
#include "tools.h"
#include "sockets.h"

// CONVERTION
uint32_t hostname2ip( const char *hostname )
{
	struct hostent *phostent;
	unsigned int hostaddr;
	unsigned char *temp;

	phostent = gethostbyname(hostname);
	if (phostent==NULL) {
		//printf(" Error gethostbyname(%s)\n",hostname);
		return 0;
	}
	temp = ((unsigned char *) phostent->h_addr_list[0]);
	hostaddr = *(unsigned int*)temp;//   *(*temp<<24) + ( *(temp+1)<<16 ) + ( *(temp+2)<<8 ) + (*(temp+3));
	//printf("IP = %03d.%03d.%03d.%03d\n", *temp, *(temp+1), *(temp+2), *(temp+3));
	//if (hostaddr==0x7F000001) hostaddr=0;
	return hostaddr;
}

char *iptoa(char *dest, unsigned int ip )
{
  sprintf(dest,"%d.%d.%d.%d", 0xFF&(ip), 0xFF&(ip>>8), 0xFF&(ip>>16), 0xFF&(ip>>24));
  return dest;
}

char ip_string[3][0x40];
int ip_string_counter = 0;
char *ip2string( unsigned int ip )
{
	ip_string_counter++; if (ip_string_counter>2) ip_string_counter = 0;
	return iptoa(ip_string[ip_string_counter], ip );
}

////////////////////////////////////////////////////////////////////////////////
// SOCKETS FUNCTIONS
////////////////////////////////////////////////////////////////////////////////

int fdstatus_read(int s)
{
  fd_set readfds;
  int retval;
  struct timeval timeout;
  FD_ZERO(&readfds);
  FD_SET(s, &readfds);
  timeout.tv_usec = 0;
  timeout.tv_sec = 0;
  //do {
  retval = select(s+1, &readfds, NULL, NULL,&timeout); 
  //} while(retval<0 && errno==EINTR);
  return retval;
}

int fdstatus_readt(int s, int tim)
{
  fd_set readfds;
  int retval;
  struct timeval timeout;

	FD_ZERO(&readfds);
	FD_SET(s, &readfds);
	timeout.tv_usec = (tim%1000)*1000;
	timeout.tv_sec = tim/1000;
 // do {
	retval = select(s+1, &readfds, NULL, NULL,&timeout); 
  //} while(retval<0 && errno==EINTR);
  return retval;
}

int fdstatus_writet(int s, int tim)
{
  fd_set writefds;
  int retval;
  struct timeval timeout;

	FD_ZERO(&writefds);
	FD_SET(s, &writefds);
	timeout.tv_usec = (tim%1000)*1000;
	timeout.tv_sec = tim/1000;
  do {
	retval = select(s+1, NULL, &writefds, NULL,&timeout); 
  } while( (retval<0) && ( (errno==EINTR)||(errno==EAGAIN) ) );

  return retval;
}

int fdstatus_write(int s)
{
  fd_set writefds;
  int retval;
  struct timeval timeout;
  FD_ZERO(&writefds);
  FD_SET(s, &writefds);
  timeout.tv_sec = 0;
  timeout.tv_usec = 100;
  do {
	retval = select(s+1, NULL, &writefds, NULL,&timeout); 
  } while ( (retval<0) && ( (errno==EINTR)||(errno==EAGAIN) ) );
  return retval;
}


int fdstatus_accept(int s)
{
  fd_set fd;
  int retval;
  struct timeval timeout;

  FD_ZERO(&fd);
  FD_SET(s, &fd);
  timeout.tv_usec = 1000;
  timeout.tv_sec = 0;
  do {
	retval = select(s+1, &fd, NULL, NULL,&timeout); 
  } while(retval<0 && errno==EINTR);
  return retval;
}


int SetSocketTimeout(int connectSocket, int milliseconds)
{
    struct timeval tv;

	tv.tv_sec = milliseconds / 1000 ;
	tv.tv_usec = ( milliseconds % 1000) * 1000  ;

	setsockopt (connectSocket, SOL_SOCKET, SO_SNDTIMEO, (char*)&tv, sizeof tv);
	setsockopt (connectSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof tv);
	return 0;
}

/* Disable the Nagle (TCP No Delay) algorithm */
int SetSocketNoDelay(int sock)
{
	int val = 1;
	if ( setsockopt( sock, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val)) < 0) return -1; 
	return 0;
}

int SetSocketKeepalive(int sock)
{
	int val = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val)) < 0) return -1; 
/*
	val = 60;
	if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, (void*)&val, sizeof(val)) < 0) return -1;
	val = 30;
	if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, (void*)&val, sizeof(val)) < 0) return -1;
	val = 4;
	if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, (void*)&val, sizeof(val)) < 0) return -1;
*/
	return 0;
}

void SetSoketNonBlocking(int fd)
{
	int flags = fcntl( fd, F_GETFL );
	fcntl( fd, F_SETFL, flags|O_NONBLOCK );
}

/*
int SetSocketPriority(int sock)
{
	setsockopt(sock, SOL_SOCKET, SO_PRIORITY, (void *)&cfg->netprio, sizeof(ulong));
}
*/

int SetSocketReuseAddr(int sock)
{
	int reuse = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(int))< 0) return 0; else return 1;
}


///////////////////////////////////////////////////////////////////////////////
// UDP CONNECTION
///////////////////////////////////////////////////////////////////////////////

int CreateServerSockUdp(int port, uint32_t ip)
{
	int sock;
	sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock==-1) {
		printf("socket() failed\n");
		return -1;
	}

	struct sockaddr_in saddr;
	memset((char *)&saddr, 0, sizeof(saddr));
	saddr.sin_family = PF_INET;
	if (ip) saddr.sin_addr.s_addr = ip; else saddr.sin_addr.s_addr = htonl( INADDR_ANY );
	if (port) saddr.sin_port = htons(port);

	int reuse = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(int))< 0) {
		close(sock);
		printf("setsockopt() failed\n");
		return -1;
	}

	if ( bind( sock, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in)) == -1 ) {
		close(sock);
		//if (errno==99) pthread_exit(0); /////////////////////////// XXX
		//printf("bind() failed\n");
		return -1;
	}

	return sock;
}

int CreateClientSockUdp(int port, uint32_t ip)
{
	int sock = socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP);
	if (sock==-1) {
		printf("failed to create udp socket (errno=%d)\n",errno);
		return -1;
	}
	if (port && ip) {
		struct sockaddr_in saddr;
		saddr.sin_family = PF_INET;
		saddr.sin_port = htons(port);
		saddr.sin_addr.s_addr = ip;
		if ( connect(sock,(struct sockaddr *)&saddr,sizeof(struct sockaddr_in)) != 0) {
			close(sock);
			return -1;
		}
	}
	return sock;
}


///////////////////////////////////////////////////////////////////////////////
// TCP CONNECTION
///////////////////////////////////////////////////////////////////////////////

int CreateServerSockTcp(int port, uint32_t ip)
{
	int sock;
	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if ( sock==-1 ) {
		printf("socket() failed\n");
		return -1;
	}

	struct sockaddr_in saddr;
	saddr.sin_family = PF_INET;
	if (ip) saddr.sin_addr.s_addr = ip; else saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons(port);

	int reuse=1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(int))< 0) {
		close(sock);
		printf("setsockopt(SO_REUSEADDR) failed\n");
		return -1;
	}

	if ( bind(sock, (struct sockaddr*)&saddr, sizeof(struct sockaddr))==SOCKET_ERROR ) {
		close(sock);
		//if (errno==99) pthread_exit(0);
		//printf("bind() failed (Port:%d)\n",port);
		return -1;
	}

	if (listen(sock, SOMAXCONN) == SOCKET_ERROR) {
		close(sock);
		printf("listen() failed\n");
		return -1;
	}
	return sock;
}

int CreateClientSockTcp(uint32_t netip, int port)
{
	int sock = socket(PF_INET,SOCK_STREAM,0);
	if( sock<0 ) {
		//printf("Invalid Socket\n");
		return -1;
	}

	struct sockaddr_in saddr;
	memset(&saddr,0, sizeof(saddr));
	saddr.sin_family = PF_INET;
	saddr.sin_port = htons(port);
	saddr.sin_addr.s_addr = netip;
	if ( connect(sock,(struct sockaddr *)&saddr,sizeof(struct sockaddr_in)) != 0 ) {
		close(sock);
		return -1;
	}
	return sock;
}


///////////////////////////////////////////////////////////////////////////////
// NON BLOCKED TCP CONNECTION
///////////////////////////////////////////////////////////////////////////////

int CreateClientSockTcp_nonb(unsigned int netip, int port)
{
	int ret, flags, error;
	socklen_t len;
	int sockfd;
	struct sockaddr_in saddr;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if( sockfd<0 ) return -1;

	flags = fcntl(sockfd,F_GETFL);
	if (flags<0) {
		close(sockfd);
		return -1;
 	}
	if ( fcntl(sockfd,F_SETFL,flags|O_NONBLOCK)<0 ) {
		close(sockfd);
		return -1;
	}

	memset(&saddr,0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(port);
	saddr.sin_addr.s_addr = netip;

	do {
		ret = connect( sockfd, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in) );
	} while ( ret && (errno==EINTR) );

	if (ret) {
		if (errno==EINPROGRESS || errno==EALREADY) {
			struct pollfd pfd;
			pfd.fd = sockfd;
			pfd.events = POLLOUT;
			errno = 0;
			do {
				ret = poll(&pfd, 1, 1000);
			} while (ret < 0 && errno == EINTR);
			if (ret < 0) {
				close(sockfd);
				return -1;
			}
			else if (ret == 0) {
				errno = ETIMEDOUT;
				close(sockfd);
				return -1;
			}
			else {
				if ( pfd.revents && (pfd.revents & POLLOUT) ) {
					len = sizeof(error);
					if ( getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) ) {
						close(sockfd);
						return -1;
					}
					if (error) {
						errno = error;
						close(sockfd);
						return -1;
					}
				}
				else {
					errno = ECONNABORTED;
					close(sockfd);
					return -1;
				}
			}
		}
		else if (errno!=EISCONN) {
			close(sockfd);
			return -1;
		}
	}

	flags &=~ O_NONBLOCK;
	fcntl(sockfd, F_SETFL, flags);	/* restore file status flags */

	return sockfd;
}

int CreateServerSockTcp_nonb(int port, uint32_t ip)
{
	struct protoent *ptrp;
	int p_proto;
	if ((ptrp = getprotobyname("tcp"))) p_proto = ptrp->p_proto; else p_proto = 6;

	int sock;
	sock = socket(AF_INET, SOCK_STREAM, p_proto);
	if ( sock<0 ) {
		printf("socket() failed\n");
		return -1;
	}

	int flgs=fcntl(sock,F_GETFL);
	if(flgs<0) {
		close(sock);
		printf("socket: fcntl GETFL failed\n");
		return -1;
	}

	if ( fcntl(sock,F_SETFL,flgs|O_NONBLOCK)<0 ) {
		close(sock);
		printf("socket: fcntl SETFL failed\n");
		return -1;
	}

	int reuse=1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(int))< 0) {
		close(sock);
		printf("setsockopt(SO_REUSEADDR) failed\n");
		return -1;
	}

	struct sockaddr_in saddr;
	saddr.sin_family = AF_INET;
	if (ip) saddr.sin_addr.s_addr = ip; else saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons(port);
	if ( bind(sock, (struct sockaddr*)&saddr, sizeof(struct sockaddr))==SOCKET_ERROR ) {
		close(sock);
		//if (errno==99) pthread_exit(0);
		//printf("bind() failed (Port:%d, errno=%d)\n",port,errno);
		return -1;
	}

	if (listen(sock, SOMAXCONN) == SOCKET_ERROR) {
		close(sock);
		printf("listen() failed\n");
		return -1;
	}
	return sock;
}

// >0 : received ok
// =0 : disconnected
// =-1 : error
// =-2 : timeout
int recv_nonb(int sock,uint8_t *buf,int len,int timeout)
{
	int ret;
    int index = 0;
	uint32_t now = GetTickCount();
	uint32_t last = now + timeout;
	while (1) {
		struct pollfd pfd;
		pfd.fd = sock;
		pfd.events = POLLIN | POLLPRI;
		ret = poll(&pfd, 1, last-now);
		if (ret>0) {
			if ( pfd.revents & (POLLIN|POLLPRI) ) {
				ret = recv( sock, buf+index, len-index, MSG_NOSIGNAL|MSG_DONTWAIT );
				if (ret>0) {
					index+=ret;
					if (index==len) return index;
				}
				else if (ret==0) return 0; // disconected
				else if ( (ret==-1)&&(errno!=EAGAIN)&&(errno!=EWOULDBLOCK)&&(errno!=EINTR) ) return -1; // error
			}
			if ( pfd.revents & (POLLHUP|POLLNVAL) ) return 0; // disconnected
		}
		else if (ret==0) return -2; // timeout
		else if ( (errno!=EINTR)&&(errno!=EAGAIN) ) return -1; // error

		now = GetTickCount();
		if (now>last) return -2; // timeout
	}
}

int send_nonb00(int sock,uint8_t *buf,int len,int to)
{
	if (sock<=0) return FALSE;
	int remain = len;
	uint8_t *ptr = buf;
	while (remain) {
		struct pollfd pfd;
		pfd.fd = sock;
		pfd.events = POLLOUT;
		int ret = poll(&pfd, 1, 100);
		if (ret==0) return FALSE;
		else if ( (ret==-1)&&(errno!=EINTR)&&(errno!=EAGAIN) ) return FALSE;
		else if ( pfd.revents & POLLOUT ) {
			int got = send( sock, (void *) ptr, (size_t) remain, MSG_NOSIGNAL|MSG_DONTWAIT);
			if (got >= 0) {
				remain -= got;
				ptr    += got;
			} else if (
				errno != EWOULDBLOCK &&
				errno != EAGAIN      &&
				errno != EINTR
			) {
				mlogf(LOGERROR,getdbgflag(DBG_ERROR,0,0)," send_nonb(%d): error(%d) (sent %d from %d)\n", sock, errno, len-remain,len );
				return FALSE;
			}
		}
		else if ( pfd.revents & (POLLHUP|POLLERR|POLLNVAL) ) return FALSE;
	}
	return TRUE;
}

int send_nonb(int sock,uint8_t *buf,int len,int to)
{
	if (sock<=0) return FALSE;
	int remain = len;
	uint8_t *ptr = buf;

	int got = send( sock, (void *) ptr, (size_t) remain, MSG_NOSIGNAL|MSG_DONTWAIT);
	if (got >= 0) {
				remain -= got;
				ptr    += got;
	} else if (
		errno != EWOULDBLOCK &&
		errno != EAGAIN      &&
		errno != EINTR
	) {
		//mlogf(LOGDEBUG,getdbgflag(DBG_ERROR,0,0)," send_nonb(%d): error(%d) (sent %d from %d)\n", sock, errno, len-remain,len );
		return FALSE;
	}

	while (remain) {
		struct pollfd pfd;
		pfd.fd = sock;
		pfd.events = POLLOUT;
		int ret = poll(&pfd, 1, 100);
		if (ret==0) return FALSE;
		else if ( (ret==-1)&&(errno!=EINTR)&&(errno!=EAGAIN) ) return FALSE;
		else if ( pfd.revents & POLLOUT ) {
			int got = send( sock, (void *) ptr, (size_t) remain, MSG_NOSIGNAL|MSG_DONTWAIT);
			if (got >= 0) {
				remain -= got;
				ptr    += got;
			} else if (
				errno != EWOULDBLOCK &&
				errno != EAGAIN      &&
				errno != EINTR
			) {
				//mlogf(LOGDEBUG,getdbgflag(DBG_ERROR,0,0)," send_nonb(%d): error(%d) (sent %d from %d)\n", sock, errno, len-remain,len );
				return FALSE;
			}
		}
		else if ( pfd.revents & (POLLHUP|POLLERR|POLLNVAL) ) return FALSE;
	}
	return TRUE;
}

