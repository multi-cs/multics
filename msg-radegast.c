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

#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <netdb.h> 
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#endif

#include "debug.h"
#include "sockets.h"
#include "msg-radegast.h"

///////////////////////////////////////////////////////////////////////////////

int rdgd_message_receive(int sock, unsigned char *buffer, int timeout)
{
	int len;
	unsigned char netbuf[300];

	if (sock==INVALID_SOCKET) {
		return -1;
	}

	len = recv_nonb(sock, netbuf, 2,timeout);
	if (len<=0) {
		return len; // disconnected
	}
	if (len != 2) {
		return -1;
	}
	len = recv_nonb(sock, netbuf+2, netbuf[1],timeout);
	if (len<=0) {
		return len; // disconnected
	}
	if (len != netbuf[1]) {
		return -1;
	}
	len += 2;
#ifdef DEBUG_NETWORK
	if (flag_debugnet) {
		mlogf(LOGDEBUG,0," radegast: receive data %d\n",len);
		debughex(netbuf,len);
	}
#endif
	memcpy(buffer, netbuf, len);
	return len;
}

///////////////////////////////////////////////////////////////////////////////

int rdgd_message_send(int sock, unsigned char *buf, int len)
{
#ifdef DEBUG_NETWORK
	if (flag_debugnet) {
		mlogf(LOGDEBUG,0," radegast: send data %d\n",len);
		debughex(buf,len);
	}
#endif
	return send_nonb( sock, buf, len, 100);
}

///////////////////////////////////////////////////////////////////////////////

// -1: not yet
// 0: disconnect
// >0: ok
int rdgd_check_message(int sock)
{
	int len;
	unsigned char netbuf[300];

	len = recv(sock, netbuf, 2, MSG_PEEK|MSG_NOSIGNAL|MSG_DONTWAIT);
	if (len==0) return 0;
	if (len!=2) return -1;

	int datasize = netbuf[1];
	len = recv(sock, netbuf, 2+datasize, MSG_PEEK|MSG_NOSIGNAL|MSG_DONTWAIT);

	if (len!=2+datasize) return -1;

	return len;
}

