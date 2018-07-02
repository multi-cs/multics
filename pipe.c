
#include "pipe.h"

int frcc_pipe[2]; // newcamd server recv pipe

int dcwpipe[2];

// to check for EINTR
int pipe_read( int fd, uint8_t *buf, int len )
{
	int readlen;
	while (1) {
		readlen = read( fd, buf, len);
		if (readlen==-1) {
			if ( (errno==EINTR)||(errno==EWOULDBLOCK)||(errno==EAGAIN) ) {
				usleep(1);
				continue;
			}
			else {
				flag_debugfile = 1;
				mlogf(LOGERROR,getdbgflag(DBG_ERROR,0,0)," pipe(%d): read failed (errno=%d)\n", fd, errno);
				prg.restart = 1;
				return -1;
			}
		}
		break;
	}
	return readlen;
}

// to check for EINTR
int pipe_write( int fd, uint8_t *buf, int len )
{
	int writelen;
	while (1) {
		writelen = write( fd, buf, len);
		if (writelen==-1) {
			if ( (errno==EINTR)||(errno==EWOULDBLOCK)||(errno==EAGAIN) ) {
				usleep(1);
				continue;
			}
			else {
				flag_debugfile = 1;
				mlogf(LOGERROR,getdbgflag(DBG_ERROR,0,0)," pipe(%d): write failed (errno=%d)\n", fd, errno);
				prg.restart = 1;
				return -1;
			}
		}
		break;
	}
	return writelen;
}

int pipe_purge( int fd )
{
	uint8_t rbuf[1024];
	while(1) {
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET( fd, &readfds);
		struct timeval timeout;
		timeout.tv_usec = 0;
		timeout.tv_sec = 0;
		int retval = select(fd+1, &readfds, NULL, NULL,&timeout);
		if ( retval>0 )	{
			retval = read( fd, rbuf, sizeof(rbuf) );
		}
		else break;
	}
	return 0;
}


// offset  size  desc
// 0       1     0xFF
// 1       1     Data CRC
// 2       2     Data Length
int pipe_recv( int fd, uint8_t *buf )
{
	uint8_t rbuf[1024];
	int rlen;

	rlen = pipe_read( fd, rbuf, 4);
	if (rlen!=4) {
		mlogf(LOGERROR,getdbgflag(DBG_ERROR,0,0)," pipe(%d): header recv error (rlen=%d)\n",fd,rlen);
		pipe_purge(fd); // wrong data --> purge
		return 0;
	}
	if (rbuf[0]!=0xFF) {
		mlogf(LOGERROR,getdbgflag(DBG_ERROR,0,0)," pipe(%d): recv error, wrong id %02X\n", fd,rbuf[0]);
		pipe_purge(fd); // wrong data --> purge
		return 0;
	}
	int len = (rbuf[2]<<8)|rbuf[3];
	rlen += pipe_read( fd, rbuf+4, len);
	if ( rlen!= len+4 ) {
		mlogf(LOGERROR,getdbgflag(DBG_ERROR,0,0), " pipe(%d): recv error (rlen=%d)\n",fd,rlen);
		pipe_purge(fd); // wrong data --> purge
		return 0;
	}
	//Checksum
/*	int i;
	uint8_t sum =0;
	for(i=4; i<rlen; i++) sum ^= rbuf[i];
	if (sum!=rbuf[1]) {
		mlogf(LOGERROR,getdbgflag(DBG_ERROR,0,0)," pipe(%d): recv error, wrong checksum\n",fd);
		pipe_purge(fd); // wrong data --> purge
		return 0;
	}*/
	memcpy(buf, rbuf+4, len);
	//mlogf(LOGDEBUG,getdbgflag(DBG_ERROR,0,0)," pipe(%d): recv data\n"); debughex(rbuf, rlen);
	return len;
}	

int pipe_send( int fd, uint8_t *buf, int len )
{
	uint8_t wbuf[1024];
	//ID (check for errors)
	wbuf[0] = 0xFF;
	//Checksum
/*	int i;
	uint8_t sum =0;
	for(i=0; i<len; i++) sum ^= buf[i];
	wbuf[1] = sum;*/
	//LENGTH
	wbuf[2] = (len>>8)&0x0f;
	wbuf[3] = len&0xff;
	// DATA
	int wlen = 4+len;
	memcpy(wbuf+4, buf, len);
	//mlogf(LOGDEBUG,0," pipe(%d): write data\n",fd); debughex(buf, len);
	return pipe_write( fd, wbuf, wlen);
}

void pipe_cmd( int pfd, int cmd )
{
	uint8_t buf[2];
	buf[0] = cmd;
	buf[1] = 0;
	pipe_send( pfd, buf, 2);
}

void pipe_lock( int pfd )
{
	uint8_t buf[2];
	buf[0] = PIPE_LOCK;
	buf[1] = 0;
	pipe_send( pfd, buf, 2);
}

void pipe_wakeup( int pfd )
{
	uint8_t buf[2];
	buf[0] = PIPE_WAKEUP;
	buf[1] = 0;
	pipe_send( pfd, buf, 2);
}

void pipe_pointer( int pfd, int cmd, void *ptr )
{
	uint8_t buf[16];
	buf[0] = cmd;
	memcpy( buf+1, &ptr, sizeof(void*) );
	//mlogf(LOGDEBUG,0," pipe_pointer(%d): %p\n", pfd, ptr); debughex(buf, 1+sizeof(void*));
	pipe_send( pfd, buf, 1+sizeof(void*) );
}

