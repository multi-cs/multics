#define CAMD_ECM_REQUEST     0
#define CAMD_ECM_REPLY       1
#define CAMD_KEEPALIVE       0x37
#define CAMD_CEX_IDREQUEST   0x3D
#define CAMD_CEX_IDREPLY     0x3E
#define CAMD_CEX_PUSH        0x3F

///////////////////////////////////////////////////////////////////////////////
//
///////////////////////////////////////////////////////////////////////////////

void aes_set_keys( uint8_t *key, AES_KEY *dkey, AES_KEY *ekey)
{
	AES_set_decrypt_key( key, 128, dkey);
	AES_set_encrypt_key( key, 128, ekey);
}

void aes_decrypt(AES_KEY *dkey, uint8_t *buf, int n)
{
	int32_t i;
	for (i=0; i<n; i+=16) {
		AES_decrypt(buf+i, buf+i, dkey);
	}
}

void aes_encrypt(AES_KEY *ekey, uint8_t *buf, int n)
{
	int32_t i;
	for (i=0; i<n; i+=16) {
		AES_encrypt(buf+i, buf+i, ekey);
	}
}

void camd35_init_data( char *user, char *pass, AES_KEY *encryptkey, AES_KEY *decryptkey, uint32_t *ucrc)
{
	unsigned char md5tmp[MD5_DIGEST_LENGTH];
	*ucrc = crc32( 0L, MD5( (uint8_t*)user, strlen(user), md5tmp), MD5_DIGEST_LENGTH ); // user
	aes_set_keys( MD5( (uint8_t*)pass, strlen(pass), md5tmp) , decryptkey, encryptkey); // pass
}

///////////////////////////////////////////////////////////////////////////////

inline int camd35_padding( int len )
{
	if (len&0x0f) return ( (len&0xfff0)+0x10 ); else return len;
}

///////////////////////////////////////////////////////////////////////////////

// for connected udp sockets
void camd35_send( int handle, AES_KEY *encryptkey, uint32_t ucrc, unsigned char *buf, int len)
{
	uint8_t sbuf[1024];
	sbuf[0] = ucrc>>24;
	sbuf[1] = ucrc>>16;
	sbuf[2] = ucrc>>8;
	sbuf[3] = ucrc;
	memcpy( sbuf+4, buf, len );
	memset( sbuf+4+len, 0xFF, 15);
	//
	uint32_t datacrc = crc32(0L, buf+20, len-20);
	sbuf[8] = datacrc>>24;
	sbuf[9] = datacrc>>16;
	sbuf[10] = datacrc>>8;
	sbuf[11] = datacrc;
	int newlen = camd35_padding(len);
#ifdef DEBUG_NETWORK
	if (flag_debugnet) {
		mlogf(LOGDEBUG,0," camd35: Send data length %d\n", newlen+4);
		debughex(sbuf, newlen+4);
	}
#endif
	aes_encrypt( encryptkey, sbuf+4, newlen);
	// SEND
	send( handle, sbuf, newlen+4, 0);
}

void camd35_sendto( int handle, uint32_t ip, int port, AES_KEY *encryptkey, uint32_t ucrc, unsigned char *buf, int len)
{
	uint8_t sbuf[1024];
	sbuf[0] = ucrc>>24;
	sbuf[1] = ucrc>>16;
	sbuf[2] = ucrc>>8;
	sbuf[3] = ucrc;
	memcpy( sbuf+4, buf, len );
	memset( sbuf+4+len, 0xFF, 15);
	//
	uint32_t datacrc = crc32(0L, buf+20, len-20);
	sbuf[8] = datacrc>>24;
	sbuf[9] = datacrc>>16;
	sbuf[10] = datacrc>>8;
	sbuf[11] = datacrc;
	int newlen = camd35_padding(len);
#ifdef DEBUG_NETWORK
	if (flag_debugnet) {
		mlogf(LOGDEBUG,0," camd35: Send data to (%s:%d) length %d\n", ip2string(ip), port, newlen+4);
		debughex(sbuf, newlen+4);
	}
#endif
	aes_encrypt( encryptkey, sbuf+4, newlen);
	// SEND
	struct sockaddr_in si_other;
	int slen = sizeof(si_other);
	memset((char *) &si_other, 0, sizeof(si_other));
	si_other.sin_family = AF_INET;
	si_other.sin_port = htons( port );
	si_other.sin_addr.s_addr = ip;
	sendto( handle, sbuf, newlen+4, 0, (struct sockaddr *)&si_other, slen);
}

int cs378x_send( int handle, AES_KEY *encryptkey, uint32_t ucrc, unsigned char *buf, int len)
{
	uint8_t sbuf[1024];
	sbuf[0] = ucrc>>24;
	sbuf[1] = ucrc>>16;
	sbuf[2] = ucrc>>8;
	sbuf[3] = ucrc;
	memcpy( sbuf+4, buf, len );
	memset( sbuf+4+len, 0xFF, 15);
	//
	uint32_t datacrc = crc32(0L, buf+20, len-20);
	sbuf[8] = datacrc>>24;
	sbuf[9] = datacrc>>16;
	sbuf[10] = datacrc>>8;
	sbuf[11] = datacrc;
	int newlen = camd35_padding(len);
	//mlogf(LOGDEBUG,0, " cs378x: send data\n"); debughex(sbuf, newlen+4);
	aes_encrypt( encryptkey, sbuf+4, newlen);
	return send_nonb( handle, sbuf, newlen+4, 100 );
}

int cs378x_recv(int handle, uint32_t ucrc, AES_KEY *decryptkey, unsigned char *buf)
{
	int received = recv_nonb( handle, buf, 32+4, 1000); // Get minimum packet size
	if (received<=0) return received; // Disconnect
	uint32_t ucrc1 = (buf[0]<<24)|(buf[1]<<16)|(buf[2]<<8)|buf[3];
	if (ucrc!=ucrc1) return -2; // wrong ucrc
	aes_decrypt( decryptkey, buf+4, received-4);
	//Fix for ECM request size > 255 (use ecm length field)
	int datalen = buf[5];
	if (buf[4] == 0) datalen = (((buf[25] & 0x0f) << 8) | buf[26]) + 3; // ECM
	else if ( (buf[4]&0xFC)==0x3C ) datalen = buf[5] | (buf[6] << 8); // cacheex
	else datalen = buf[5]; // Normal
	int newlen = 4+camd35_padding(20+datalen);
	if (received<newlen) {
		int n = recv_nonb( handle, buf+received, newlen-received, 500);
		if ( n != (newlen-received) ) return -3; // receive timeout or wrong packet size
		aes_decrypt( decryptkey, buf+received, n);
	}
	//mlogf(LOGDEBUG,getdbgflag(DBG_SERVER,0,srv->id)," msg from cs378x server (%s:%d)\n", srv->host->name, srv->port); debughex(buf, newlen);
	return newlen;
}


int cs378x_msg_peek(int handle, uint32_t ucrc, AES_KEY *decryptkey, unsigned char *buf)
{
	int len = recv( handle, buf, 32+4, MSG_NOSIGNAL|MSG_DONTWAIT); // Get minimum packet size
	if (len<=0) return len; // Disconnect
	//
	uint32_t ucrc1 = (buf[0]<<24)|(buf[1]<<16)|(buf[2]<<8)|buf[3];
	if (ucrc!=ucrc1) return -2; // wrong ucrc
	aes_decrypt( decryptkey, buf+4, len-4);
	//Fix for ECM request size > 255 (use ecm length field)
	int datalen = buf[5];
	if (buf[4] == 0) datalen = (((buf[25] & 0x0f) << 8) | buf[26]) + 3; // ECM
	else if ( (buf[4]&0xFC)==0x3C ) datalen = buf[5] | (buf[6] << 8); // cacheex
#ifndef PUBLIC
	else if ( (buf[4]&0xFE)==0x80 ) datalen = buf[5] | (buf[6] << 8); // ECM REQUEST
#endif
	else datalen = buf[5]; // Normal
	int newlen = 4+camd35_padding(20+datalen);
	if (len<newlen) {
		int n = recv( handle, buf+len, newlen-len, MSG_NOSIGNAL|MSG_DONTWAIT);
		if ( n != (newlen-len) ) return -3; // receive timeout or wrong packet size
		aes_decrypt( decryptkey, buf+len, n);
	}
	//mlogf(LOGDEBUG,getdbgflag(DBG_SERVER,0,srv->id)," msg from cs378x server (%s:%d)\n", srv->host->name, srv->port); debughex(buf, newlen);
	return newlen;
}


