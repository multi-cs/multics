
unsigned int hostname2ip( const char *hostname );
char *ip2string( unsigned int hostaddr );
char *iptoa(char *dest, unsigned int ip );

// SOCKET OPTIONS
int SetSocketTimeout(SOCKET sockid, int milliseconds);
int SetSocketNoDelay(SOCKET sock);
int SetSocketKeepalive(SOCKET sock);
void SetSoketNonBlocking(SOCKET sock);
int SetSocketReuseAddr(int sock);
// UDP CONNECTION
int CreateServerSockUdp(int port, uint32_t ip);
int CreateClientSockUdp(int port, uint32_t ip);
// TCP CONNECTION
int CreateServerSockTcp(int port, uint32_t ip);
int CreateClientSockTcp(unsigned int netip, int port);
// TCP NON BLOCKED CONNECTION
int CreateClientSockTcp_nonb(unsigned int netip, int port);
int recv_nonb(int sock,uint8_t *buf,int len,int timeout);
int send_nonb(int sock,uint8_t *buf,int len,int to);
int CreateServerSockTcp_nonb(int port, uint32_t ip);
