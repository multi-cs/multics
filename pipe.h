
///////////////////////////////////////////////////////////////////////////////
//
///////////////////////////////////////////////////////////////////////////////

extern int frcc_pipe[2]; // newcamd server recv pipe

extern int dcwpipe[2];

// PIPE COMMANDS
#define PIPE_LOCK                1
#define PIPE_WAKEUP              2
#define PIPE_SENDCW              3

#define PIPE_SRV_CONNECTED       4
#define PIPE_SRV_AVAILABLE       5

#define PIPE_CLI_CONNECTED       6

#define PIPE_CACHE_FIND          11
#define PIPE_CACHE_FIND_FAILED   12
#define PIPE_CACHE_FIND_WAIT     13
#define PIPE_CACHE_FIND_SUCCESS  14

#define PIPE_CACHE_REQUEST       15
#define PIPE_CACHE_REPLY         16
#define PIPE_CACHE_RESENDREQ     17

#define PIPE_CACHEEX_PUSH_LOCAL  21
#define PIPE_CACHEEX_PUSH_REMOTE 22
//#define PIPE_CACHEEX_PUSH_OUT  23

#define PIPE_CACHEEX_PUSH_IN     24

#define PIPE_CARD_DEL            31
#define PIPE_CARD_ADD            32


// to check for EINTR
int pipe_read( int fd, uint8_t *buf, int len );
int pipe_write( int fd, uint8_t *buf, int len );
int pipe_purge( int fd );
int pipe_recv( int fd, uint8_t *buf );
int pipe_send( int fd, uint8_t *buf, int len );
void pipe_cmd( int pfd, int cmd );
void pipe_lock( int pfd );
void pipe_wakeup( int pfd );

