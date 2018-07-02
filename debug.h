#define DBG_ALL         0x00
#define DBG_CCCAM       0x01
#define DBG_CACHE       0x02
#define DBG_NEWCAMD     0x03
#define DBG_MGCAMD      0x04
#define DBG_SERVER      0x05
#define DBG_CONFIG      0x06
#define DBG_HTTP        0x07
#ifdef CACHEEX
#define DBG_CACHEEX     0x08
#endif
#define DBG_ERROR       0x09
#define DBG_CAMD35      0x10
#define DBG_CS378X      0x11

//#define LOGCRITICAL 0
//#define LOGERROR 1
//#define LOGWARNING 2
//#define LOGINFO 3
//#define LOGDEBUG 4
//#define LOGTRACE 5

struct trace_data {
	char host[32];
	int port;
	unsigned int ip;
	int sock;
	struct sockaddr_in addr;
};

extern int flag_debugscr;
#ifdef DEBUG_NETWORK
extern int flag_debugnet;
#endif
extern int flag_debugfile;
extern char debug_file[256];
extern int loglevel;

extern int flag_debugtrace;
extern struct trace_data trace;

extern uint32_t flagdebug;

#define MAX_DBGLINES 70
#define MAX_DBGLINE_LEN 4000
extern char dbgline[MAX_DBGLINES][MAX_DBGLINE_LEN];
extern int idbgline;

uint32_t getdbgflag( int i, int j, int k);
uint32_t getdbgflagpro( int i, int j, int k, int csid );

char* debugtime(char *str);
void debug(char *str);

void mlogf( int lineloglevel,uint32_t flag, char *format, ...);
void debughex(uint8_t *buffer, int len);

void fdebug(char *str);
void fdebugf(char *format, ...);

