#define MAX_ECM_DATA 9000
#define TIME_ECMALIVE 17000

#if __x86_64__ || __ppc64__
#define dcwcmp8(cw1, cw2) ( *((uint64_t*)(cw1))==*((uint64_t*)(cw2)) )
#define dcwcmp16(cw1, cw2) (( *((uint64_t*)(cw1))==*((uint64_t*)(cw2)) ) && ( *((uint64_t*)(cw1+8))==*((uint64_t*)(cw2+8)) ))
#else
#define dcwcmp8(cw1, cw2) (( *((uint32_t*)(cw1))==*((uint32_t*)(cw2)) ) && ( *((uint32_t*)(cw1+4))==*((uint32_t*)(cw2+4)) ))
#define dcwcmp16(cw1, cw2) (( *((uint32_t*)(cw1))==*((uint32_t*)(cw2)) ) && ( *((uint32_t*)(cw1+4))==*((uint32_t*)(cw2+4)) ) && ( *((uint32_t*)(cw1+8))==*((uint32_t*)(cw2+8)) ) && ( *((uint32_t*)(cw1+12))==*((uint32_t*)(cw2+12)) ))
#endif


#define ECM_SRV_REQUEST     0
#define ECM_SRV_REPLY_GOOD  1
#define ECM_SRV_REPLY_FAIL  2
#define ECM_SRV_EXCLUDE     3

// cachestatus
#define ECM_CACHE_NONE      0
#define ECM_CACHE_REQ       1
#define ECM_CACHE_REQ2      2
#define ECM_CACHE_REP       4
#define ECM_CACHE_CWC       8

typedef enum
{
	STAT_DCW_FAILED,	// decode failed
	STAT_DCW_WAIT,		// Wait servers answer
	STAT_DCW_WAITCACHE,	// Wait cached servers answer
	STAT_DCW_SUCCESS	// dcw returned 
} dcwstatus_type;


#define DCW_SOURCE_NONE      0
#define DCW_SOURCE_CACHE     1
#define DCW_SOURCE_SERVER    2
#ifdef SRV_CSCACHE
#define DCW_SOURCE_CSCLIENT  3
#define DCW_SOURCE_MGCLIENT  4
#endif
#define DCW_SOURCE_CCCLIENT  6

struct ecm_request {
	struct ecm_request *next;
	struct ecm_request *prev;

	struct ecm_request *csnext;
	struct ecm_request *csprev;

	struct cardserver_data *cs;
	// Ecm Data
	uint32_t recvtime;     // First request time in ms received from client
	uint32_t lastrecvtime; // Last request time received from client
	uint32_t lastsendtime; // Last request Time sent to server
	uint16_t sid;					// Service id
	uint16_t caid;				// CA id
	uint32_t provid;				// Provider
	uint16_t chid;				// for irdeto
	int ecmlen;
	uint8_t ecm[MAX_ECM_SIZE];
	uint32_t hash;
#ifdef CACHEEX
	unsigned char ecmd5[16]; //MD5_DIGEST_LENGTH];
#endif
	// DCW/Status
	dcwstatus_type dcwstatus;
	uint8_t cw[16];
	// DCW SOURCE
	int dcwsrctype;
	int dcwsrcid;
	//int peerid; // Cache PeerID sending dcw(0=nothing)

	int cw1cycle; // 0x80 / 0x81

	unsigned int checktime; // time when recheck the ecm.
	unsigned int waitserver; // wait for available server.

	unsigned char cachestatus;// 0:nothing sent;; 1:request sent;; 2:reply sent
	unsigned char cacheexstatus;// 0:nothing sent;; 1:request sent;; 2:reply sent

	char *statusmsg; // DCW status message

#ifdef CHECK_NEXTDCW
	// Last Successive ECM/DCW
	struct {	
		struct ecm_request *ecm; // NULL: nothing, else found last decode and checked
		uint8_t dcw[16];
		int error;
        int ecmid;
        int counter; // successif dcw counter * -1:error, 0: not found, 1: found and checked 1 time, 2: found and checked 2 times ...
		int cwcycle; // 0: CW0 next to cycle; 1: CW1 next to cycle
        uint32_t dcwchangetime;
	} lastdecode; // maybe we have 3 different channels with same caid:provid:sid ???
#endif

	// SERVERS that received ecm request
	struct {
		uint32_t srvid; // Server ID 0=nothing
		int flag; // 0=request , 1=reply, 2: excluded(server disconnected, card removed...)
		uint32_t sendtime; // ECM request sent time
		uint32_t statustime; // Last Status Time
		uint8_t dcw[16];
	} server[20]; 
	int server_totalsent;
	int server_totalwait;

	int waitcache; // 1: Wait for Cache; 0: dont wait

	int period; // ==1, number of retries to decode ecm. 

	uint32_t iplist[20]; 	// Clients ip list: to Remove Circular request: check for client ip & srv ip
	uint32_t srviplist[20]; 	// Clients ip list: to Remove Circular request: check for client ip & srv ip

#ifdef ECMLIST	// Clients list
	struct {
		void *cccam;
		void *mgcamd;
	} client;
#endif
};

typedef struct ecm_request ECM_DATA;

extern struct ecm_request *ecmdata;
extern int totalecm;

void init_ecmdata();
uint32_t ecm_crc( uint8_t *ecm, int ecmlen);
unsigned int hashCode( unsigned char *buf, int count);
inline uint8_t checkECMD5(uint8_t *ecmd5);

void ecm_addip( ECM_DATA *ecm, unsigned int ip);
int ecm_checkip(ECM_DATA *ecm, unsigned int ip);

uint32_t ecm_getprovid( uint8_t *ecm, uint16_t caid );
uint16_t ecm_getchid( uint8_t *ecm, uint16_t caid );

//struct ecm_request *store_ecmdata(struct cardserver_data *cs,uint8_t *ecm,int ecmlen, unsigned short sid, unsigned short caid, unsigned int provid);
struct ecm_request *search_ecmdata_dcw( uint8_t *ecm, int ecmlen, unsigned short sid);
struct ecm_request *search_ecmdata_any(struct cardserver_data *cs, uint8_t *ecm, int ecmlen, unsigned short sid, unsigned short caid);
struct ecm_request *search_ecmdata_byhash( uint16_t caid, uint16_t sid,uint32_t hash );
struct ecm_request *search_ecmdata_byecmd5( uint16_t caid, uint32_t provid, uint8_t ecmd5[16] );

int ecm_addsrv(ECM_DATA *ecm, unsigned srvid);
void ecm_addsrvip(ECM_DATA *ecm, unsigned int ip);
int ecm_checksrvip(ECM_DATA *ecm, unsigned int ip);
int ecm_nbsentsrv(ECM_DATA *ecm);
int ecm_nbwaitsrv(ECM_DATA *ecm);
int ecm_setsrvflag(ECM_DATA *ecm, unsigned int srvid, int flag);
int ecm_setsrvflagdcw(ECM_DATA *ecm, unsigned int srvid, int flag, uint8_t dcw[16]);
int ecm_getsrvflag(ECM_DATA *ecm, unsigned int srvid);


int ishalfnulledcw( uint8_t dcw[16] );

int ecmdata_check_cw( uint8_t tag, uint32_t hash, unsigned short caid, unsigned int provid , unsigned short sid, uint8_t cw[16], int cwpart );

#ifdef CHECK_NEXTDCW

void checkfreeze_storeECM(ECM_DATA *ecm);
void checkfreeze_checkECM( ECM_DATA *ecm, ECM_DATA *oldecm );
int checkfreeze_setdcw( ECM_DATA *ecm, uint8_t dcw[16] );

#endif
