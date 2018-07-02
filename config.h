#include "ipdata.h"

#define MAX_ACCEPT_THREADS 500
#define KEEPALIVE_NEWCAMD	80


/// FLAGS defined in config
#define FLAG_DEFCONFIG   0x001
// FLAG_DISABLE: by user
#define FLAG_DISABLE     0x002
// FLAG_DISABLE: by user
#define FLAG_EXPIRED     0x004
// FLAG_DELETE: by config reader
#define FLAG_DELETE      0x008
// FLAG_DISCONNECT: by config reader, to reconnect
#define FLAG_DISCONNECT  0x010
//
#define FLAG_WORKTHREAD  0x100

// can send request
#define FLAG_CACHE_SENDREQ 0x0100
// can send reply
#define FLAG_CACHE_SENDREP 0x0200



#define IS_DISABLED(x)  ( x & (FLAG_DISABLE|FLAG_DELETE|FLAG_EXPIRED) )
//|FLAG_EXPIRED

#if TARGET == 3
#define MAX_SIDS 1024
#else
#define MAX_SIDS 4096
#endif

//Don't pack structs on ARM processors like RPI. It causes unaligned access exceptions
#ifdef NOPACK
#define PACK
#else
#define PACK __attribute__ ((__packed__))
#endif



struct sid_chid_data {
	uint16_t sid;
	uint16_t chid;
};

struct sid_chid_ecmlen_data {
	uint16_t sid;
	uint16_t chid;
	uint16_t ecmlen;
	uint8_t cw1cycle; // 1 - 2

	uint32_t ecmnb;
	uint32_t ecmok;
};


#define MAX_CSPORTS 200

struct sharelimit_data {
	uint16_t caid;
	uint32_t provid;
	uint8_t uphops; // 0: deny
};

struct ip2country_data {
	struct ip2country_data *next;
	uint32_t ipstart;
	uint32_t ipend;
	char code[70];
};

struct country_image_data {
	char code[3];
	char name[40];
	int len;
	uint8_t data[512];
};

struct chninfo_data
{
	struct chninfo_data *next;
	uint16_t sid;
	uint16_t caid;
	uint32_t prov;
	uint8_t cw1cycle;
	char name[0];
};

struct providers_data
{
	struct providers_data *next;
	uint32_t caprovid;
	char name[0];
};

struct sid_data
{
	struct sid_data *next;
	//uint8_t nodeid[8]; // CCcam nodeid card real owner, each server has many cards(locals+remote) and propably each server has different locals
	uint16_t sid;
	//uint16_t caid;
	uint32_t prov;
	int val;
};


#if TARGET == 3
#define CARD_MAXPROV 16
#else
#define CARD_MAXPROV 32
#endif

struct cs_card_data
{
	struct cs_card_data *next;
	uint32_t shareid;			// This is for CCcam
	uint32_t localid;			// This is for Fake CCcam Cards
#ifdef CCCAM_CLI
	uint8_t uphops;		// Max distance to get cards
	uint8_t dnhops;
	uint8_t nodeid[8]; // CCcam nodeid card real owner
#endif

	struct sid_data *sids[256]; // 0..FF

	// ECM Statistics
	int ecmerrdcw;  // null DCW/failed DCW checksum (diffeent dcw)
	int ecmnb;	// number of ecm's requested
	int ecmok;	// dcw returned to client
	int ecmoktime;

	uint16_t caid;		// Card CAID
	int  nbprov;				// Nb providers
	uint32_t prov[CARD_MAXPROV];		// Card Providers
};


struct host_data
{
	struct host_data *next;
	uint32_t flags;
	char name[256];
	uint32_t ip;
	uint32_t checkiptime;
	uint32_t clip; // client ip
};

/*
ECM total: 0 (average rate: 0/s)
ECM forwards: 0 
ECM cache hits: 0 
ECM denied: 0 
ECM filtered: 0 
ECM failures: 0
EMM total: 0
*/

struct sms_data {
	struct sms_data *next;
	int status; // bit 0 (0:in,1:out) bit 1 (0:unread/1:read)
	uint32_t hash;
	char msg[1024];
	time_t rawtime;
};

#define CACHE_PROG_DEFAULT 0
#define CACHE_PROG_CSP     1
#define CACHE_PROG_MULTICS 2

#define PEER_OFFLINE       0
#define PEER_ONLINE        1


struct PACK cachepeer_data
{
	// Config data
	struct cachepeer_data *next;
#ifdef PEERLIST
	struct cachepeer_data *nextReq; // Request Peers List
	struct cachepeer_data *nextRep; // Reply Peers List
	struct cachepeer_data *fnext;
#endif
	uint32_t flags;
	uint32_t id; // unique id
	uint32_t srvid; // unique id

	struct host_data *host;
	uint16_t port;

	int fblock0onid;
	int csp;
	int autoadd;
	int fwd; // forward cache

	//number of hits for each profile
	struct {
		int csid;
		int hits;
	} csporthit[MAX_CSPORTS];
#ifndef PUBLIC
	// Share Limits
	struct sharelimit_data sharelimits[100];
#endif

	//## Runtime Data
	int runtime; // Added At Runtime

	struct sms_data *sms;

	int outsock;
	uint16_t recvport;
	int status;
	int ping; // <=0 : inactive
	uint32_t lastpingnb; // last ping counter (if failed)
	uint32_t lastpingsent; // last ping sent to peer
	uint32_t lastpingrecv; // last ping received from peer after a ping request

	char program[32]; // Program Name
	char version[32]; // Program version
#ifdef NEWCACHE
	int protocol; // Cache Protocol Version (0:CSP Protocol)
	int ismultics;
#endif

	// All Peer Card List
	uint32_t cards[1024];
	int nbcards;
	// Compatible card list with profiles
	uint32_t comcards[1024];
	int nbcomcards;

	int ipoll;
	//Stat
	int sentreq;
	int sentrep;
	//
	uint8_t crc[4];
/*
	int totreq; // total received requests (+errors)
	int totrep; // total received replies (+errors)
	int rep_badheader; // wrong header
	int rep_badfields; // badfields blocked replies
	int rep_failed; // failed replies
	int rep_baddcw;
*/
	int reqnb; // Total Requests
	int repok; // Total Replies
	int hitnb; // All DCW transferred to clients
	int ihitnb; // Instant Hits

	//int hitfwd;  // Hits forwarded to peer

	//Last Used Cached data
	uint16_t lastcaid;
	uint32_t lastprov;
	uint16_t lastsid;
	uint32_t lastdecodetime;

};

///////////////////////////////////////////////////////////////////////////////

typedef enum
{
	STAT_DCW_SENT,	// no ecm found / DCW was sent to client
	STAT_ECM_SENT,	// ECM was sent to server
	STAT_ECM,		// ECM is waiting to be send
	STAT_DCW		// DCW is waiting to be send
} sendstatus_type;

// CLIENT FLAGS

struct client_info_data
{
	struct client_info_data *next;
	char name[32];
	char value[256];
};

struct PACK cs_client_data
{
	struct cs_client_data *next;
	uint32_t flags;
	uint32_t id; // unique id
	uint32_t pid; // Profile id
	struct cardserver_data *cs;
	uint32_t gid;
	// User/Pass
	char user[64];
	char pass[64];
	uint32_t userhash;
	//
	uint8_t type; // Clients type: NEWCAMD
	// Card
	struct cs_card_data card;
	// Client Info Data
	struct client_info_data *info;
	char *realname;
#ifdef EXPIREDATE
	struct tm enddate;
#endif
	struct host_data *host;
#ifdef CHECK_NEXTDCW
	int dcwcheck;
#endif

	//## Runtime Data (DYNAMIC)
	uint32_t ip;
	int handle;
	int ipoll;
	uint32_t chkrecvtime; // message recv time
	//
	uint16_t progid; // program id ex: 0x4343=>CCcam/ 0x0000=>Generic
	// Connection time
	struct {
		int status; // 0: not connected / -1: Connecting... / 1: Connected
		uint32_t time; // Last connection time
		uint32_t lastseen; // Last connected time
		uint32_t uptime;
	} connection;

	// Session Key
	uint8_t sessionkey[16];
	struct message_data msg;
	// ECM Stat
	int ecmnb;	// ecm number requested by client
	int ecmdenied;	// ecm number requested by client
	int ecmok;	// dcw returned to client
	int ecmoktime;
	uint32_t lastactivity; // Last Received Packet
	uint32_t lastecmtime; // Last ecm time, if it was more than 5mn so reconnect to client
	uint32_t lastdcwtime; // last good dcw time sent to client

#ifdef SRV_CSCACHE
	int cachedcw; // dcw from client
#endif

	int freeze; //a freeze: is a decode failed to a channel opened last time within 3mn
	int zap;
	int nblogin; // Total Number of logins
	int nbloginerror; // Total Number of logins
	int nbdiffip; // Total Number of logins with different IP's

	// ECM
	struct {
		int busy; // if ecmbusy dont process anyother ecm until that current ecm was finished
		sendstatus_type status; // answer was sent to client?
		// Ecm Data
		uint32_t recvtime; // ECM Receive Time in ms
		ECM_DATA *request;
		uint32_t hash; // to check for ecm
		int climsgid; // MessageID for the ecm request
	} ecm;

	//Last Used Share Saved data
	struct {
		ECM_DATA *request;
		uint16_t caid;
		uint32_t prov;
		uint16_t sid;
		uint32_t hash;
		uint8_t tag;
		int status;
		uint8_t dcw[16];
		int dcwsrctype;
		int dcwsrcid;
		uint32_t cardid;
		uint32_t decodetime;
	} lastecm; // Last decoded ecm

};


#ifdef RADEGAST_SRV

struct PACK rdgd_client_data { // Connected Client
	struct rdgd_client_data *next;
	uint32_t flags;
	uint32_t id; // unique id

	// Share Limits
	struct sharelimit_data sharelimits[100];
	// Client Info Data
	struct client_info_data *info;
	char *realname;
#ifdef EXPIREDATE
	struct tm enddate;
#endif
	struct host_data *host;

	//## Runtime Data (DYNAMIC)
	uint32_t ip;
	int handle;
	int ipoll;
	uint32_t chkrecvtime; // message recv time

	// Connection time
	uint32_t connected;
	uint8_t type;
	// ECM Stat
	int ecmnb;	// ecm number requested by client
	int ecmdenied;	// ecm number requested by client
	int ecmok;	// dcw returned to client
	int ecmoktime;
	uint32_t lastactivity; // Last Received Packet
	uint32_t lastecmtime; // Last ecm time, if it was more than 5mn so reconnect to client
	uint32_t lastdcwtime; // last good dcw time sent to client
	//
	int freeze; //a freeze: is a decode failed to a channel opened last time within 3mn
	int zap;
	int nblogin; // Total Number of logins
	int nbloginerror; // Total Number of logins
	int nbdiffip; // Total Number of logins with different IP's

	struct {
		int busy; // if ecmbusy dont process anyother ecm until that current ecm was finished
		sendstatus_type status; // answer was sent to client?
		// Ecm Data
		uint32_t recvtime; // ECM Receive Time in ms
		int id;
		//Last Used Share Saved data
		uint16_t lastcaid;
		uint32_t lastprov;
		uint16_t lastsid;
		int laststatus;
		// DCW SOURCE
		int lastdcwsrctype;
		int lastdcwsrcid;
		uint32_t lastcardid;
		uint32_t lastdecodetime;
		char *statmsg; // DCW Status Message
	} ecm;
};

#endif


#if defined(CAMD35_SRV) || defined(CS378X_SRV) || defined(CAMD35_CLI) || defined(CS378X_CLI)
#include "aes.h"
#endif


#if defined(CAMD35_SRV) || defined(CS378X_SRV)

struct PACK camd35_client_data { // Connected Client
	struct camd35_client_data *next;
	uint32_t flags;
	uint32_t id; // unique id

	struct client_info_data *info;
	char *realname;

	// User/Pass
	char user[64];
	char pass[64];
	uint32_t userhash;
	// Card
	struct cs_card_data card;
	// AES KEYS
	AES_KEY decryptkey;
	AES_KEY encryptkey;
	uint32_t ucrc;

#ifdef CACHEEX
	int cacheex_mode;
	uint8_t nodeid[8];
	//number of hits for each profile
	struct {
		int csid;
		int hits;
	} csporthit[MAX_CSPORTS];
#endif
	// Profiles
	uint16_t csport[MAX_CSPORTS];
	// Share Limits
	struct sharelimit_data sharelimits[100];

	//## Runtime Data (DYNAMIC)
	unsigned int ip; // Client ip
	int port; // Client port
	int handle; // udp
	int ipoll;
//	uint32_t chkrecvtime; // message recv time

	// Connection time
	struct {
		int status; // 0: not connected / -1: Connecting... / 1: Connected
		uint32_t time; // Last connection time
		uint32_t lastseen; // Last connected time
		uint32_t uptime;
	} connection;

	unsigned char type;
	// ECM Stat

	int ecmnb;	// ecm number requested by client
	int ecmdenied;	// ecm number requested by client
	int ecmok;	// dcw returned to client
	int ecmoktime;
	unsigned int lastecmtime; // Last ecm time, if it was more than 5mn so reconnect to client
	unsigned int lastdcwtime; // last good dcw time sent to client
	unsigned int lastactivity;
#ifdef CACHEEX
	struct {
		uint32_t push[10]; // Requests
		uint32_t got[10]; // Replies
		uint32_t badcw;
		uint32_t csp; // Replies from csp cache
		uint32_t hits; // ecm hits
		uint32_t ihits; // instant hits
		uint16_t lastcaid;
		uint32_t lastprov;
		uint16_t lastsid;
		uint32_t lastdecodetime;
	} cacheex;
#endif

#ifdef CHECK_NEXTDCW
	int dcwcheck;
#endif

	int freeze; //a freeze: is a decode failed to a channel opened last time within 3mn
	int zap;

	struct {
		int busy; // if ecmbusy dont process anyother ecm until that current ecm was finished
		sendstatus_type status; // answer was sent to client?
		// Ecm Data
		uint32_t recvtime; // ECM Receive Time in ms
		ECM_DATA *request;
		uint32_t hash; // to check for ecm
		int pin;
	} ecm;

	//Last Used Share Saved data
	struct {
		ECM_DATA *request;
		uint16_t caid;
		uint32_t prov;
		uint16_t sid;
		uint32_t hash;
		uint8_t tag;
		int status;
		uint8_t dcw[16];
		int dcwsrctype;
		int dcwsrcid;
		uint32_t cardid;
		uint32_t decodetime;
	} lastecm; // Last decoded ecm
/*
	struct {
		int busy; // if ecmbusy dont process anyother ecm until that current ecm was finished
		sendstatus_type status; // answer was sent to client?
		// Ecm Data
		uint32_t recvtime; // ECM Receive Time in ms
		int id;
		//Last Used Share Saved data
		uint16_t lastcaid;
		uint32_t lastprov;
		uint16_t lastsid;
		int laststatus;
		// DCW SOURCE
		int lastdcwsrctype;
		int lastdcwsrcid;
		uint32_t lastcardid;
		uint32_t lastdecodetime;
		char *statmsg; // DCW Status Message
	} ecm;
*/
};


struct camd35_server_data {
	struct camd35_server_data *next;
	uint32_t flags;
	struct camd35_client_data *client; // clients
	struct camd35_client_data *cacheexclient;
	int totalclients;
	int id;
	int port;
	int handle;
	int ipoll;
};

#endif

// cs : newcamd
// cc : cccam

struct cardserver_data
{
	struct cardserver_data *next;
	uint32_t flags;

	uint32_t id; // unique id
	char name[64];
	//NEWCAMD SERVER
	struct {
		struct cs_client_data *client;
		int totalclients;
		uint32_t flags;
		uint8_t key[16];
		int port; // output port
		SOCKET handle;
		int ipoll;
		// for faster poll()
		struct {
			struct pollfd pfd[NEWCAMD_MAX_PFD];
			int count;
			int update;
			int ipoll;
		} clipfd;
	} newcamd;
#ifdef RADEGAST_SRV
	struct {
		struct rdgd_client_data *client;
		uint32_t flags;
		int port; // output port
		SOCKET handle;
		int ipoll;
	} radegast;
#endif

	struct ecm_request *ecmdata;
	int totalecm;

	//CARD
	struct {
		uint16_t caid;		// Card CAID
		int  nbprov;				// Nb providers
		struct {
			uint32_t id;
			// SIDS
			struct {
				int deny;
				int total;
				struct sid_chid_ecmlen_data *data;
			} sidlist;
		} prov[CARD_MAXPROV];		// Card Providers
	} card;

	// SIDS
	struct {
		int deny;
		int total;
		struct sid_chid_ecmlen_data *data;
	} sidlist;

	//OPTIONS
	struct {
		uint16_t onid;

		struct {
			uint32_t timeout; // decode timeout in ms
#ifdef CHECK_NEXTDCW
			uint8_t check;
			uint8_t halfnulled;
#ifdef DCWSWAP
			uint8_t swap;
#endif
#endif
			int retry; // number of retries to decode ecm
		} dcw;

		uint8_t checkecm; // viaccess ecm
		uint8_t checkecmlength; // length header

		int maxfailedecm; // Max failed ecm per sid

		int faccept0sid;
		int faccept0provider;
		int faccept0caid;
		// share into servers
		int fsharecccam;
		int fsharenewcamd;
		int fsharemgcamd;
#ifndef PUBLIC
		int fshareexpired;
#endif

		// allow incoming dcw from...
		int fallowcccam;	// Allow cccam server protocol to decode ecm
		int fallownewcamd;	// Allow newcamd server protocol to decode ecm
		int fallowradegast;
		int fallowcamd35;
		int fallowcs378x;
		/*int fallowskipcwc;*/
		int fallowcache;
#ifdef CACHEEX
		int fallowcacheex;
		uint32_t cacheexvalidtime;
		struct {
			int maxhop;
		} cacheex;
#endif

		int cachetimeout;
		int cachesendreq;
		int cacheresendreq;
		int cachesendrep;
#ifndef PUBLIC
		int cachestatic; // Static/dynamic Timeout 
#endif

		int fmaxuphops; // allowed cards distance to decode ecm
		int cssendcaid; // flag send caid to servers
		int cssendprovid; // flag send provid to servers
		int cssendsid; // flag send sid to servers
		// Servers Config
		struct {
			uint32_t max;		// Maximum sevrer nb available to decode one ecm request
			uint32_t first; // on start request servers number
			uint32_t interval;    // interval between 2 same ecm request to diffrent server
			uint32_t timeout;     // timeout for resending ecm request to server
			uint32_t timeperecm;  // min time to senddo a request
			uint32_t validecmtime;  // max server ecm reply time
#ifndef PUBLIC
			uint32_t threshold; // Threshold of cs number to decode ecm
#endif
		} server;
		// Server Retry
		struct {
			int newcamd; // Newcamd Retries
			int cccam; // CCcam Retries
#ifdef RADEGAST_CLI
			int radegast; // Radegast Retries
#endif
		} retry;
	} option;

	int ecmlen[30];

	///////////////////////////////////////////////////////////////////////////

	struct {
		uint32_t csp;
#ifdef CACHEEX
		uint32_t cacheex;
#endif
		struct {
			uint32_t csp;
#ifdef CACHEEX
			uint32_t cacheex;
#endif
		} instant;
	} hits;

	///////////////////////////////////////////////////////////////////////////

	// ECM Stat
	int ecmaccepted;	// accepted ecm
	int ecmdenied;	// denied/filtred ecm
	int ecmok;	// good dcw
	int ecmoktime;

	int ttime[101]; // contains number of dcw/time (0.0s,0.1s,0.2s ... 2.9s)
	int ttimecache[101]; // for cache only
	int ttimecacheex[101]; // for cacheEX only
	int ttimecards[101]; // for cards only
#ifdef SRV_CSCACHE
	int ttimeclients[101]; // for cards only
#endif
	// Last Decode
	struct {
		void *ecm;
		uint32_t ecmtime; // Last ecm time, if it was more than 5mn so reconnect to client
		uint32_t dcwtime; // last good dcw time sent to client
	} last;

#ifndef PUBLIC
	struct {
		uint16_t sid;
		uint16_t nbsrv;
	} deniedsids[1024]; // Runtime deniedsids
#endif

	int ecmbusysrv; // nb of ecm returned with busy srv

};



///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

//server is in config
#define FLAGSRV_CONFIG  1

// Server/client type
#define TYPE_NEWCAMD    1
#define TYPE_CCCAM      2
#define TYPE_GBOX       3
#define TYPE_RADEGAST   4
#define TYPE_CAMD35     5
#define TYPE_CS378X     6



struct PACK server_data
{
	struct server_data *next;
	uint32_t flags;
	uint32_t id; // unique id
	//*** Config DATA
	uint8_t type; // Clients type: NEWCAMD/CCcam
	struct host_data *host;
	int port;
	char user[64];
	char pass[64];
#ifdef CACHEEX
	int cacheex_mode; // only for CCcam Server
	int cacheex_maxhop;
#ifndef PUBLIC
	int cacheex_forward;
#endif
	//number of hits for each profile
	struct {
		int csid;
		int hits;
	} csporthit[MAX_CSPORTS];
#endif

	pthread_mutex_t lock;
	pid_t pid;
	pthread_t tid;

	// Newcamd
	uint8_t key[16];
	// Profiles
	uint16_t csport[MAX_CSPORTS];
	// Server Priority
	int priority; // Priority Server
	// Share Limits
	struct sharelimit_data sharelimits[100];
	// ACCEPTED SIDs
	struct sid_chid_data *sids; // Accepted sids

	//*** DYNAMIC DATA
	char *progname; // Known names
	char version[32];
	uint8_t sessionkey[16];
	struct message_data msg;
#ifdef CLI_CSCACHE
	int cscached; // flag for newcamd cached servers
#endif
	int error;
	char *statmsg; // Connection Status Message
	//CCcam additional data
#ifdef CCCAM_CLI
	struct cc_crypt_block sendblock;	// crypto state block
	struct cc_crypt_block recvblock;	// crypto state block
	uint8_t nodeid[8];
	char build[32];
#endif

#if defined(CAMD35_CLI) || defined(CS378X_CLI)
	// AES KEYS
	AES_KEY decryptkey;
	AES_KEY encryptkey;
	uint32_t ucrc;
#endif

	//Connection Data
	SOCKET handle;
	int ipoll;
	uint32_t chkrecvtime; // message recv time
	struct cs_card_data *card;

	// Connection data
	struct {
		int status; // 0: not connected / -1: Connecting... / 1: Connected
		uint32_t time; // Last re/connection time
		uint32_t lastseen; // Last connected time
		uint32_t uptime;
		uint32_t delay; // delay for next reconnect
	} connection;

	// TCP Connection Keepalive
	uint32_t ping; // ping time;
	struct {
		uint32_t status; // CON: Keepalive packet was sent to server and we have no response. / DIS: Retry number of reconnection
		uint32_t time;   // CON: last Keepalive sent time / DIS: start time for trying connection
	} keepalive;

	// ECM Statistics
	int ecmtimeout; // number of errors for timeout (no cw returned by server)
	int ecmerrdcw;  // null DCW/failed DCW checksum (diffeent dcw)
	int ecmnb;	// total number of ecm requests
	int ecmok;	// dcw returned to client
	int ecmoktime;
	int ecmperhr;
	int hits;

#ifdef CACHEEX
	struct {
		uint32_t push[10]; // Requests
		uint32_t got[10]; // byhop
		uint32_t badcw;
		uint32_t csp; // Replies from csp cache
		uint32_t hits; // ecm hits
		uint32_t ihits; // instant hits
		uint16_t lastcaid;
		uint32_t lastprov;
		uint16_t lastsid;
		uint32_t lastdecodetime;
	} cacheex;
#endif

	// CURRENT ECM DATA
	int busy; // cardserver is busy (ecm was sent) / or not (no ecm sent/dcw returned)
	struct cs_card_data *busycard; // card
	uint32_t busycardid; // card
	struct {
		ECM_DATA *request;
		int id; // ecm id
		uint32_t hash; // to check for ecm
		uint32_t msgid;
	} ecm;

	// Last ECM Stat
	uint32_t lastecmoktime;
	uint32_t lastecmtime; // Last ecm time, if it was more than 5mn so reconnect to client
	uint32_t lastdcwtime; // last good dcw time sent to client

	int retry; // nb of retries of the current ecm request

	struct {
		int csid;
		int ecmnb;
		int ecmok;
		uint32_t ecmoktime;
		int hits; // Ecm hits got from this server 
	} cstat[MAX_CSPORTS];
};



#ifdef CCCAM_SRV

struct PACK cc_client_data { // Connected Client
	//### Config Data (STATIC)
	struct cc_client_data *next;
#ifdef ECMLIST
	struct cc_client_data *nextEcm; // In ECM List
#endif
	struct cc_client_data *inext; // fd fast lookup
	uint32_t flags;

	uint32_t id; // unique id
	struct cccam_server_data *parent;
	//fline
	char user[64];
	char pass[64];
	uint32_t userhash;
	uint8_t dnhops;		// Max Down Hops
	uint8_t uphops;		// Max distance to get cards
	uint8_t shareemus;		// Client use our emu
	uint8_t allowemm;		// Client has rights for au
#ifdef CACHEEX
	int cacheex_mode;
#endif
#ifdef CHECK_NEXTDCW
	int dcwcheck;
#endif

	struct {
#ifndef PUBLIC
		int checknodeid;
#endif
		uint8_t nodeid[8];
		char version[32];
	} option;

	// Profiles
	uint16_t csport[MAX_CSPORTS];
	// Share Limits
	struct sharelimit_data sharelimits[100];
	// Client Info Data
	struct client_info_data *info;
	char *realname;
#ifdef EXPIREDATE
	struct tm enddate;
#endif
	struct host_data *host;

//#ifndef PUBLIC
//	int badcw; // if yes => send badcw to client :D
//	int infraction; /// INFRACTION => FREEZE
//#endif

	//## Runtime Data (DYNAMIC)
	uint32_t ip;
	int handle;				// SOCKET
	int ipoll;
	uint32_t chkrecvtime; // message recv time
	// CCcam Connection Data
	struct cc_crypt_block sendblock;	// crypto state block
	struct cc_crypt_block recvblock;	// crypto state block
	struct message_data msg;
	// Connection time
	struct {
		int status; // 0: not connected / -1: Connecting... / 1: Connected
		uint32_t time; // Last connection time
		uint32_t lastseen; // Last connected time
		uint32_t uptime;
	} connection;
	// Client Info
	uint8_t nodeid[8];
	char version[32];
	char build[32];

	int cardsent; // flag

#ifdef CACHEEX
	//number of hits for each profile
	struct {
		int csid;
		int hits;
	} csporthit[MAX_CSPORTS];
#endif

	// ECM Stat
	int ecmnb;	// ecm number requested by client
	int ecmdenied;	// ecm number requested by client
	int ecmok;	// dcw returned to client
	int ecmoktime;

#ifdef CACHEEX
	struct {
		int push[10]; // Requests
		int got[10]; // Replies
		uint32_t badcw;
		int csp; // Replies from csp cache
		int hits; // ecm hits
		int ihits; // instant hits
		uint16_t lastcaid;
		uint32_t lastprov;
		uint16_t lastsid;
		uint32_t lastdecodetime;
	} cacheex;
	pid_t pid;
	pthread_t tid;
#endif

	// last packets time
	uint32_t lastactivity; // Last Received Packet
	uint32_t lastecmtime; // Last ecm time, if it was more than 5mn so reconnect to client
	uint32_t lastdcwtime; // last good dcw time sent to client

	int freeze; //a freeze: is a decode failed to a channel opened last time within 3mn
	int zap;
	int nblogin; // Total Number of logins
	int nbloginerror; // Total Number of logins
	int nbdiffip; // Total Number of logins with different IP's
	int nbdcwerr; // dcw sent to client but not client never received it !!!

	// Current ecm request data
	struct {
		int busy; // if ecmbusy dont process anyother ecm until that current ecm was finished
		sendstatus_type status; // answer was sent to client?
		uint32_t cardid;
		// Ecm Data
		uint32_t recvtime; // ECM Receive Time in ms
		ECM_DATA *request; //ecmid
		uint32_t hash; // to check for ecm
		char *statmsg; // DCW Status Message
	} ecm; // current ecm to decode

	//Last Used Share Saved data
	struct {
		ECM_DATA *request;
		uint16_t caid;
		uint32_t prov;
		uint16_t sid;
		uint32_t hash;
		uint8_t tag;
		int status;
		uint8_t dcw[16];
		int dcwsrctype;
		int dcwsrcid;
		uint32_t cardid;
		uint32_t decodetime;
	} lastecm; // Last decoded ecm

};

#endif

#ifdef CCCAM

struct cccam_server_data {
#ifdef CCCAM_SRV
	struct cccam_server_data *next;
	uint32_t flags;
	struct cc_client_data *client;
	struct cc_client_data *cacheexclient;
	int totalclients;
	int id;
	int handle;
	int ipoll;
	int port; // output port
	struct ip_hacker_data *iplist;
	// for faster poll()
	struct {
		struct pollfd pfd[CCCAM_MAX_PFD];
		int count;
		int update;
		int ipoll;
	} clipfd;
#endif
};

#endif





#ifdef MGCAMD_SRV

struct PACK mg_client_data
{
	struct mg_client_data *next;
#ifdef ECMLIST
	struct mg_client_data *nextEcm; // In ECM List
#endif
	uint32_t flags;

	uint32_t id; // unique id
	struct mgcamdserver_data *parent;
	// NEWCAMD SPECIFIC DATA
	char user[64];
	char pass[64];
	uint32_t userhash;
#ifndef PROXY
	int proxy;
#endif
	// Profiles
	uint16_t csport[MAX_CSPORTS];
	// Share Limits
	struct sharelimit_data sharelimits[100];
	// Client Info Data
	struct client_info_data *info;
	char *realname;
#ifdef EXPIREDATE
	struct tm enddate;
#endif
	struct host_data *host;
#ifdef CHECK_NEXTDCW
	int dcwcheck;
#endif

#ifndef PUBLIC
	int badcw; // if yes => send badcw to client :D
	int infraction; /// INFRACTION => FREEZE
#endif

	//## Runtime Data (DYNAMIC)
	uint32_t ip;
	SOCKET handle;
	int ipoll;
	uint32_t chkrecvtime; // message recv time
	uint16_t progid; // program id ex: 0x4343=>CCcam/ 0x0000=>Generic
	uint8_t sessionkey[16];
	struct message_data msg;
	// Connection time
	// Connection time
	struct {
		int status; // 0: not connected / -1: Connecting... / 1: Connected
		uint32_t time; // Last connection time
		uint32_t lastseen; // Last connected time
		uint32_t uptime;
	} connection;

	int cardsent; // flag 0:none, 1:default, 2:all
	// ECM Stat
	int ecmnb;	// ecm number requested by client
	int ecmdenied;	// ecm number requested by client
	int ecmok;	// dcw returned to client
	int ecmoktime;
	uint32_t lastactivity; // Last Received Packet
	uint32_t lastecmtime; // Last ecm time, if it was more than 5mn so reconnect to client
	uint32_t lastdcwtime; // last good dcw time sent to client

	int freeze; //a freeze: is a decode failed to a channel opened last time within 3mn
	int zap;
	int nblogin; // Total Number of logins
	int nbloginerror; // Total Number of logins
	int nbdiffip; // Total Number of logins with different IP's

#ifdef SRV_CSCACHE
	int cachedcw; // dcw from client
#endif

	struct {
		int busy; // if ecmbusy dont process anyother ecm until that current ecm was finished
		sendstatus_type status; // answer was sent to client?
		// Ecm Data
		uint32_t recvtime; // ECM Receive Time in ms
		ECM_DATA *request;
		uint32_t hash; // to check for ecm
		int climsgid;
	} ecm;

	//Last Used Share Saved data
	struct {
		ECM_DATA *request;
		uint16_t caid;
		uint32_t prov;
		uint16_t sid;
		uint32_t hash;
		uint8_t tag;
		int status;
		uint8_t dcw[16];
		int dcwsrctype;
		int dcwsrcid;
		uint32_t cardid;
		uint32_t decodetime;
	} lastecm; // Last decoded ecm

};


struct mgcamdserver_data {
	struct mgcamdserver_data *next;
	uint32_t flags;
	struct mg_client_data *client;
	int totalclients;

	int id;
	int handle;
	int ipoll;
	int port;

	uint16_t csport[MAX_CSPORTS]; // default cards
	uint8_t key[16];

	struct ip_hacker_data *iplist;
	// for faster poll()
	struct {
		struct pollfd pfd[MGCAMD_MAX_PFD];
		int count;
		int update;
		int ipoll;
	} clipfd;
};

#endif


///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

#ifdef PEERLIST
#define MAX_PEER_INDEX  0xFFF
#endif

struct cacheserver_data {
	struct cacheserver_data *next;
	uint32_t flags;
	struct cachepeer_data *peer;  // All PEERS
#ifdef PEERLIST
	struct cachepeer_data *peerReq; // Connected Peers for request
	struct cachepeer_data *peerRep; // Connected Peers for reply
	struct cachepeer_data *fpeer[MAX_PEER_INDEX+1]; // Hash table of Peers
#endif
	int totalpeers;
	//
	int id;
	int handle;
	int ipoll;
	int port;
	//
	int hits;  // Total Hits
	int ihits; // Instant Hits
	int req; // Request sent
	int rep; // Replies
};


struct dcw_data {
	struct dcw_data *next;
	uint8_t dcw[16];
};

struct filename_data
{
	struct filename_data *next;
	char name[512];
	int wd;
	int nowatch;
	int noeditor;
};


#ifdef HTTP_SRV
struct http_file_data {
	struct http_file_data *next;
	char path[512];
	char url[512];
	char mime[512];
};
#endif


// Configurable Data
struct config_data
{
#ifndef PUBLIC
	struct host_data *srvhost;
#endif
	struct filename_data *files;
	char stylesheet_file[256];
    char javascript_file[256];
	char channelinfo_file[256];
	char providers_file[256];
	char ip2country_file[256];
	struct ip2country_data *ip2country;
	struct chninfo_data *chninfo;
	struct providers_data *providers;

	char blockcountry[512][3];

#ifdef TESTCHANNEL
	struct {
		uint16_t caid;
		uint32_t provid;
		uint16_t sid;
	} testchn;
#endif

#ifdef TWIN
	struct {
		struct {
			char fname[256];
			int count;
			struct {
				char name[256];
				uint16_t caid;
				uint32_t prov;
				uint8_t sid;
				uint16_t deg;
				uint16_t freq;
				uint8_t cw1cycle;
				struct {
					uint32_t rtime;
					char cw[16];
					char prevcw[16];
					uint8_t cwcycle;
					int error;
				} ecm;
			} data[512];
		} chninfo;
		struct {
			char device[256];
			int handle;
		} serial;
	} twin;
#endif

	// UniqueID counters
	int clientid;
	int serverid;
	int cardserverid; // Profiles

	struct dcw_data *bad_dcw;

	struct {
		struct cacheserver_data *server;
		int totalservers;
		int peerid;
		int serverid;

		int autoadd;
		int autoenable;
		int faccept0onid;
		int alivetime;
		int filter;
		int filtertime;
		int threshold;
#ifndef PUBLIC
		int dcwcheck2;
		int dcwcheck3;
#endif
		int forward;
		int hits;  // Total Hits
		int ihits; // Instant Hits
		int req; // Request sent
		int rep; // Replies

		uint16_t caids[32];
		pid_t pid_recvmsg;
		pthread_t tid_recvmsg;
		pid_t pid_pipe;
		pthread_t tid_pipe;

		uint32_t speed; // packets / second
	} cache;

	uint8_t nodeid[8];

#ifdef CACHEEX
	// CACHE SERVERS
	struct {
		int hits;  // Total Hits
		int ihits; // Instant Hits
		int req; // Request sent
		int rep; // Replies
		//int alivetime;
		pid_t pid_pipe;
		pthread_t tid_pipe;
	} cacheex;
#endif

	//SERVERS
	struct {
		int clientid;
		int dcwcheck;
		int keepalive;
	} newcamd;
	struct server_data *server;
	struct server_data *cacheexserver;
	int totalservers;

	// Host List
	struct host_data *host; 

	//CS PROFILES
	struct cardserver_data *cardserver;
	int totalprofiles;

#ifdef CCCAM
	struct {
		struct cccam_server_data *server;
		int totalservers;
		int clientid; // CCcam Clients
		int serverid; // CCcam Servers
		char version[32];
		char build[32];
		uint16_t csport[MAX_CSPORTS]; // default cards
		int dcwcheck;
		int keepalive;
		pid_t pid_recvmsg;
		pthread_t tid_recvmsg;
		pid_t pid_connect;
		pthread_t tid_connect;
	} cccam;
#endif

#ifdef FREECCCAM_SRV
	struct {
		struct cccam_server_data server;
		int clientid; // CCcam Clients
		int serverid; // CCcam Servers
		char version[32];
		char build[32];
		char user[64];
		char pass[64];
		int maxusers;
		uint16_t csport[MAX_CSPORTS]; // default cards
		pid_t pid_recvmsg;
		pthread_t tid_recvmsg;
		pid_t pid_connect;
		pthread_t tid_connect;
	} freecccam;
#endif


#ifdef MGCAMD_SRV
	struct {
		struct mgcamdserver_data *server;
		int totalservers;
		int clientid; // mgcamd Clients
		int serverid; // mgcamd Servers
		uint16_t csport[MAX_CSPORTS]; // default cards
		int dcwcheck;
		int keepalive;
		pid_t pid_recvmsg;
		pthread_t tid_recvmsg;
		pid_t pid_connect;
		pthread_t tid_connect;
	} mgcamd;
#endif


#ifdef CAMD35_SRV
	struct {
		struct camd35_server_data *server;
		int totalservers;
		int clientid;
		int serverid;
		pid_t pid_recvmsg;
		pthread_t tid_recvmsg;
		pid_t pid_connect;
		pthread_t tid_connect;
	} camd35;
#endif
#ifdef CS378X_SRV
	struct {
		struct camd35_server_data *server;
		int totalservers;
		int clientid;
		int serverid;
		int keepalive;
		pid_t pid_recvmsg;
		pthread_t tid_recvmsg;
		pid_t pid_connect;
		pthread_t tid_connect;
	} cs378x;
#endif

	//WEBIF
#ifdef HTTP_SRV
	struct {
		int port;
		int handle;
		char user[64];
		char pass[64];
		// Show flags
		struct {
			int nodebug;
			int nocache;
			int noservers;
			int noprofiles;
			int nocacheex;
			int nomgcamd;
			int nonewcamd;
			int nocccam;
			int noeditor;
			int norestart;
		} show;
		int autorefresh;
		char title[512];
		struct http_file_data *files;
		pid_t pid;
		pthread_t tid;
	} http;
#endif

#ifdef TELNET
	struct {
		int port;
		int handle;
		char user[64];
		char pass[64];
		pid_t pid;
		pthread_t tid;
	} telnet;
#endif
	struct {
		uint32_t thread;
		uint32_t connect;
	} delay;

	void *lastecm;

	struct {
		uint32_t time;
		int count; 
	} failban;
};

// Static Data
struct program_data
{
	int restart;
#ifndef PUBLIC
	int updatenodes;
#endif

	struct timeval exectime; // last dcw time sent to client

	//PROCESS_ID
	pid_t pid_main;
	pid_t pid_cfg;
	pid_t pid_dns;
	pid_t pid_srv;


	pid_t pid_mg_msg;
	pid_t pid_cs_msg;
	pid_t pid_cc_msg;
	pid_t pid_connect;

	pid_t pid_msg;
	pthread_t tid_msg;

	pid_t pid_setdcw;
	pthread_t tid_setdcw;

	pid_t pid_cache;
	pthread_t tid_cache;

	pid_t pid_cache_pipe;
	pthread_t tid_cache_pipe;

#ifdef CACHEEX
	pid_t pid_ccex_msg;
	pthread_t tid_cacheex;
	pthread_mutex_t lockcacheex;
#endif

	//THREAD_ID
	pthread_t tid_cfg;
	pthread_t tid_dns;
	pthread_t tid_srv;

	pthread_t tid_date;
	pid_t pid_date;
	pthread_mutex_t lockthreaddate;

	pthread_mutex_t lockcache;

	pthread_mutex_t lock;		// ECM DATA(main data)
	pthread_mutex_t lockcli;	// CS Clients data
	pthread_mutex_t locksrv;	// CS Servers data
	// THREADS
	pthread_mutex_t locksrvth; // Servers connection thread
	pthread_mutex_t locksrvcs; // Newcamd server
	pthread_mutex_t lockdnsth; // DNS lookup Thread

#ifdef CCCAM_SRV
	pthread_mutex_t lockcccli; // CCcam Clients data
	pthread_mutex_t locksrvcc; // CCcam server
#endif
#ifdef FREECCCAM_SRV
	pthread_mutex_t lockfreecccli; // FreeCCcam Clients data
	pthread_mutex_t locksrvfreecc; // FreeCCcam server
#endif
	pthread_mutex_t lockrdgdcli; // Radegast Clients
	pthread_mutex_t lockrdgdsrv; // Radegast Server

#ifdef MGCAMD_SRV
	pthread_mutex_t lockclimg;	// CCcam Clients data
	pthread_mutex_t locksrvmg; // CCcam server
#endif

	pthread_mutex_t lockmain; // Check ECM/DCW Thread
	pthread_mutex_t lockecm;

	pthread_mutex_t lockhttp; // http Thread
	pthread_mutex_t lockdns;

	pthread_mutex_t lockdcw;


	struct {
		int servers;
		int cache; // 
		int cccam;
		int freecccam;
		int mgcamd;
		int newcamd;
		int ecm;
		struct {
			int cccam;
			int mgcamd;
		} con;
	} epoll;


	struct {
		int ecm[2];
		int cccam[2];
		int freecccam[2];
		int cccam_cex[2];
		int mgcamd[2];
		int newcamd[2];
		int cache[2];
		int cacheex[2];
		int cs378x[2];
		int cs378x_cex[2];
		struct {
			int cccam[2];
			int mgcamd[2];
		} con;
	} pipe;

	uint8_t nodeid[8]; // Default Random nodeid 
	int currentloglevel; // Loglevel of multics
};

extern struct program_data prg;
extern char config_file[256];

void init_config(struct config_data *cfg);
int read_config(struct config_data *cfg);

int read_cccam_nodeid( struct config_data *cfg );
int read_chinfo( struct config_data *cfg );
void free_chinfo( struct config_data *cfg );
int read_ip2country( struct config_data *cfg );
void free_ip2country( struct config_data *cfg );
int read_providers( struct config_data *cfg );
void free_providers( struct config_data *cfg );

void reread_config( struct config_data *cfg );
int check_config(struct config_data *cfg);
int done_config(struct config_data *cfg);
void cfg_set_id_counters(struct config_data *cfg);

void free_card(struct cs_card_data* card);
void free_cardlist(struct cs_card_data* card);

struct host_data *add_host( struct config_data *cfg, char *hostname);
void cfg_addcachepeer(struct cacheserver_data *srv, struct cachepeer_data *peer);
void free_filenames( struct config_data *cfg );

//216.155.145.232 

#define IP_ADRESS 0
//( (1<<24) | (0<<16) | (0<<8) | 127 )


#if (IP_ADRESS==0)
#define CHECK_IP_ADRESS(s) ;
#else
#define CHECK_IP_ADRESS(s) 	if (s>0) { struct sockaddr_in sa; socklen_t sa_len = sizeof(sa); if (getsockname(s, (struct sockaddr*)&sa, &sa_len)==-1) pthread_exit(0); if (IP_ADRESS!=sa.sin_addr.s_addr) pthread_exit(0); }
#endif

