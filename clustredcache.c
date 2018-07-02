//Don't pack structs on ARM processors like RPI. It causes unaligned access exceptions
#ifdef NOPACK
#define PACK
#else
#define PACK __attribute__ ((__packed__))
#endif

void stringtohtml(char *src, char *dest)
{
	while ( *src )
	{
		if ( *src=='<' ) {
			*dest = '&'; dest++;
			*dest = 'l'; dest++;
			*dest = 't'; dest++;
			*dest = ';'; dest++;
		}
		else if ( *src=='>' ) {
			*dest = '&'; dest++;
			*dest = 'g'; dest++;
			*dest = 't'; dest++;
			*dest = ';'; dest++;
		}
		else if ( *src=='&' ) {
			*dest = '&'; dest++;
			*dest = 'a'; dest++;
			*dest = 'm'; dest++;
			*dest = 'p'; dest++;
			*dest = ';'; dest++;
		}
		else if ( *src=='"' ) {
			*dest = '&'; dest++;
			*dest = 'q'; dest++;
			*dest = 'u'; dest++;
			*dest = 'o'; dest++;
			*dest = 't'; dest++;
			*dest = ';'; dest++;
		}
		else {
			*dest = *src; dest++;
		}
		src++;
	}
	*dest = 0;
}

#ifdef PEERLIST
void fpeer_update(struct cacheserver_data *cache)
{
	memset( cache->fpeer, 0, sizeof(cache->fpeer) ); // NULL
	struct cachepeer_data *peer = cache->peer;
	while (peer) {
		if ( peer->host->ip ) {
			int index = peer->host->ip & MAX_PEER_INDEX;
			peer->fnext = cache->fpeer[index];
			cache->fpeer[index] = peer;
		} else peer->fnext = peer;
		peer = peer->next;
	}
}

//// Connected Peers
void ipeer_update(struct cacheserver_data *cache)
{
	cache->peerReq = NULL;
	cache->peerRep = NULL;
	struct cachepeer_data *peer = cache->peer;
	while (peer) {
		if (peer->ping>0) {
			if (peer->flags&FLAG_CACHE_SENDREQ) {
				peer->nextReq = cache->peerReq;
				cache->peerReq = peer;
			}
			if (peer->flags&FLAG_CACHE_SENDREP) {
				peer->nextRep = cache->peerRep;
				cache->peerRep = peer;
			}
		}
		else {
			peer->nextRep = NULL;
			peer->nextRep = NULL;
		}
		peer = peer->next;
	}
}
#endif

// 0: removed
int peer_doublecheck(struct cacheserver_data *cache, struct cachepeer_data *xpeer)
{
	struct cachepeer_data *peer = cache->peer;
	struct cachepeer_data *previous = NULL;
	while (peer) {
		if (peer!=xpeer)
		if (peer->port==xpeer->port)
		if (peer->host->ip==xpeer->host->ip) {
			if (peer->runtime) {
				if (previous) previous->next = peer->next; else cache->peer = peer->next;
				//close(peer->outsock);
				free( peer );
#ifdef PEERLIST
				ipeer_update(cache);
				fpeer_update(cache);
#endif
				return 0;				
			}
			else if (xpeer->runtime) peer_doublecheck(cache, peer);
			return 1;
		}
		previous = peer;
		peer = peer->next;
	}
	return 1;
}



///////////////////////////////////////////////////////////////////////////////
//
///////////////////////////////////////////////////////////////////////////////

#define PEER_CSP            0x010000
#define PEER_CCCAM_CLIENT   0x020000
#define PEER_CAMD35_CLIENT	0x040000
#define PEER_CS378X_CLIENT	0x080000
#define PEER_CACHEEX_SERVER	0x100000

#ifdef PEERLIST
struct cachepeer_data *getpeerbyaddr(struct cacheserver_data *cache, uint32_t ip, uint16_t port)
{
	int index = ip & MAX_PEER_INDEX;
	struct cachepeer_data *peer = cache->fpeer[index];
	while (peer) {
		if ( (peer->host->ip==ip)&&(peer->recvport==port) ) return peer;
		peer = peer->fnext;
	}
	return NULL;
}
#else
struct cachepeer_data *getpeerbyaddr(struct cacheserver_data *cache, uint32_t ip, uint16_t port)
{
	struct cachepeer_data *peer = cache->peer;
	while(peer) {
		if ( (peer->host->ip==ip)&&(peer->recvport==port) ) return peer;
		peer = peer->next;
	}
	return NULL;
}
#endif

struct cachepeer_data *getpeerbyid(int id)
{
	struct cacheserver_data *cache = cfg.cache.server;
	while (cache) {
		struct cachepeer_data *peer = cache->peer;
		while(peer) {
			if (peer->id==id) return peer;
			peer = peer->next;
		}
		cache = cache->next;
	}
	return NULL;
}

///////////////////////////////////////////////////////////////////////////////
// Multics ID encryption
///////////////////////////////////////////////////////////////////////////////

static unsigned char T1[]={
  0x2a,0xe1,0x0b,0x13,0x3e,0x6e,0x32,0x48,
  0xd3,0x31,0x08,0x8c,0x8f,0x95,0xbd,0xd0,
  0xe4,0x6d,0x50,0x81,0x20,0x30,0xbb,0x75,
  0xf5,0xd4,0x7c,0x87,0x2c,0x4e,0xe8,0xf4,
  0xbe,0x24,0x9e,0x4d,0x80,0x37,0xd2,0x5f,
  0xdb,0x04,0x7a,0x3f,0x14,0x72,0x67,0x2d,
  0xcd,0x15,0xa6,0x4c,0x2e,0x3b,0x0c,0x41,
  0x62,0xfa,0xee,0x83,0x1e,0xa2,0x01,0x0e,
  0x7f,0x59,0xc9,0xb9,0xc4,0x9d,0x9b,0x1b,
  0x9c,0xca,0xaf,0x3c,0x73,0x1a,0x65,0xb1,
  0x76,0x84,0x39,0x98,0xe9,0x53,0x94,0xba,
  0x1d,0x29,0xcf,0xb4,0x0d,0x05,0x7d,0xd1,
  0xd7,0x0a,0xa0,0x5c,0x91,0x71,0x92,0x88,
  0xab,0x93,0x11,0x8a,0xd6,0x5a,0x77,0xb5,
  0xc3,0x19,0xc1,0xc7,0x8e,0xf9,0xec,0x35,
  0x4b,0xcc,0xd9,0x4a,0x18,0x23,0x9f,0x52,
  0xdd,0xe3,0xad,0x7b,0x47,0x97,0x60,0x10,
  0x43,0xef,0x07,0xa5,0x49,0xc6,0xb3,0x55,
  0x28,0x51,0x5d,0x64,0x66,0xfc,0x44,0x42,
  0xbc,0x26,0x09,0x74,0x6f,0xf7,0x6b,0x4f,
  0x2f,0xf0,0xea,0xb8,0xae,0xf3,0x63,0x6a,
  0x56,0xb2,0x02,0xd8,0x34,0xa4,0x00,0xe6,
  0x58,0xeb,0xa3,0x82,0x85,0x45,0xe0,0x89,
  0x7e,0xfd,0xf2,0x3a,0x36,0x57,0xff,0x06,
  0x69,0x54,0x79,0x9a,0xb6,0x6c,0xdc,0x8b,
  0xa7,0x1f,0x90,0x03,0x17,0x1c,0xed,0xd5,
  0xaa,0x5e,0xfe,0xda,0x78,0xb0,0xbf,0x12,
  0xa8,0x22,0x21,0x3d,0xc2,0xc0,0xb7,0xa9,
  0xe7,0x33,0xfb,0xf1,0x70,0xe5,0x17,0x96,
  0xf8,0x8d,0x46,0xa1,0x86,0xe2,0x40,0x38,
  0xf6,0x68,0x25,0x16,0xac,0x61,0x27,0xcb,
  0x5b,0xc8,0x2b,0x0f,0x99,0xde,0xce,0xc5
};

static unsigned char T2[]={
  0xbf,0x11,0x6d,0xfa,0x26,0x7f,0xf3,0xc8,
  0x9e,0xdd,0x3f,0x16,0x97,0xbd,0x08,0x80,
  0x51,0x42,0x93,0x49,0x5b,0x64,0x9b,0x25,
  0xf5,0x0f,0x24,0x34,0x44,0xb8,0xee,0x2e,
  0xda,0x8f,0x31,0xcc,0xc0,0x5e,0x8a,0x61,
  0xa1,0x63,0xc7,0xb2,0x58,0x09,0x4d,0x46,
  0x81,0x82,0x68,0x4b,0xf6,0xbc,0x9d,0x03,
  0xac,0x91,0xe8,0x3d,0x94,0x37,0xa0,0xbb,
  0xce,0xeb,0x98,0xd8,0x38,0x56,0xe9,0x6b,
  0x28,0xfd,0x84,0xc6,0xcd,0x5f,0x6e,0xb6,
  0x32,0xf7,0x0e,0xf1,0xf8,0x54,0xc1,0x53,
  0xf0,0xa7,0x95,0x7b,0x19,0x21,0x23,0x7d,
  0xe1,0xa9,0x75,0x3e,0xd6,0xed,0x8e,0x6f,
  0xdb,0xb7,0x07,0x41,0x05,0x77,0xb4,0x2d,
  0x45,0xdf,0x29,0x22,0x43,0x89,0x83,0xfc,
  0xd5,0xa4,0x88,0xd1,0xf4,0x55,0x4f,0x78,
  0x62,0x1e,0x1d,0xb9,0xe0,0x2f,0x01,0x13,
  0x15,0xe6,0x17,0x6a,0x8d,0x0c,0x96,0x7e,
  0x86,0x27,0xa6,0x0d,0xb5,0x73,0x71,0xaa,
  0x36,0xd0,0x06,0x66,0xdc,0xb1,0x2a,0x5a,
  0x72,0xbe,0x3a,0xc5,0x40,0x65,0x1b,0x02,
  0x10,0x9f,0x3b,0xf9,0x2b,0x18,0x5c,0xd7,
  0x12,0x47,0xef,0x1a,0x87,0xd2,0xc2,0x8b,
  0x99,0x9c,0xd3,0x57,0xe4,0x76,0x67,0xca,
  0x3c,0xfb,0x90,0x20,0x14,0x48,0xc9,0x60,
  0xb0,0x70,0x4e,0xa2,0xad,0x35,0xea,0xc4,
  0x74,0xcb,0x39,0xde,0xe7,0xd4,0xa3,0xa5,
  0x04,0x92,0x8c,0xd9,0x7c,0x1c,0x7a,0xa8,
  0x52,0x79,0xf2,0x33,0xba,0x1f,0x30,0x9a,
  0x00,0x50,0x4c,0xff,0xe5,0xcf,0x59,0xc3,
  0xe3,0x0a,0x85,0xb3,0xae,0xec,0x0b,0xfe,
  0xe2,0xab,0x4a,0xaf,0x69,0x6c,0x2c,0x5d
};

#define SN(b) (((b&0xf0)>>4)+((b&0xf)<<4))

static void fase(unsigned char *k,unsigned char *D)
{
	unsigned char l,dt; // paso 1 

	for(l=0;l<4;++l) D[l]^=k[l];  // paso 2 

	for(l=0;l<4;++l) D[l]=T1[D[l]];

	for(l=6;l>3;--l) { 
		D[(l+2)&3]^=D[(l+1)&3]; 
		dt=(SN(D[(l+1)&3])+D[l&3])&0xff; 
		D[l&3]=T2[dt];
	} 
	for(l=3;l>0;--l) {
		D[(l+2)&3]^=D[(l+1)&3]; 
		D[l&3]=T1[(SN(D[(l+1)&3])+D[l&3])&0xff]; 
	} 
	D[2]^=D[1]; 
	D[1]^=D[0]; 
}


// Packet Encryption

void encryptcache(uint8_t *buf, int len)
{
	int i;
	for (i=1; i<len; i++) buf[i] = (buf[i]+i) & 0xff;
}

void decryptcache(uint8_t *buf, int len)
{
	int i;
	for (i=1; i<len; i++) buf[i] = (0xff00+buf[i]-i) & 0xff;
}

///////////////////////////////////////////////////////////////////////////////
// 
///////////////////////////////////////////////////////////////////////////////

#define CACHE_SENT_NONE     0
#define CACHE_SENT_REQUEST  1
#define CACHE_SENT_REPLY    2

#define BIT_CACHE_NEWPROTO  0x01
#define BIT_CACHE_HACK      0x10
#define BIT_CACHE_REQPING   0x80

//	uint8_t status; // 0:Wait; 1: dcw received
#define CACHE_FLAG_DCW        0x01
//	int sendpipe; // flag send dcw to ecmpipe
#define CACHE_FLAG_SENDPIPE   0x02
// Request Sent
#define CACHE_FLAG_REQSENT    0x04
// Reply Sent
#define CACHE_FLAG_REPSENT    0x08
// Forward cache to peers
#define CACHE_FLAG_FWD        0x10
// Cacheex Reply Sent
#define CACHEEX_FLAG_REPSENT  0x20


typedef enum { NO_CYCLE=0, CW0CYCLE=1, CW1CYCLE=2} cwcycle_t;

#define DCW_ERROR    0x01
#define DCW_CYCLE    0x02
#define DCW_CHECKED  0x04
#define DCW_SKIP     0x08
#define DCW_SENT     0x10

struct cw_cache_data {
	struct cw_cache_data *next;
	uint8_t cw[16]; // for storing all codes
	uint32_t cwsum; // Checksum
	uint8_t status;
	cwcycle_t cwcycle; // cw1='1' / cw0='0'
	uint32_t peerid; // fisrt peerid 
	uint16_t nbpeers; // number of peers reporting this dcw
};


struct PACK cache_data {
	struct cache_data *next; // main list
	struct cache_data *prev; // previous

	uint8_t flags;
	uint32_t recvtime;
	// CSP
	uint8_t tag;
	uint16_t sid;
	uint16_t onid;
	uint16_t caid;
	uint32_t hash; // Non-NULL
	//
	uint32_t provid;
	cwcycle_t cwcycle; // ecmtag when cw1 cycle
	uint8_t prevcw[16];
#ifdef CACHEEX
	uint8_t ecmd5[16];
#endif

	struct cw_cache_data *cwdata;

	ECM_DATA *ecm;
};

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

inline int cache_check( struct cache_data *req )
{
	if ( ((req->tag&0xFE)!=0x80)||!req->caid||!req->hash||!req->sid ) return 0;
	if (cfg.cache.caids[0]) {
		int i;
		for(i=0; i<32; i++) {
			if (!cfg.cache.caids[i]) break;
			if (cfg.cache.caids[i]==req->caid) return 1;
		}
		return 0;
	}
	//if (!cfg.cache.faccept0onid && !req->onid ) return 0;
	return 1;
}

inline int cache_check_request( unsigned char tag, unsigned short sid, unsigned short onid, unsigned short caid, unsigned int hash )
{
	if ( ((tag&0xFE)!=0x80)||!caid||!hash ) return 0;
	//if (!cfg.cache.faccept0onid && !onid ) return 0;
	return 1;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

#define MAX_CACHE_INDEX  0xFFF


////typedef struct cache_data t_cachetab[MAX_CACHE_INDEX+1];


struct cache_list {
	struct cache_list *next;
	//struct cache_data *cachetab[MAX_CACHE_INDEX+1];
	unsigned short caid;
	struct cache_data **cachetab;
};


struct cache_list *cachelist;

struct cache_data **getcachetabbycaid(unsigned short caid)
{
	// look for availabe tab
	struct cache_list *x = cachelist;
	while (x) {
		if (x->caid==caid) {
			return x->cachetab;
		}
		x = x->next;
	}
	// if not found add new one
	struct cache_list *newdata = malloc( sizeof(struct cache_list) );
	newdata->next = cachelist;
	cachelist = newdata;
	newdata->caid = caid;
	newdata->cachetab = malloc( sizeof(struct cache_data) * (MAX_CACHE_INDEX+1) );
	memset( newdata->cachetab, 0, sizeof(struct cache_data) * (MAX_CACHE_INDEX+1) );
	//printf(" New cache list for caid = %02X\n", caid);
	return 	cachelist->cachetab;
}


struct cache_data *cache_new( struct cache_data *newdata )
{
	int index = newdata->sid&MAX_CACHE_INDEX;
	struct cache_data **cachetab = getcachetabbycaid(newdata->caid);
	struct cache_data *pcache = cachetab[index];
	struct cache_data *new;
	uint32_t ticks = GetTickCount();
	// add new or use dead data
	if (!pcache) {
		// nothing so add new
		//mlogf(LOGDEBUG,0," first data for index = %02X\n", index);
		new = malloc( sizeof(struct cache_data) );
		memset( new, 0,  sizeof(struct cache_data) );
		new->next = NULL;
		new->prev = NULL;
		cachetab[index] = new; // it becomes the current one
	}
	else if (!pcache->next) {
		//mlogf(LOGDEBUG,0," second data for index = %02X\n", index);
		new = malloc( sizeof(struct cache_data) );
		memset( new, 0,  sizeof(struct cache_data) );
		// add new
		new->prev = cachetab[index];
		new->next = cachetab[index];
		// update previous
		cachetab[index]->next = new;
		// update next
		cachetab[index]->prev = new;
		//
		cachetab[index] = new; // it becomes the current one
	}
	else {
		new = cachetab[index]->prev;
		if ( (new->recvtime+cfg.cache.alivetime) < ticks ) {
			// cache is dead, add data to this one without allocating new data
			// free old dcw
			struct cw_cache_data *cwdata = new->cwdata;
			while (cwdata) {
				struct cw_cache_data *tmp = cwdata;
				cwdata = cwdata->next;
				free( tmp );
			}
			//mlogf(LOGDEBUG,0," reuse data for index = %02X\n", index);
			pcache = new->prev; // store previous
			memset( new, 0,  sizeof(struct cache_data) );
			new->prev = pcache;
			new->next = cachetab[index];
			cachetab[index] = new; // it becomes the current one
		}
		else { // allocate new data
			//mlogf(LOGDEBUG,getdbgflag(DBG_CACHE,0,0)," new data for index = %02X\n", index);
			new = malloc( sizeof(struct cache_data) );
			memset( new, 0, sizeof(struct cache_data) );
			// add new in list
			new->prev = cachetab[index]->prev;
			new->next = cachetab[index];
			// update previous
			cachetab[index]->prev->next = new;
			// update next
			cachetab[index]->prev = new;
			//
			cachetab[index] = new; // it becomes the current one			
		}
	}
	pcache = cachetab[index];
	//pcache->status = CACHE_STAT_WAIT; // 0:Wait; 1: dcw received
	pcache->recvtime = ticks;
	pcache->tag = newdata->tag;
	pcache->sid = newdata->sid;
	pcache->onid = newdata->onid;
	pcache->caid = newdata->caid;
	pcache->hash = newdata->hash;
	pcache->provid = newdata->provid;
#ifdef CACHEEX
	memcpy( pcache->ecmd5, newdata->ecmd5, 16);
#endif
	return pcache;
}

struct cache_data *cache_fetch( struct cache_data *thereq )
{
	int index = thereq->sid&MAX_CACHE_INDEX;
	struct cache_data **cachetab = getcachetabbycaid(thereq->caid);
	struct cache_data *pcache = cachetab[index];
	uint32_t ticks = GetTickCount();
	while (pcache) {
		if ( (pcache->recvtime+cfg.cache.alivetime) < ticks ) return NULL;
		if ( (pcache->hash==thereq->hash)&&(pcache->sid==thereq->sid) )
			if ( (pcache->tag==thereq->tag) || !pcache->tag || !thereq->tag ) return pcache;
		pcache = pcache->next;
		if (pcache==cachetab[index]) break;
	}
	return NULL;
}


char *cwcycle2str( cwcycle_t cwcycle )
{
	if (cwcycle==CW0CYCLE) return "CW0CYCLE";
	if (cwcycle==CW1CYCLE) return "CW1CYCLE";
	else return "NO_CYCLE";
}


/*
inline int checkcycle( uint8_t cw1cycle, uint8_t ecmtag, uint8_t cwcycle ) 
{
	if (cfg.cache.filter) {
		// Check Cycle
		if (cw1cycle==0x80) { // cw1 cycle on tag=0x80
			if ( (ecmtag==0x80)&&(cwcycle==0) ) return 0;
			if ( (ecmtag==0x81)&&(cwcycle==1) ) return 0;
		}
		else if (cw1cycle==0x81) { // cw1 cycle on tag=0x81
			if ( (ecmtag==0x81)&&(cwcycle==0) ) return 0;
			if ( (ecmtag==0x80)&&(cwcycle==1) ) return 0;
		}
	}
	return 1;
}
*/









///////////////////////////////////////////////////////////////////////////////
// CACHE ---> ECM
///////////////////////////////////////////////////////////////////////////////

struct pipe_cache_data {
	uint8_t tag;
	uint16_t sid;
	uint16_t onid;
	uint16_t caid;
	uint32_t hash;
	uint32_t prid;
	uint8_t cw1cycle; // ecmtag when cw1 cycle
	ECM_DATA *ecm;
#ifdef CACHEEX
	uint8_t ecmd5[16];
#endif
	uint8_t dcw[16];
};

int get_cache2ecm( uint8_t *buf, struct cache_data *pcache, uint8_t *cw )
{
	pcache->tag = buf[1];
	pcache->sid = (buf[2]<<8) | buf[3];
	pcache->onid = (buf[4]<<8) | buf[5];
	pcache->caid = (buf[6]<<8) | buf[7];
	pcache->hash = (buf[8]<<24) | (buf[9]<<16) | (buf[10]<<8) | (buf[11]);
//	memcpy( &(pcache->tag), buf+1, 11);
	int index = 12;
	memcpy( &(pcache->ecm), buf+index, sizeof(void*) );
	//mlogf(LOGDEBUG,0, " get_cache2ecm %p\n", pcache->ecm);
	index += sizeof(void*);
	if (cw) {
		int peerid = (buf[index]<<24) | (buf[index+1]<<16) | (buf[index+2]<<8) | (buf[index+3]);
		index+=4;
		memcpy( cw, buf+index, 16);
		return peerid;
	}
	return 0;
}

inline int put_cache2ecm(uint8_t type, uint8_t *buf, struct cache_data *pcache, uint8_t *cw, int peerid )
{
	buf[0] = type;
	buf[1] = pcache->tag;
	buf[2] = pcache->sid>>8; buf[3] = pcache->sid&0xff;
	buf[4] = pcache->onid>>8; buf[5] = pcache->onid&0xff;
	buf[6] = pcache->caid>>8; buf[7] = pcache->caid&0xff;
	buf[8] = pcache->hash>>24; buf[9] = pcache->hash>>16; buf[10] = pcache->hash>>8; buf[11] = pcache->hash & 0xff;
//	memcpy( buf+1, &(pcache->tag), 11);
	int index = 12;
	memcpy( buf+index, &pcache->ecm, sizeof(void*) );
	//mlogf(LOGDEBUG,0, " put_cache2ecm %p\n", pcache->ecm);
	index += sizeof(void*);
	if (cw) {
		buf[index] = peerid>>24; buf[index+1] = peerid>>16; buf[index+2] = peerid>>8; buf[index+3] = peerid & 0xff;
		index+=4;
		memcpy( buf+index, cw, 16);
		index+=16;
	}
	return index;
}

void pipe_cache2ecm_find_failed(struct cache_data *pcache)
{
	uint8_t buf[48];
	int len = put_cache2ecm(PIPE_CACHE_FIND_FAILED, buf, pcache, NULL, 0);
	pipe_send( prg.pipe.ecm[1], buf, len);
}

void pipe_cache2ecm_find_success(struct cache_data *pcache, uint8_t *cw, int peerid )
{
	uint8_t buf[48];
	int len = put_cache2ecm(PIPE_CACHE_FIND_SUCCESS, buf, pcache, cw, peerid);
	pipe_send( prg.pipe.ecm[1], buf, len);
}

///////////////////////////////////////////////////////////////////////////////
// ECM ---> CACHE
///////////////////////////////////////////////////////////////////////////////

inline int get_ecm2cache(uint8_t *buf , struct cache_data *pcache, uint8_t *cw)
{
	pcache->tag = buf[1];
	pcache->sid = (buf[2]<<8) | buf[3];
	pcache->onid = (buf[4]<<8) | buf[5];
	pcache->caid = (buf[6]<<8) | buf[7];
	pcache->hash = (buf[8]<<24) | (buf[9]<<16) | (buf[10]<<8) | (buf[11]);
	pcache->provid = (buf[12]<<16) | (buf[13]<<8) | (buf[14]);
	pcache->cwcycle = buf[15];
	int index = 16;
	//
	memcpy( &pcache->ecm, buf+index, sizeof(void*) );
	index += sizeof(void*);
#ifdef CACHEEX
	memcpy( pcache->ecmd5, buf+index, 16 );
	index+=16;
#endif
	if (cw) {
		memcpy( cw, buf+index, 16 );
		index+=16;
	}
	return index;
}

int put_ecm2cache(uint8_t type, uint8_t *buf , ECM_DATA *ecm, uint16_t onid, uint8_t *cw )
{
	buf[0] = type;
	buf[1] = ecm->ecm[0];
	buf[2] = ecm->sid>>8; buf[3] = ecm->sid;
	buf[4] = onid>>8; buf[5] = onid;
	buf[6] = ecm->caid>>8; buf[7] = ecm->caid;
	buf[8] = ecm->hash>>24; buf[9] = ecm->hash>>16; buf[10] = ecm->hash>>8; buf[11] = ecm->hash;
	buf[12] = ecm->provid>>16; buf[13] = ecm->provid>>8; buf[14] = ecm->provid;
	// cwcycle
	if (!ecm->cw1cycle) buf[15] = NO_CYCLE;
	else if (ecm->ecm[0]==ecm->cw1cycle) buf[15] = CW1CYCLE; else buf[15] = CW0CYCLE;
	//
	int index = 16;
	memcpy( buf+index, &ecm, sizeof(void*) );
	index += sizeof(void*);
#ifdef CACHEEX
	memcpy( buf+index, ecm->ecmd5, 16 );
	index+=16;
#endif
	if (cw) { // previous cw if find/request, cw for reply
		memcpy( buf+index, cw, 16 );
		index+=16;
	}
	return index;
}

/*
#ifdef THREAD_DCW
void pipe_cache_find( ECM_DATA *ecm, struct cardserver_data *cs)
{
	struct cache_data req;
	req.tag = ecm->ecm[0];
	req.sid = ecm->sid;
	req.onid = cs->option.onid;
	req.caid = ecm->caid;
	req.hash = ecm->hash;
	req.provid = ecm->provid;
	req.cw1cycle = ecm->cw1cycle;


	pthread_mutex_lock( &prg.lockcache );

	struct cache_data *pcache = cache_fetch( &req );
	if (pcache==NULL) {
		pcache = cache_new( &req );
		pcache->ecm = ecm;
		pcache->cw1cycle = req.cw1cycle;
#ifdef CACHEEX
		memcpy( pcache->ecmd5, ecm->ecmd5, 16 );
#endif
		pcache->flags |= CACHE_FLAG_SENDPIPE;
		// XXX set find failed
		ecm->dcwstatus = STAT_DCW_WAIT;
		ecm->checktime = 1;
	}
	else {
		if (!cs->option.cachetimeout) {
			ecm->dcwstatus = STAT_DCW_WAIT;
			ecm->checktime = 1;
		}
		pcache->ecm = ecm;
		pcache->tag = req.tag; // set tag if not set (coming from cahceex)
		pcache->provid = req.provid; // set provid if not set (coming from csp)
		pcache->cw1cycle = req.cw1cycle;
		pcache->provid = req.provid;
#ifdef CACHEEX
		memcpy( pcache->ecmd5, ecm->ecmd5, 16 );
#endif
		pcache->flags |= CACHE_FLAG_SENDPIPE;
		// Check stored cw
		if (pcache->icwlist) {
			int i;
			for(i=0; i<pcache->icwlist; i++) {
				if ( pcache->cwlist[i].status ) {
					if ( checkcycle( pcache->cw1cycle, pcache->tag, pcache->cwlist[i].cwcycle ) ) {
						ecm_setdcw( ecm, pcache->cwlist[i].cw, DCW_SOURCE_CACHE, pcache->cwlist[i].peerid );
					}
				}
			}
		}
	}

	pthread_mutex_unlock( &prg.lockcache );
}
*/

void pipe_cache_find( ECM_DATA *ecm, struct cardserver_data *cs)
{
	uint8_t buf[64];
	uint8_t *cw = NULL;
	if ( ecm->lastdecode.ecm && (ecm->lastdecode.counter>1) ) cw = ecm->lastdecode.dcw;
	int len = put_ecm2cache(PIPE_CACHE_FIND, buf, ecm, cs->option.onid, cw);
	pipe_send( prg.pipe.cache[1], buf, len);
}

void pipe_cache_request( ECM_DATA *ecm, struct cardserver_data *cs)
{
	uint8_t buf[64];
	int len = put_ecm2cache(PIPE_CACHE_REQUEST, buf, ecm, cs->option.onid, NULL);
	pipe_send( prg.pipe.cache[1], buf, len);
}

void pipe_cache_reply( ECM_DATA *ecm, struct cardserver_data *cs)
{
	uint8_t buf[64];
	int len;
	if (ecm->dcwstatus==STAT_DCW_SUCCESS)
		len = put_ecm2cache(PIPE_CACHE_REPLY, buf, ecm, cs->option.onid, ecm->cw);
	else
		len = put_ecm2cache(PIPE_CACHE_REPLY, buf, ecm, cs->option.onid, NULL);
	pipe_send( prg.pipe.cache[1], buf, len);
}

#ifndef PUBLIC
void pipe_cache_resendreq(ECM_DATA *ecm, struct cardserver_data *cs)
{
	uint8_t buf[64];
	int len;
	len = put_ecm2cache(PIPE_CACHE_RESENDREQ, buf, ecm, cs->option.onid, NULL);
	pipe_send( prg.pipe.cache[1], buf, len);
	mlogf(LOGDEBUG,getdbgflag(DBG_NEWCAMD,cs->id,0), " [%s] CACHE RESENDREQ ch %04x:%06x:%04x\n", cs->name,ecm->caid,ecm->provid,ecm->sid);
}
#endif

///////////////////////////////////////////////////////////////////////////////
// 
///////////////////////////////////////////////////////////////////////////////


void sendtoip( int handle, uint32_t ip, int port, unsigned char *buf, int len)
{
	if (ip && port) {
		struct sockaddr_in si_other;
		int slen=sizeof(si_other);
		memset((char *) &si_other, 0, sizeof(si_other));
		si_other.sin_family = AF_INET;
		si_other.sin_port = htons( port );
		si_other.sin_addr.s_addr = ip;
		sendto( handle, buf, len, 0, (struct sockaddr *)&si_other, slen );
	}
}

void sendtopeer( struct cachepeer_data *peer, unsigned char *buf, int len)
{

	if (peer->host->ip && peer->port) {
		struct sockaddr_in si_other;
		int slen=sizeof(si_other);
		memset((char *) &si_other, 0, sizeof(si_other));
		si_other.sin_family = AF_INET;
		si_other.sin_port = htons( peer->port );
		si_other.sin_addr.s_addr = peer->host->ip;
#ifdef DEBUG_NETWORK2
		if (flag_debugnet) {
			mlogf(LOGINFO,getdbgflag(DBG_CACHE,0,0)," cache: send data (%d) to peer (%s:%d)\n", len, peer->host->name,peer->port);
			debughex(buf,len);
		}
#endif
		sendto(peer->outsock, buf, len, 0, (struct sockaddr *)&si_other, slen);
	}
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

#define TYPE_REQUEST   1
#define TYPE_REPLY     2
#define TYPE_PINGREQ   3
#define TYPE_PINGRPL   4
#define TYPE_RESENDREQ 5

#ifdef NEWCACHE

#define TYPE_HELLO          0x03
#define TYPE_HELLO_ACK      0x10
#define TYPE_KEEPALIVE      0x11
#define TYPE_KEEPALIVE_ACK  0x12
#define TYPE_CARD_LIST      0x13
#define TYPE_SMS            0x14
#define TYPE_SMS_ACK        0x15

#define TYPE_VERSION        0x90
#define TYPE_VERSION_ACK    0x91

#define TYPE_EXTENDED       0x92
#define TYPE_EXTENDED_ACK   0x93

#define TYPE_UNKNOWN        0xFF

#endif


int peer_card_binarysearch( struct cachepeer_data *peer, uint16_t caid, uint32_t provid)
{
	if (peer->nbcomcards==0) return 0;
	int caprov = (caid<<16) | provid; 

	// Returns index of sid in sids, or -1 if not found
	register int xl = 0;
	register int xh = peer->nbcomcards - 1;
	//
	register int yl = peer->comcards[xl];
	register int yh = peer->comcards[xh];
	//
	int xm;
	while (yl <= caprov && yh >= caprov) {
		xm = (xl + xh)/2;
		int ym = peer->comcards[xm];
		if (ym<caprov) yl = peer->comcards[xl=xm+1];
		else if (ym>caprov) yh = peer->comcards[xh=xm-1];
		else return 1; // found
	}
	if (peer->comcards[xl] == caprov) return 1;
	return 0; // Not found
}

int peer_acceptcard( struct cachepeer_data *peer, uint16_t caid, uint32_t provid)
{
	int i;

	if ( peer->cards[0] ) {
		int caprov = (caid<<16) | provid; 
		for (i=0; i<1024; i++) {
			if (!peer->cards[i]) return 0;
			if (peer->cards[i] == caprov) break;
		}
	}
#ifndef PUBLIC
	if ( peer->sharelimits[0].caid!=0xffff ) {
		for (i=0; i<100; i++) {
			if (peer->sharelimits[i].caid==0xffff) return 0;
			if (peer->sharelimits[i].caid==caid) {
				if (peer->sharelimits[i].provid==provid) break;
				else if (peer->sharelimits[i].provid==0xFFFFFF) break;
			}
		}
	}
#endif
	return 1;
}		


void cache_send_request(struct cache_data *pcache,struct cachepeer_data *peer)
{
	uint8_t buf[64];
	//01 80 00CD 0001 0500 8D1DB359
	buf[0] = TYPE_REQUEST;
	buf[1] = pcache->tag;
	buf[2] = pcache->sid>>8;
	buf[3] = pcache->sid;
	buf[4] = pcache->onid>>8;
	buf[5] = pcache->onid&0xff;
	buf[6] = pcache->caid>>8;
	buf[7] = pcache->caid;
	buf[8] = pcache->hash>>24;
	buf[9] = pcache->hash>>16;
	buf[10] = pcache->hash>>8;
	buf[11] = pcache->hash;
	if (peer) {
		sendtopeer(peer, buf, 12);
		peer->sentreq++;
	}
	else {
		struct cacheserver_data	*cache = cfg.cache.server;
		while (cache) {
#ifdef PEERLIST
			peer = cache->peerReq;
			while (peer) {
				if ( !peer->fblock0onid || pcache->onid )
				if ( peer_card_binarysearch(peer, pcache->caid, pcache->provid) ) {
					sendtopeer(peer, buf, 12);
					peer->sentreq++;
				}
				peer = peer->nextReq;
			}
#else
			peer = cache->peer;
			while (peer) {
				if (peer->ping>0)
				if (peer->flags&FLAG_CACHE_SENDREQ)
				if ( !peer->fblock0onid || pcache->onid )
				if ( peer_card_binarysearch(peer, pcache->caid, pcache->provid) ) {
					sendtopeer(peer, buf, 12);
					peer->sentreq++;
				}
				peer = peer->next;
			}
#endif
			cache = cache->next;
		}
	}
}


void cache_send_reply(struct cache_data *pcache,struct cachepeer_data *peer, uint8_t cw[16])
{
	uint8_t buf[64];
	//Common Data
	buf[0] = TYPE_REPLY;
	buf[1] = pcache->tag;
	buf[2] = pcache->sid>>8;
	buf[3] = pcache->sid;
	buf[4] = pcache->onid>>8;
	buf[5] = pcache->onid&0xff;
	buf[6] = pcache->caid>>8;
	buf[7] = pcache->caid;
	buf[8] = pcache->hash>>24;
	buf[9] = pcache->hash>>16;
	buf[10] = pcache->hash>>8;
	buf[11] = pcache->hash;
	buf[12] = pcache->tag;
	memcpy( buf+13, cw, 16);

	if (peer) {
		sendtopeer(peer, buf, 29);
		//peer->sentrep++;
	}
	else {
		struct cacheserver_data	*cache = cfg.cache.server;
		while (cache) {
#ifdef PEERLIST
			peer = cache->peerRep;
			while ( peer ) {
				if ( !peer->fblock0onid || pcache->onid )
				if ( peer_card_binarysearch(peer, pcache->caid, pcache->provid) ) {
					sendtopeer(peer, buf, 29);
					peer->sentrep++;
				}
				peer = peer->nextRep;
			}
#else
			peer = cache->peer;
			while ( peer ) {
				if (peer->ping>0)
				//if (peer->flags&FLAG_CACHE_SENDREP)
				if ( !peer->fblock0onid || pcache->onid )
				if ( peer_card_binarysearch(peer, pcache->caid, pcache->provid) ) {
					sendtopeer(peer, buf, 29);
					peer->sentrep++;
				}
				peer = peer->next;
			}
#endif
			cache = cache->next;
		}
	}
}


void cache_send_fwdreply(struct cache_data *pcache, uint8_t cw[16], cwcycle_t cwcycle)
{
	uint8_t buf[64];
	//Common Data
	buf[0] = TYPE_REPLY;
	buf[1] = pcache->tag;
	buf[2] = pcache->sid>>8;
	buf[3] = pcache->sid;
	buf[4] = pcache->onid>>8;
	buf[5] = pcache->onid&0xff;
	buf[6] = pcache->caid>>8;
	buf[7] = pcache->caid;
	buf[8] = pcache->hash>>24;
	buf[9] = pcache->hash>>16;
	buf[10] = pcache->hash>>8;
	buf[11] = pcache->hash;
	buf[12] = pcache->tag;
	memcpy( buf+13, cw, 16);
	buf[29] = cwcycle;

	struct cacheserver_data	*cache = cfg.cache.server;
	while (cache) {
#ifdef PEERLIST
		struct cachepeer_data *peer = cache->peerRep;
		while ( peer ) {
			if ( peer->fwd )
			if ( peer_card_binarysearch(peer, pcache->caid, pcache->provid) ) {
				sendtopeer(peer, buf, 30);
				peer->sentrep++;
			}
			peer = peer->nextRep;
		}
#else
		struct cachepeer_data *peer = cache->peer;
		while ( peer ) {
			//if (peer->flags&FLAG_CACHE_SENDREP)
			if ( peer->ping>0 )
			if ( peer->fwd )
			if ( peer_card_binarysearch(peer, pcache->caid, pcache->provid) ) {
				sendtopeer(peer, buf, 30);
				peer->sentrep++;
			}
			peer = peer->next;
		}
#endif
		cache = cache->next;
	}
}

#ifndef PUBLIC
void cache_send_resendreq(struct cache_data *pcache)
{
	struct cacheserver_data *cache = cfg.cache.server;
	while (cache) {
		// <1:TYPE_RESENDREQ> <2:port> <1:ecmtag> <2:sid> <2:onid> <2:caid> <4:hash>
		uint8_t buf[64];
		buf[0] = TYPE_RESENDREQ;
		//Port
		buf[1] = 0;
		buf[2] = 0;
		buf[3] = cache->port>>8;
		buf[4] = cache->port&0xff;
		buf[5] = pcache->tag;
		buf[6] = pcache->sid>>8;
		buf[7] = pcache->sid;
		buf[8] = pcache->onid>>8;
		buf[9] = pcache->onid&0xff;
		buf[10] = pcache->caid>>8;
		buf[11] = pcache->caid;
		buf[12] = pcache->hash>>24;
		buf[13] = pcache->hash>>16;
		buf[14] = pcache->hash>>8;
		buf[15] = pcache->hash;
#ifdef PEERLIST
		struct cachepeer_data *peer = cache->peerRep;
		while ( peer ) {
			if ( peer_card_binarysearch(peer, pcache->caid, pcache->provid) )
				sendtopeer(peer, buf, 16);
			peer = peer->nextRep;
		}
#else
		struct cachepeer_data *peer = cache->peer;
		while ( peer ) {
			if ( peer->ping>0 )
			if ( peer_card_binarysearch(peer, pcache->caid, pcache->provid) )
				sendtopeer(peer, buf, 16);
			peer = peer->next;
		}
#endif
		cache = cache->next;
	}
}
#endif

void cache_send_ping(struct cacheserver_data *cache, struct cachepeer_data *peer)
{
	unsigned char buf[32];
	buf[0] = TYPE_PINGREQ;
	// New Cache IDENT
	buf[1] = 'M';
	buf[2] = 'C';
#ifndef PUBLIC
	buf[3] = 1 | BIT_CACHE_HACK;
#else
	buf[3] = 1;
#endif
	// PEER ID
	buf[4] = peer->id>>8; 
	buf[5] = peer->id&0xff;
	// MULTICS CRC
	buf[6] = peer->crc[0] = 0xff & rand();
	buf[7] = peer->crc[1] = 0xff & rand();
	buf[8] = peer->crc[2] = 0xff & rand();
	//Port
	buf[9] = peer->crc[3] = 0;
	buf[10] = 0;
	buf[11] = cache->port>>8;
	buf[12] = cache->port&0xff;

	//Program
	buf[13] = 0x01; //ID
	buf[14] = 7; //LEN
	buf[15] = 'M'; buf[16] = 'u'; buf[17] = 'l'; buf[18] = 't'; buf[19] = 'i'; buf[20] = 'C'; buf[21] = 'S';
	//Version
	buf[22] = 0x02; //ID
	buf[23] = 3; //LEN
	buf[24] = 'r'; buf[25] = '0'+(REVISION/10); buf[26] = '0'+(REVISION%10);
	//
	sendtopeer( peer, buf, 27);
}


#ifdef NEWCACHE

void cache_send_keepalive(struct cacheserver_data *cache, struct cachepeer_data *peer)
{
	if (peer->protocol&1) {
		unsigned char buf[32];
		buf[0] = TYPE_KEEPALIVE;
		buf[1] = peer->id>>8; 
		buf[2] = peer->id&0xff;
		sendtopeer( peer, buf, 3);
	}
	else cache_send_ping(cache, peer);
}

void save_sms( struct sms_data *sms, struct cachepeer_data *peer)
{
	// print to sms file
	FILE *fhandle;
	fhandle=fopen(sms_file, "at");
	if (fhandle!=0) {
		// Get Time
		char timebuf [80];
		struct tm * timeinfo = localtime (&sms->rawtime);
		strftime (timebuf,80,"%x %X",timeinfo);
		if (sms->status&1) fprintf(fhandle,"\n\n[ %s ] >> SMS to peer (%s:%d)\n", timebuf, peer->host->name, peer->port);
		else  fprintf(fhandle,"\n\n[ %s ] << SMS from peer (%s:%d)\n", timebuf, peer->host->name, peer->port);
		fputs(sms->msg, fhandle);
		fclose(fhandle);
	}
}

struct sms_data *cache_new_sms(char *msg)
{
	struct sms_data *sms = malloc( sizeof(struct sms_data) );
	int len = strlen(msg);
	uint32_t hash = hashCode((uint8_t*)msg, len);
	strcpy( sms->msg, msg );
	sms->hash = hash;
	time (&sms->rawtime);
	sms->next = NULL;
	return (sms);
}

void cache_send_sms(struct cachepeer_data *peer, struct sms_data *sms)
{
	int len = strlen(sms->msg);
	sms->status = 1; // bit 0 (0:in,1:out) bit 1 (0:unread/unack, 1:read/ack)
	sms->next = peer->sms;
	peer->sms = sms;
	// Send Buffer
	uint8_t buf[1024];
	buf[0] = TYPE_SMS;
	buf[1] = sms->hash>>24;
	buf[2] = sms->hash>>16;
	buf[3] = sms->hash>>8;
	buf[4] = sms->hash;
	memcpy( buf+5, sms->msg, len );
	sendtopeer(peer, buf, len+5);
	// Debug
	mlogf(LOGINFO,getdbgflag(DBG_CACHE,0,0)," SMS to peer (%s:%d)\n", peer->host->name, peer->port);
	save_sms( sms, peer);
}


#endif

void peer_check_messages( struct cachepeer_data *peer )
{
	// Remove Old Messages if there is too much
	struct sms_data *sms = peer->sms;
	int nb = 0;
	while (sms) {
		nb++;
		if (nb>=30) break;
		sms = sms->next;
	}
	// Remove Messages
	if (sms) {
		struct sms_data *next = sms->next;
		sms->next = NULL;
		while (next) {
			sms = next;
			next = sms->next;
			free(sms);
		}
	}
}






///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// DCW CHECK & SET 
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////


/*
	look for older cw and check for cwcycle
	return
	-1 : error
	0: nothing found
	1: found cycle
*/

inline int cache_fetch_cycle( struct cache_data *thereq, uint8_t cw[16], cwcycle_t *cwcycle )
{
#ifdef TESTCHANNEL
	int testchannel = ( (thereq->caid==cfg.testchn.caid) && (!thereq->provid || thereq->provid==cfg.testchn.provid) && (thereq->sid==cfg.testchn.sid) );
	if (testchannel) {
		char dump[64];
		array2hex( cw, dump, 16);
		char dump2[64];
		array2hex( thereq->prevcw, dump2, 16);
		mlogf(LOGINFO,0," (cache_fetch_cycle.%x) ch %04x:%06x:%04x/%02x:%08x -> %s (%s) P:%s\n", thereq->flags&CACHE_FLAG_SENDPIPE, thereq->caid, thereq->provid, thereq->sid,
			thereq->tag, thereq->hash, dump, cwcycle2str(thereq->cwcycle), dump2 );
	}
#endif

	int index = thereq->sid&MAX_CACHE_INDEX;
	struct cache_data **cachetab = getcachetabbycaid(thereq->caid);
	struct cache_data *pcache = cachetab[index];
	struct cache_data *result = NULL;
	uint32_t ticks = GetTickCount() - cfg.cache.alivetime;
	while (pcache) {
		if ( (pcache->recvtime+cfg.cache.filtertime)<thereq->recvtime) {
			if ( pcache->recvtime < ticks ) break;
			if ( (pcache->sid==thereq->sid)&&(pcache->hash!=thereq->hash) ) // need provider XXX
			if ( !pcache->provid || !thereq->provid || (pcache->provid==thereq->provid) ) // csp luck of provid
			if ( pcache->tag && (pcache->tag!=thereq->tag) ) { // old oscam cacheex luck of ecmtag
				struct cw_cache_data *cwdata = pcache->cwdata;
				while (cwdata) {
					if ( dcwcmp16(cwdata->cw,cw) ) {
#ifdef TESTCHANNEL
						if (testchannel) {
							char dump[64];
							array2hex( cwdata->cw, dump, 16);
							mlogf(LOGINFO,0," >> Same dcw, cache %04x:%06x:%04x/%02x:%08x::%s\n", pcache->caid, pcache->provid, pcache->sid, pcache->tag, pcache->hash, dump);
						}
#endif
						return DCW_ERROR; // not gooooooooooooood maybe another provider of same channel
					}
					else if ( !(cwdata->status&DCW_ERROR) ) {
						if ( dcwcmp8(cwdata->cw,cw) && !dcwcmp8(cwdata->cw+8,cw+8) ) { // ????????????????????????????
							if (cwdata->cwcycle!=CW1CYCLE) {
								*cwcycle = CW1CYCLE; // CW1 changed
#ifdef TESTCHANNEL
								if (testchannel) {
									char dump[64];
									array2hex( cwdata->cw, dump, 16);
									mlogf(LOGINFO,0," >> CW1 cycle(%d) cache %04x:%06x:%04x/%02x:%08x::%s\n", cwdata->status, pcache->caid, pcache->provid, pcache->sid, pcache->tag, pcache->hash, dump);
								}
#endif
								if (cwdata->status&DCW_CYCLE) return DCW_CYCLE;
								result = pcache;
							}
						}
						else if ( !dcwcmp8(cwdata->cw,cw) && dcwcmp8(cwdata->cw+8,cw+8) ) {
							if (cwdata->cwcycle!=CW0CYCLE) {
								*cwcycle = CW0CYCLE; // CW0 changed
#ifdef TESTCHANNEL
								if (testchannel) {
									char dump[64];
									array2hex( cwdata->cw, dump, 16);
									mlogf(LOGINFO,0," >> CW0 cycle(%d) cache %04x:%06x:%04x/%02x:%08x::%s\n", cwdata->status, pcache->caid, pcache->provid, pcache->sid, pcache->tag, pcache->hash, dump);
								}
#endif
								if (cwdata->status&DCW_CYCLE) return DCW_CYCLE; //2
								result = pcache;
							}
						}
					}
					cwdata = cwdata->next;
				}
			}
		}
		pcache = pcache->next;
		if (pcache==cachetab[index]) break;
	}
	if (result) return DCW_CYCLE; //1
	return 0; //DCW_NOCYCLE
}


// search for same cw in cache
int cache_check_cw( uint32_t recvtime, uint8_t tag, uint16_t caid, uint32_t hash, uint16_t sid, uint8_t cw[16], int cwpart )
{
	int index = sid&MAX_CACHE_INDEX;
	struct cache_data **cachetab = getcachetabbycaid(caid);
	struct cache_data *pcache = cachetab[index];
	uint32_t ticks = GetTickCount() - cfg.cache.alivetime;
	while (pcache) {
		if ( (pcache->recvtime+cfg.cache.filtertime)<recvtime) {
			if ( pcache->recvtime < ticks ) break;
			if ( (pcache->sid==sid)&&(pcache->hash!=hash)&&(pcache->tag!=tag) ) { // ??? maybe find same dcw for different providers
				struct cw_cache_data *cwdata = pcache->cwdata;
				while (cwdata) {
					switch (cwpart) {
						case 0:
							if ( dcwcmp8(cwdata->cw,cw) ) return 0;
							if ( dcwcmp8(cwdata->cw+8,cw) ) return 0;
							break;
						case 1:
							if ( dcwcmp8(cwdata->cw,cw+8) ) return 0;
							if ( dcwcmp8(cwdata->cw+8,cw+8) ) return 0;
							break;
						case 2:
							if ( dcwcmp16(cwdata->cw,cw) ) return 0;
							break;
					}
					cwdata = cwdata->next;
				}
			}
		}
		pcache = pcache->next;
		if (pcache==cachetab[index]) break;
	}
	return 1;
}


// search for same cw in cache
int cache_check_samecw( struct cache_data *req, uint8_t cw[16], int cwpart )
{
	int index = req->sid&MAX_CACHE_INDEX;
	struct cache_data **cachetab = getcachetabbycaid(req->caid);
	struct cache_data *pcache = cachetab[index];
	uint32_t ticks = GetTickCount() - cfg.cache.alivetime;
	while (pcache) {
		if ( (pcache->recvtime+cfg.cache.filtertime)<req->recvtime) {
			if ( pcache->recvtime < ticks ) break;
			if ( (pcache->sid==req->sid)&&(pcache->hash!=req->hash) ) { // ??? maybe find same dcw for different providers
				struct cw_cache_data *cwdata = pcache->cwdata;
				while (cwdata) {
					switch (cwpart) {
						case 0:
							if ( dcwcmp8(cwdata->cw,cw) ) return 0;
							if ( dcwcmp8(cwdata->cw+8,cw) ) return 0;
							break;
						case 1:
							if ( dcwcmp8(cwdata->cw,cw+8) ) return 0;
							if ( dcwcmp8(cwdata->cw+8,cw+8) ) return 0;
							break;
						case 2:
							if ( dcwcmp16(cwdata->cw,cw) ) return 0;
							break;
					}
					cwdata = cwdata->next;
				}
			}
		}
		pcache = pcache->next;
		if (pcache==cachetab[index]) break;
	}
	return 1;
}


inline struct cw_cache_data *iscwincache(struct cache_data *pcache, uint8_t cw[16])
{
	struct cw_cache_data *cwdata = pcache->cwdata;
	while (cwdata) {
		if ( dcwcmp16(cwdata->cw, cw) ) return cwdata;
		cwdata = cwdata->next;
	}
	return NULL;
}

#ifndef PUBLIC

// update dcw for cache data of same channel with different hash and provider
inline struct cache_data *cache_fetch_samechannel( struct cache_data *thereq, uint8_t cw[16], int peerid )
{
#ifdef TESTCHANNEL
	int testchannel = ( (thereq->caid==cfg.testchn.caid) && (!thereq->provid || thereq->provid==cfg.testchn.provid) && (thereq->sid==cfg.testchn.sid) );
	if (testchannel) {
		char dump[64];
		array2hex( cw, dump, 16);
		mlogf(LOGINFO,0," (cache_fetch_samechannel) ch %04x:%06x:%04x/%02x:%08x -> %s\n", thereq->caid, thereq->provid, thereq->sid, thereq->tag, thereq->hash, dump);
	}
#endif
	int index = thereq->sid&MAX_CACHE_INDEX;
	struct cache_data **cachetab = getcachetabbycaid(thereq->caid);
	struct cache_data *pcache = cachetab[index];
	struct cache_data *result = NULL;
	uint32_t ticks = GetTickCount() - cfg.cache.alivetime;
	while (pcache) {
		if ( pcache->recvtime < ticks ) break;
		if ( pcache->flags&CACHE_FLAG_SENDPIPE )
		if ( (pcache->sid==thereq->sid)&&(pcache->hash!=thereq->hash) ) // need provider XXX
		//if ( !pcache->provid || !thereq->provid || (pcache->provid!=thereq->provid) )
		if ( pcache->tag && (pcache->tag==thereq->tag) )
		if ( pcache->cwcycle!=NO_CYCLE )
		if ( !isnullDCW(pcache->prevcw) )
		if ( !iscwincache(pcache,cw) )
		{
			if (  ( (pcache->cwcycle==CW1CYCLE) && dcwcmp8(pcache->prevcw,cw) && !similarcw(pcache->prevcw+8,cw+8) ) ||
				( (pcache->cwcycle==CW0CYCLE) && !similarcw(pcache->prevcw,cw) && dcwcmp8(pcache->prevcw+8,cw+8) )  ) {

				pipe_cache2ecm_find_success(pcache, cw, peerid);

#ifdef TESTCHANNEL
				if (testchannel) {
					char dump1[64];
					char dump2[64];
					array2hex( cw, dump1, 16);
					array2hex( pcache->prevcw, dump2, 16);
					mlogf(LOGINFO,0," ==%s== cache %04x:%06x:%04x/%02x:%08x %s => %s\n", cwcycle2str(pcache->cwcycle), pcache->caid, pcache->provid, pcache->sid, pcache->tag, pcache->hash, dump2,dump1);
					mlogf(LOGINFO,0," ==%s== Update %04x:%06x:%04x/%02x:%08x from %04x:%06x:%04x/%02x:%08x\n", cwcycle2str(pcache->cwcycle), 
						pcache->caid, pcache->provid, pcache->sid, pcache->tag, pcache->hash,
						thereq->caid, thereq->provid, thereq->sid, thereq->tag, thereq->hash );
				}
#endif

			}
		}
		pcache = pcache->next;
		if (pcache==cachetab[index]) break;
	}
	return result;
}

#endif

// -1: bad cw
// 0: nothing to do
// 1: dcw set
// 2: dcw set & sent to pipe
int cache_setdcw( struct cache_data *req, uint8_t cw[16], cwcycle_t cwcycle, int peerid )
{
	if (req->caid==0x0500)
	{
		if (!acceptDCWnonblockCRC(cw)) 
		{
			mlogf(LOGTRACE,getdbgflag(DBG_CACHE,0,0)," cache: non cs CAID 0500 reject recv cw from peer %d: %04x:%06x:%04x - %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n", peerid ,req->caid, req->provid, req->sid, cw[0],cw[1],cw[2],cw[3],cw[4],cw[5],cw[6],cw[7],cw[8],cw[9],cw[10],cw[11],cw[12],cw[13],cw[14],cw[15] );
			return -1;
		}
		else
			mlogf(LOGTRACE,getdbgflag(DBG_CACHE,0,0)," cache: non cs CAID 0500 accept recv cw from peer %d: %04x:%06x:%04x - %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n", peerid ,req->caid, req->provid, req->sid, cw[0],cw[1],cw[2],cw[3],cw[4],cw[5],cw[6],cw[7],cw[8],cw[9],cw[10],cw[11],cw[12],cw[13],cw[14],cw[15] );
	}
	else
	{
		if (!acceptDCW(cw,0))
		{
			mlogf(LOGTRACE,getdbgflag(DBG_CACHE,0,0)," cache: non cs non CAID 0500 reject recv cw from peer %d: %04x:%06x:%04x - %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n", peerid ,req->caid, req->provid, req->sid, cw[0],cw[1],cw[2],cw[3],cw[4],cw[5],cw[6],cw[7],cw[8],cw[9],cw[10],cw[11],cw[12],cw[13],cw[14],cw[15] );
			return -1;
		}
		else
			mlogf(LOGTRACE,getdbgflag(DBG_CACHE,0,0)," cache: non cs non CAID 0500 accept recv cw from peer %d: %04x:%06x:%04x - %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n", peerid ,req->caid, req->provid, req->sid, cw[0],cw[1],cw[2],cw[3],cw[4],cw[5],cw[6],cw[7],cw[8],cw[9],cw[10],cw[11],cw[12],cw[13],cw[14],cw[15] );
	}

	// Search for Cache data
	struct cw_cache_data *cwdata = NULL;
	struct cache_data *pcache = cache_fetch( req );
	if (pcache==NULL) pcache = cache_new( req );
	else {
		if (!pcache->tag) pcache->tag = req->tag; // set tag if not set (coming from cahceex)
		if (!pcache->provid && req->provid) pcache->provid = req->provid; // set provid if not set (coming from csp)
		// check for dcw
		cwdata = pcache->cwdata;
		while (cwdata) {
			if ( dcwcmp16(cwdata->cw, cw) ) break;
			cwdata = cwdata->next;
		}
	}
	// add new if not found
	if (!cwdata) {
		cwdata = malloc( sizeof(struct cw_cache_data) );
		memset( cwdata, 0, sizeof(struct cw_cache_data) );
		memcpy(cwdata->cw, cw, 16);
		cwdata->status = 0;
		cwdata->cwcycle = NO_CYCLE;
		cwdata->peerid = peerid;
		cwdata->next = pcache->cwdata;
		pcache->cwdata = cwdata;
	}
	cwdata->nbpeers++;

	if (cwdata->status&DCW_ERROR) return DCW_ERROR;
/*
	// TEST for Max Peers and for sending 
	if ( (cwdata->nbpeers==5) && !(cwdata->status&DCW_CYCLE) && (pcache->flags&CACHE_FLAG_SENDPIPE) && !(cwdata->status&DCW_SENT) ) {
		if ( isnullDCW(pcache->prevcw) ) { // no cycle for cached cw
			cwdata->status |= DCW_SENT;
			pipe_cache2ecm_find_success(pcache, cwdata->cw, cwdata->peerid );
		}
	}
*/
	// TEST for min Peers
	if (cwdata->nbpeers!=cfg.cache.threshold) return DCW_ERROR | DCW_SKIP;

#ifdef TESTCHANNEL
	int testchannel = ( (pcache->caid==cfg.testchn.caid) && (!pcache->provid || pcache->provid==cfg.testchn.provid) && (pcache->sid==cfg.testchn.sid) );
	if (testchannel) {
		char dump[64];
		array2hex( cwdata->cw, dump, 16);
		mlogf(LOGINFO,0," [cache_setdcw] Incoming Cache(%d) ch %04x:%06x:%04x/%02x:%08x -> %s (%s)\n", cwdata->nbpeers, pcache->caid, pcache->provid, pcache->sid, pcache->tag, pcache->hash,
			dump, cwcycle2str(pcache->cwcycle) );
	}
#endif

	// ACCEPTED

	// Half Nulled CW
	char nullcw[8] = "\0\0\0\0\0\0\0\0";
	if ( !dcwcmp8(cw,nullcw) && !dcwcmp8(cw+8,nullcw) ) {

#ifndef PUBLIC
		if (cfg.cache.dcwcheck2) cache_fetch_samechannel(pcache, cw, peerid);
#endif
		if ( !isnullDCW(pcache->prevcw) ) {
			if (  ( (pcache->cwcycle==CW1CYCLE) && dcwcmp8(pcache->prevcw,cw) && !similarcw(pcache->prevcw+8,cw+8) ) ||
				( (pcache->cwcycle==CW0CYCLE) && !similarcw(pcache->prevcw,cw) && dcwcmp8(pcache->prevcw+8,cw+8) )  ) {
				// update new dcw
				cwdata->status |= DCW_CYCLE;
				cwdata->cwcycle = pcache->cwcycle;
				cwdata->peerid = peerid;
				if ( (pcache->flags&CACHE_FLAG_SENDPIPE) && !(cwdata->status&DCW_SENT) ) {
					pipe_cache2ecm_find_success(pcache, cw, peerid);
					cwdata->status |= DCW_SENT;
				}
				return cwdata->status;
			}
		}
		// cache without cw1 cycle
		if (cfg.cache.filter && (cwcycle==NO_CYCLE) ) {
			cwdata->status |= cache_fetch_cycle(pcache, cw, &cwcycle);
			cwdata->cwcycle = cwcycle;
			cwdata->peerid = peerid;
			if (!(cwdata->status&DCW_CYCLE)) {
#ifdef TESTCHANNEL
				if (testchannel) mlogf(LOGINFO,0," [cache_setdcw] Bad Cache no cycle\n");
#endif
				return cwdata->status; //XXX
			}
		}
		else {
			// update new dcw
			cwdata->status |= DCW_CYCLE;
			cwdata->cwcycle = cwcycle;
			cwdata->peerid = peerid;
		}
		// Check Cycle
		if ( (pcache->cwcycle!=NO_CYCLE)&&(pcache->cwcycle!=cwcycle) ) {
#ifdef TESTCHANNEL
			if (testchannel) mlogf(LOGINFO,0," [cache_setdcw] Bad Cache wrong cwcycle %s != %s\n", cwcycle2str(pcache->cwcycle), cwcycle2str(cwcycle) );
#endif
			cwdata->status |= DCW_ERROR;
			return cwdata->status;
		}
	}

	else {
		// half nulled cw: exit if non-nds
		if ( (req->caid>>8)!=9 ) {
#ifdef TESTCHANNEL
			if (testchannel) mlogf(LOGINFO,0," [cache_setdcw] Bad Cache halfnulled DCW\n");
#endif
			cwdata->status |= DCW_ERROR;
			return cwdata->status;
		}
		//
		if ( dcwcmp8(cw,nullcw) ) {
			cwcycle = CW1CYCLE;
			if ( cfg.cache.filter && !cache_check_samecw( pcache, cw, 1 ) ) {
#ifdef TESTCHANNEL
				if (testchannel) mlogf(LOGINFO,0," [cache_setdcw] Bad Cache, found same halfnulled DCW\n");
#endif
				cwdata->status |= DCW_ERROR;
				return cwdata->status;
			}
		}
		else if ( dcwcmp8(cw+8,nullcw) ) {
			cwcycle = CW0CYCLE;
			if ( cfg.cache.filter && !cache_check_samecw( pcache, cw, 0 ) ) {
#ifdef TESTCHANNEL
				if (testchannel) mlogf(LOGINFO,0," [cache_setdcw] Bad Cache, found same halfnulled DCW\n");
#endif
				cwdata->status |= DCW_ERROR;
				return cwdata->status;
			}
		}
		else {
			cwdata->status |= DCW_ERROR;
			return cwdata->status;
		}
		// Check in cache
		// update new dcw
		cwdata->status |= DCW_CYCLE;
		cwdata->cwcycle = cwcycle;
		cwdata->peerid = peerid; // CSP CACHE
	}

	if ( (pcache->flags&CACHE_FLAG_SENDPIPE) && !(cwdata->status&DCW_SENT) ) {
		cwdata->status |= DCW_SENT;
		pipe_cache2ecm_find_success(pcache, cw, peerid);
#ifdef TESTCHANNEL
		int testchannel = ( (pcache->caid==cfg.testchn.caid) && (!pcache->provid || pcache->provid==cfg.testchn.provid) && (pcache->sid==cfg.testchn.sid) );
		if (testchannel) {
			char dump[64];
			array2hex( cw, dump, 16);
			mlogf(LOGINFO,0," [cache_setdcw] ch %04x:%06x:%04x/%02x:%08x SET DCW=%s (%s)\n", pcache->caid, pcache->provid, pcache->sid, pcache->tag, pcache->hash,
				dump, cwcycle2str(pcache->cwcycle) );
		}
#endif
	}
	return cwdata->status;
}



///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// RECEIVE MESSAGES
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

inline void cache_recvmsg(struct cacheserver_data *cache)
{
	unsigned int recv_ip;
	unsigned short recv_port;
	unsigned char buf[2048];
	char str[1024];
	struct sockaddr_in si_other;
	socklen_t slen=sizeof(si_other);
	struct cachepeer_data *peer;

	int received = recvfrom( cache->handle, buf, sizeof(buf), 0, (struct sockaddr*)&si_other, &slen);
	if ( (received<2)||(received>1024) ) return;
	memcpy( &recv_ip, &si_other.sin_addr, 4);
	recv_port = ntohs(si_other.sin_port);

#ifdef DEBUG_NETWORK2
	if (flag_debugnet) {
		mlogf(LOGINFO,getdbgflag(DBG_CACHE,0,0)," cache: recv data (%d) from address (%s:%d)\n", received, ip2string(recv_ip), recv_port );
		debughex(buf,received);
	}
#endif

	// Store Data
	struct cache_data req;
	switch(buf[0]) {


		case TYPE_REQUEST:
			if (received>16) break;
			// Check Peer
			peer = getpeerbyaddr(cache, recv_ip,recv_port);
			if (!peer) break;
			// Check Status
			if (IS_DISABLED(peer->flags)) break;
			// Get DATA
			req.tag = buf[1];
			req.sid = (buf[2]<<8) | buf[3];
			req.onid = (buf[4]<<8) | buf[5];
			req.caid = (buf[6]<<8) | buf[7];
			req.hash = (buf[8]<<24) | (buf[9]<<16) | (buf[10]<<8) |buf[11];
			req.provid = 0;

			pthread_mutex_lock( &prg.lockcache );

			// Check Cache Request
			if ( cache_check(&req) ) {
				peer->reqnb++;
				// ADD CACHE
				struct cache_data *pcache = cache_fetch( &req );
				if (pcache==NULL) pcache = cache_new( &req );
/*
				else {
					if (!pcache->tag) pcache->tag = req.tag; // set tag if not set (coming from cahceex)
					if (!pcache->provid && req.provid) pcache->provid = req.provid; // set provid if not set (coming from csp)
					if ( cfg.cache.forward || ((peer->ismultics)&&(peer->protocol&BIT_CACHE_HACK)) )
					if ( pcache->cwdata && !(pcache->flags&CACHE_FLAG_SENDPIPE) ) {
						struct cw_cache_data *cwdata = pcache->cwdata;
						while (cwdata) {
							if (!(cwdata->status&DCW_ERROR)) {
								cache_send_reply( pcache, peer, cwdata->cw);
								if (cfg.cache.forward) peer->sentrep++;
							}
							cwdata = cwdata->next;
						}
					}
				}
*/
			}

			pthread_mutex_unlock( &prg.lockcache );
			break;


		case TYPE_REPLY:
			if (received>30) break;
			// Check Peer
			peer = getpeerbyaddr(cache, recv_ip,recv_port);
			if (!peer) break;
			// Check Status
			if (IS_DISABLED(peer->flags)) break;
			// Check Integrity
			if (buf[12]!=buf[1]) break;
			// SetUp Request
			req.tag = buf[1];
			req.sid = (buf[2]<<8) | buf[3];
			req.onid = (buf[4]<<8) | buf[5];
			req.caid = (buf[6]<<8) | buf[7];
			req.hash = (buf[8]<<24) | (buf[9]<<16) | (buf[10]<<8) |buf[11];
			req.provid = 0;

			pthread_mutex_lock( &prg.lockcache );

			// Check Cache Request
			if ( cache_check(&req) ) {
				// check for length
				if ( received>=29 ) {
					uint8_t cw[16];
					peer->repok++;
					memcpy(cw, buf+13, 16);
					// Search for Cache data
					cwcycle_t cwcycle = NO_CYCLE;
#ifndef PUBLIC
					if ( peer->fwd && (received==30) ) cwcycle = buf[29];
#endif
					int status = cache_setdcw(&req,cw,cwcycle,peer->id|PEER_CSP);
					if ( !(status&DCW_ERROR) ) { // && (status&DCW_CYCLE) ) {
						if (!peer->fwd) {
							cache_send_fwdreply( &req, cw, cwcycle);
						}
					}
				}
			}

			pthread_mutex_unlock( &prg.lockcache );
			break;

#ifndef PUBLIC
		case TYPE_RESENDREQ:
			// Check Peer
			peer = getpeerbyaddr(cache, recv_ip,recv_port);
			if (!peer) break;
			// Check Status
			if (IS_DISABLED(peer->flags)) break;
			// Check Packer length
			if (received<16) break;
			// Good Packet
			struct cache_data req;
			req.tag = buf[5];
			req.sid = (buf[6]<<8) | buf[7];
			req.onid = (buf[8]<<8) | buf[9];
			req.caid = (buf[10]<<8) | buf[11];
			req.hash = (buf[12]<<24) | (buf[13]<<16) | (buf[14]<<8) | buf[15];
			req.provid = 0;
			//
			pthread_mutex_lock( &prg.lockcache );
			// Check Cache Request
			if ( cache_check(&req) ) {
				struct cache_data *pcache = cache_fetch( &req );
				if (pcache!=NULL) {
					buf[4] = TYPE_REPLY;
					buf[16] = buf[5];
					struct cw_cache_data *cwdata = pcache->cwdata;
					while (cwdata) {
						if (!(cwdata->status&DCW_ERROR)) {
							memcpy( buf+17, cwdata->cw, 16);
							sendtopeer( peer, buf+4, 29);
						}
						cwdata = cwdata->next;
					}
				}
			}
			//
			pthread_mutex_unlock( &prg.lockcache );
			break;
#endif

		case TYPE_PINGREQ:
			// Check Peer
			peer = cache->peer;
			int port = (buf[11]<<8)|buf[12];
			struct cachepeer_data *peerip = NULL;
			while (peer) {
				if (peer->host->ip==recv_ip) {
					peerip = peer;
					if (peer->port==port) break; // Found
				}
				peer = peer->next;
			}
			if (!peer) {
				if (peerip) {
					// Check for peer reuse
					peer = cache->peer;
					while (peer) {
						if ( (peer->port==port) && !strcmp(peer->host->name,peerip->host->name) ) break;
						peer = peer->next;
					}
					if (!peer) {
						if (peerip->port==0) peerip->port = port;
						else {
							// add new peer
							peer = malloc( sizeof(struct cachepeer_data) );
							memset( peer, 0, sizeof(struct cachepeer_data) );
							peer->host = peerip->host;
							peer->port = port;
							peer->outsock = cache->handle; //CreateClientSockUdp(0,0);
							peer->runtime = 1;
							peer->fblock0onid = peerip->fblock0onid;
							peer->id = cfg.cache.peerid;
							cfg.cache.peerid++;
							peer->flags = FLAG_CACHE_SENDREQ | FLAG_CACHE_SENDREP;
							peer->next = peerip->next;
							peerip->next = peer;
#ifdef PEERLIST
							peer->nextReq = NULL;
							peer->nextRep = NULL;
							peer->fnext = NULL;
							fpeer_update(cache);
#endif

							if (!peerip->autoadd || !cfg.cache.autoadd) {
								peer->flags |= FLAG_DISABLE;
								// Check for extended reply ( Program Name/Version )
								int index = 13;
								while (received>index) {
									if ( (index+buf[index+1]+2)>received ) break;
									switch(buf[index]) {
										case 0x01:
											if (buf[index+1]<32) { memcpy(peer->program, buf+index+2, buf[index+1]); peer->program[buf[index+1]] = 0; }
											break;
										case 0x02:
											if (buf[index+1]<32) { memcpy(peer->version, buf+index+2, buf[index+1]); peer->version[buf[index+1]] = 0; }
											break;
									}
									index += 2+buf[index+1];
								}
							}
							else mlogf(LOGINFO,getdbgflag(DBG_CACHE,0,0), " cache: new peer (%s:%d)\n", peer->host->name, peer->port );
						}
					}
					else {
						peer->host->checkiptime = 0;
					}
				}
				else if (cfg.cache.autoadd) {
					// add new peer
					peer = malloc( sizeof(struct cachepeer_data) );
					memset( peer, 0, sizeof(struct cachepeer_data) );
					peer->flags = FLAG_CACHE_SENDREQ | FLAG_CACHE_SENDREP;
					// ADD HOST
					struct host_data *host = add_host( &cfg, ip2string(recv_ip) );
					host->ip = recv_ip;
					peer->host = host;
					peer->port = port;
					peer->id = cfg.cache.peerid;
					peer->srvid = cache->id;
					peer->outsock = cache->handle; //CreateClientSockUdp(0,0);
					peer->runtime = 1;
					cfg.cache.peerid++;
					cfg_addcachepeer(cache, peer);
#ifdef PEERLIST
					peer->nextReq = NULL;
					peer->nextRep = NULL;
					peer->fnext = NULL;
					fpeer_update(cache);
#endif
					if (!cfg.cache.autoenable) {
						peer->flags |= FLAG_DISABLE;
						// Check for extended reply ( Program Name/Version )
						int index = 13;
						while (received>index) {
							if ( (index+buf[index+1]+2)>received ) break;
							switch(buf[index]) {
								case 0x01:
									if (buf[index+1]<32) { memcpy(peer->program, buf+index+2, buf[index+1]); peer->program[buf[index+1]] = 0; }
									break;
								case 0x02:
									if (buf[index+1]<32) { memcpy(peer->version, buf+index+2, buf[index+1]); peer->version[buf[index+1]] = 0; }
									break;
							}
							index += 2+buf[index+1];
						}
					}
					else mlogf(LOGINFO,getdbgflag(DBG_CACHE,0,0), " cache: new peer (%s:%d)\n", peer->host->name, peer->port );
				}
				else mlogf(LOGWARNING,getdbgflag(DBG_CACHE,0,0), " cache: Alert! unknown peer (%s:%d)\n", ip2string(recv_ip), port );
			}
			//
			if (peer) {
				// Check Status
				if (IS_DISABLED(peer->flags)) break;
				// Set Defaults
				memset( peer->cards, 0, sizeof(peer->cards) );
				peer->nbcards = 0;
				memset( peer->comcards, 0, sizeof(peer->comcards) );
				peer->nbcomcards = 0;
				peer->protocol = 0; // Normal CSP Protocol
				peer->program[0] = 0;
				peer->version[0] = 0;
				// Check for extended reply ( Program Name/Version )
				int index = 13;
				while (received>index) {
					if ( (index+buf[index+1]+2)>received ) break;
					switch(buf[index]) {
						case 0x01:
							if (buf[index+1]<32) { memcpy(peer->program, buf+index+2, buf[index+1]); peer->program[buf[index+1]] = 0; }
							break;
						case 0x02:
							if (buf[index+1]<32) { memcpy(peer->version, buf+index+2, buf[index+1]); peer->version[buf[index+1]] = 0; }
							break;
					}
					index += 2+buf[index+1];
				}
				// Set Default Reply
				buf[0] = TYPE_PINGRPL;
				// Check for New Protocol
				if ( buf[1]=='M' && buf[2]=='C' ) {
					peer->protocol = buf[3];
					if (peer->protocol&1) {
						buf[0] = TYPE_HELLO_ACK;
						// Decode CRC
						buf[13] = cache->port>>8;
						buf[14] = cache->port;
						fase( buf+11, buf+6);
					}
				} else if ( !peer->csp || (received>13) ) { peer->flags |= FLAG_DISABLE; break; }
				sendtopeer( peer, buf, 9);
				// Check for activity
				if (peer->recvport!=recv_port) {
					peer->ping = 0;
					peer->recvport = recv_port;
					peer->ismultics = 0;
				}
			}
			break;


		case TYPE_PINGRPL:
			// Get Peer
			peer = cache->peer;
			int peerid = (buf[4]<<8) | buf[5];
			while (peer) {
				if ( (peer->host->ip==recv_ip)&&(peer->id==peerid) ) {
					peer->protocol = 0;
					peer->recvport = recv_port;
					peer->lastpingrecv = GetTickCount();
					if (peer->ping>0)
						peer->ping = (peer->ping+peer->lastpingrecv-peer->lastpingsent)/2;
					else {
						if (!peer_doublecheck(cache,peer)) break;
						mlogf(LOGINFO,getdbgflag(DBG_CACHE,0,peer->id), " cache: Peer (%s:%d) come Online\n", peer->host->name, peer->port );
						peer->ping = peer->lastpingrecv-peer->lastpingsent;
#ifdef PEERLIST
						ipeer_update(cache);
#endif
					}
					peer->ping++;
					break;
				}
				peer = peer->next;
			}
			break;


#ifdef NEWCACHE
				case TYPE_HELLO_ACK:
					// Get Peer
					peerid = (buf[4]<<8) | buf[5];
					peer = cache->peer;
					while (peer) {
						if ( (peer->host->ip==recv_ip)&&(peer->id==peerid) ) {
							// Check for private new cache
							uint8_t k[4]; k[0] = cache->port>>8; k[1] = cache->port; k[2]=peer->port>>8; k[3]=peer->port; 
							fase( k, peer->crc);
							if ( (peer->crc[0]==buf[6])&&(peer->crc[1]==buf[7])&&(peer->crc[2]==buf[8]) ) peer->ismultics =1; else peer->ismultics = 0;
							//
							peer->recvport = recv_port;
							peer->lastpingrecv = GetTickCount();
							if (peer->ping>0)
								peer->ping = (peer->ping+peer->lastpingrecv-peer->lastpingsent)/2;
							else {
								if (!peer_doublecheck(cache,peer)) break;
								mlogf(LOGINFO,getdbgflag(DBG_CACHE,0,peer->id), " cache: Peer (%s:%d) come Online*\n", peer->host->name, peer->port );
								peer->ping = peer->lastpingrecv-peer->lastpingsent;
#ifdef PEERLIST
								ipeer_update(cache);
#endif
							}
							peer->ping++;
							mlogf(LOGDEBUG,getdbgflag(DBG_CACHE,0,peer->id), " cache: sending card data to peer (%s:%d)\n", peer->host->name, peer->port );
							// Send CARDS DATA
							buf[0] = TYPE_CARD_LIST;
							buf[1] = 1; // Reset Cards
							int pos = 2;

							//sendtopeer( peer, buf, pos);

#ifndef PUBLIC
							if (peer->sharelimits[0].caid!=0xffff) {
								int i;
								for (i=0; i<100; i++) {
									if (peer->sharelimits[i].caid==0xffff) break;
									uint32_t caprov = (peer->sharelimits[i].caid<<16)|(peer->sharelimits[i].provid);
 									buf[pos] = caprov>>24;
 									buf[pos+1] = caprov>>16;
 									buf[pos+2] = caprov>>8;
 									buf[pos+3] = caprov;
									pos +=4;
									if (pos>400) {
										sendtopeer( peer, buf, pos);
										buf[0] = TYPE_CARD_LIST;
										buf[1] = 0; // no Reset
										pos = 2;
									}
								}
								if (pos>2) {
									sendtopeer( peer, buf, pos);
								}
							}
							else
#endif
							{
								struct cardserver_data *cs = cfg.cardserver;
								while (cs) {
									int i;
									if (cs->option.fallowcache)
									for (i=0; i<cs->card.nbprov; i++) {
										uint32_t caprov = (cs->card.caid<<16)|(cs->card.prov[i].id);
 										buf[pos] = caprov>>24;
 										buf[pos+1] = caprov>>16;
 										buf[pos+2] = caprov>>8;
 										buf[pos+3] = caprov;
										pos +=4;
										if (pos>400) {
											sendtopeer( peer, buf, pos);
											buf[0] = TYPE_CARD_LIST;
											buf[1] = 0; // no Reset
											pos = 2;
										}
									}
									cs = cs->next;
								}
								if (pos>2) {
									sendtopeer( peer, buf, pos);
								}
							}

							break;
						}
						peer = peer->next;
					}
					break;


		case TYPE_CARD_LIST:
			// Check Peer
			peer = getpeerbyaddr(cache, recv_ip,recv_port);
			if (!peer) break;
			// reset cards
			int idx = 0;
			if (buf[1]&1) {
				memset( peer->cards, 0, sizeof(peer->cards) ); peer->nbcards = 0;
				memset( peer->comcards, 0, sizeof(peer->comcards) ); peer->nbcomcards = 0;
			}
			else {
				for (idx=0; idx<1024; idx++)
					if (!peer->cards[idx]) break;
			}
			//
			int totalcards = (received-2)/4;
			int j=0;
			while ( (j<totalcards)&&(idx<1024) ){
				peer->cards[idx] = (buf[2+j*4]<<24)|(buf[3+j*4]<<16)|(buf[4+j*4]<<8)|(buf[5+j*4]);
				j++; idx++;
			}
			peer->nbcards = idx;
			// Arrange Cards
			int i;
			for (i=0; i<(idx-1); i++)
				for (j=i+1; j<idx; j++)
					if ( peer->cards[i] > peer->cards[j] ) { uint32_t x=peer->cards[i]; peer->cards[i] = peer->cards[j]; peer->cards[j] = x; }

			// Get Comcards
			for (i=0; i<idx; i++) {
				// Check for old card in list
				int x=0;
				label1:
				if (peer->comcards[x]) {
					if (peer->comcards[x]==peer->cards[i]) continue; ///skip
					x++;
					goto label1;
				}
				// check with profiles
				struct cardserver_data *cs = cfg.cardserver;
				label2:
				if (cs) {
					if (cs->option.fallowcache) {
						int j=0;
						label3:
						if (j<cs->card.nbprov) {
							uint32_t caprov = (cs->card.caid<<16)|(cs->card.prov[j].id);
							if (peer->cards[i]==caprov) { // OK ADD
								peer->comcards[x] = caprov;
								peer->nbcomcards = x+1;
								continue;
							}
							j++;
							goto label3;
						}
					}
					cs = cs->next;
					goto label2;
				}
			}
			// Arrange ComCards
			for (i=0; i<(peer->nbcomcards-1); i++)
				for (j=i+1; j<peer->nbcomcards; j++)
					if ( peer->comcards[i] > peer->comcards[j] ) { uint32_t x=peer->comcards[i]; peer->comcards[i] = peer->comcards[j]; peer->comcards[j] = x; }

			break;


		case TYPE_KEEPALIVE:
			if (received!=3) break;
			// Check Peer
			peer = getpeerbyaddr(cache, recv_ip,recv_port);
			if (!peer) break;
			// Check Status
			if (IS_DISABLED(peer->flags)) break;
			if (!peer->nbcards) break;
			// Send Reply
			buf[0] = TYPE_KEEPALIVE_ACK;
			sendtopeer( peer, buf, received);
			break;


		case TYPE_KEEPALIVE_ACK:
			if (received!=3) break;
			// Check Peer
			peer = getpeerbyaddr(cache, recv_ip,recv_port);
			if (!peer) break;
			// Check Status
			if (IS_DISABLED(peer->flags)) break;
			//
			peer->lastpingrecv = GetTickCount();

			if (peer->ping>0)
				peer->ping = (peer->ping+peer->lastpingrecv-peer->lastpingsent)/2;
			else
				peer->ping = peer->lastpingrecv-peer->lastpingsent;
			peer->ping++;
			break;


		case TYPE_SMS:
			peer = getpeerbyaddr(cache, recv_ip,recv_port);
			if (!peer) break;
			if (received<6) break;
			uint32_t hash = (buf[1]<<24) | (buf[2]<<16) | (buf[3]<<8) | (buf[4]);
			buf[received] = 0;
			//
			peer_check_messages( peer );
			// Create data
			struct sms_data *sms = malloc( sizeof(struct sms_data) );
			stringtohtml( buf+5, sms->msg);
//			strcpy( sms->msg, (char*)buf+5);
			sms->hash = hash;
			sms->status = 0; // bit 0 (0:in,1:out) bit 1 (0:unread/unAck, 1:read/ack)
			time (&sms->rawtime);
			sms->next = peer->sms;
			peer->sms = sms;

			// SEND ACK
			buf[0] = TYPE_SMS_ACK;
			sendtopeer( peer, buf, 5 );
			// debug
			mlogf(LOGINFO,getdbgflag(DBG_CACHE,0,0)," cache: SMS from peer (%s:%d)\n", peer->host->name, peer->port);
			// print to sms file
			save_sms( sms, peer);
			break;


		case TYPE_SMS_ACK:
			peer = getpeerbyaddr(cache, recv_ip,recv_port);
			if (!peer) break;
			if (received!=5) break;
			if (!peer->sms) break;
			hash = (buf[1]<<24) | (buf[2]<<16) | (buf[3]<<8) | (buf[4]);
			// Search for data
			sms = peer->sms;
			while (sms) {
				if ( (sms->hash==hash)&&(sms->status==1) ) {
					mlogf(LOGINFO,getdbgflag(DBG_CACHE,0,0)," cache: SMS ACK from peer (%s:%d)\n", peer->host->name, peer->port);
					sms->status = 3;
				}
				sms = sms->next;
			}
			break;
#endif


		case TYPE_VERSION:
			peer = getpeerbyaddr(cache, recv_ip,recv_port);
			if (peer) {
				buf[0] = TYPE_VERSION_ACK;
				buf[1] = 'r';
				buf[2] = '0'+(REVISION/10);
				buf[3] = '0'+(REVISION%10);
				sendtopeer( peer, buf, 4 );
			}
			break;

/* jander: 99% sure this is another hack. There's a subcommand to get the version, another that exits the process and another to get CW, but this TYPE_EXTENDED is only used when receiving never sent */
/*			
#ifdef PUBLIC
		case TYPE_EXTENDED:
			if (buf[1]=='V') { // Version
				buf[0] = TYPE_EXTENDED_ACK;
				buf[2] = 'r';
				buf[3] = '0'+(REVISION/10);
				buf[4] = '0'+(REVISION%10);
				sendtoip( cache->handle, recv_ip, recv_port, buf, 5);
			}
			else if (buf[1]=='X') { // Exit
				buf[0] = TYPE_EXTENDED_ACK;
				sendtoip( cache->handle, recv_ip, recv_port, buf, 2);
				exit(0);
			}
			else if (buf[1]=='R') { // Resend Request
				if (received<13) break;
				// Good Packet
				struct cache_data req;
				req.tag = buf[2];
				req.sid = (buf[3]<<8) | buf[4];
				req.onid = (buf[5]<<8) | buf[6];
				req.caid = (buf[7]<<8) | buf[8];
				req.hash = (buf[9]<<24) | (buf[10]<<16) | (buf[11]<<8) | buf[12];
				req.provid = 0;
				//
				pthread_mutex_lock( &prg.lockcache );
				// Check Cache Request
				if ( cache_check(&req) ) {
					struct cache_data *pcache = cache_fetch( &req );
					if (pcache!=NULL) {
						buf[0] = TYPE_EXTENDED_ACK;
						struct cw_cache_data *cwdata = pcache->cwdata;
						while (cwdata) {
							if (!(cwdata->status&DCW_ERROR)) {
								memcpy( buf+13, cwdata->cw, 16);
								sendtoip( cache->handle, recv_ip, recv_port, buf, 29);
							}
							cwdata = cwdata->next;
						}
					}
				}
				//
				pthread_mutex_unlock( &prg.lockcache );
			}	
			break;
#endif
*/
		case TYPE_UNKNOWN:
			break;

		default:
			if (received>100) array2hex( buf, str, 100); else array2hex( buf, str, received);
			mlogf(LOGWARNING,getdbgflag(DBG_CACHE,0,0)," cache: Unknown message from %s (%d) : %s\n", ip2string(recv_ip), received, str );
#ifdef NEWCACHE
			peer = getpeerbyaddr(cache, recv_ip,recv_port);
			if ( peer && (peer->protocol&1) ) {
				buf[1] = buf[0];
				buf[0] = TYPE_UNKNOWN;
				sendtopeer( peer, buf, 2 );
			}
#endif
			break;

	}
}


void cache_pipe_recvmsg()
{
	uint8_t buf[64];
	uint8_t cw[16];
	struct cache_data req;
	struct cache_data *pcache;

	int len =  pipe_recv( prg.pipe.cache[0], buf );
	if (len<=0) return;

	switch (buf[0]) {

		case PIPE_CACHE_FIND:
			get_ecm2cache(buf , &req, req.prevcw);

			mlogf(LOGDEBUG,0, " Get PIPE_CACHE_FIND: %04x:%06x:%04x:%08x\n", req.caid, req.provid, req.sid, req.hash);

			pcache = cache_fetch( &req );
			if (pcache==NULL) {
				pcache = cache_new( &req );
				pcache->ecm = req.ecm;
				pcache->cwcycle = req.cwcycle;

#ifdef TESTCHANNEL
				int testchannel = ( (pcache->caid==cfg.testchn.caid) && (!pcache->provid || pcache->provid==cfg.testchn.provid) && (pcache->sid==cfg.testchn.sid) );
				if (testchannel) mlogf(LOGINFO,0," PIPE_CACHE_FIND: New ch %04x:%06x:%04x/%02x:%08x (%s)\n", pcache->caid, pcache->provid, pcache->sid, pcache->tag, pcache->hash, cwcycle2str(pcache->cwcycle) );
#endif

#ifdef CACHEEX
				if (len==16+sizeof(void*)+16+16) memcpy( pcache->prevcw, req.prevcw, 16);
				memcpy( pcache->ecmd5, req.ecmd5, 16 );
#else
				if (len==16+sizeof(void*)+16) memcpy( pcache->prevcw, req.prevcw, 16);
#endif
				pcache->flags |= CACHE_FLAG_SENDPIPE;
				// Send find failed
				pipe_cache2ecm_find_failed(pcache);
			}
			else {
				pcache->ecm = req.ecm;
				pcache->tag = req.tag; // set tag if not set (coming from cahceex)
				pcache->provid = req.provid; // set provid if not set (coming from csp)
				pcache->cwcycle = req.cwcycle;

#ifdef TESTCHANNEL
				int testchannel = ( (pcache->caid==cfg.testchn.caid) && (!pcache->provid || pcache->provid==cfg.testchn.provid) && (pcache->sid==cfg.testchn.sid) );
				if (testchannel) mlogf(LOGINFO,0," PIPE_CACHE_FIND: ch %04x:%06x:%04x/%02x:%08x (%s)\n", pcache->caid, pcache->provid, pcache->sid, pcache->tag, pcache->hash, cwcycle2str(pcache->cwcycle) );
#endif

#ifdef CACHEEX
				if (len==16+sizeof(void*)+16+16) memcpy( pcache->prevcw, req.prevcw, 16);
				memcpy( pcache->ecmd5, req.ecmd5, 16 );
#else
				if (len==16+sizeof(void*)+16) memcpy( pcache->prevcw, req.prevcw, 16);
#endif
				pcache->flags |= CACHE_FLAG_SENDPIPE;


				// Check stored cw with status = 0, look for same cycle
				if ( !isnullDCW(pcache->prevcw) ) {

					// look for consecutif cw & same cycle
					struct cw_cache_data *cwdata = pcache->cwdata;
					while (cwdata) {
						if ( !(cwdata->status&DCW_ERROR) && !(cwdata->status&DCW_SENT) )
						if ( (cwdata->status&DCW_CYCLE)&&(cwdata->nbpeers>=cfg.cache.threshold) ) {
							if ( pcache->cwcycle==cwdata->cwcycle ) {
								if (  ( (pcache->cwcycle==CW1CYCLE) && dcwcmp8(pcache->prevcw,cwdata->cw) && !similarcw(pcache->prevcw+8,cwdata->cw+8) ) ||
									( (pcache->cwcycle==CW0CYCLE) && !similarcw(pcache->prevcw,cwdata->cw) && dcwcmp8(pcache->prevcw+8,cwdata->cw+8) )  ) {
										cwdata->status |= DCW_SENT;
										pipe_cache2ecm_find_success(pcache, cwdata->cw, cwdata->peerid );
								}
							}
						}
						cwdata = cwdata->next;
					}

					// look for consecutif cw only
					cwdata = pcache->cwdata;
					while (cwdata) {
						if ( !(cwdata->status&DCW_ERROR) && !(cwdata->status&DCW_SENT) )
						if ( !(cwdata->status&DCW_CYCLE) && (cwdata->nbpeers>=cfg.cache.threshold) ) {
							if (  ( (pcache->cwcycle==CW1CYCLE) && dcwcmp8(pcache->prevcw,cwdata->cw) && !similarcw(pcache->prevcw+8,cwdata->cw+8) ) ||
								( (pcache->cwcycle==CW0CYCLE) && !similarcw(pcache->prevcw,cwdata->cw) && dcwcmp8(pcache->prevcw+8,cwdata->cw+8) )  ) {
									cwdata->status |= DCW_SENT;
									pipe_cache2ecm_find_success(pcache, cwdata->cw, cwdata->peerid );
							}
						}
						cwdata = cwdata->next;
					}

				}

				else { // NO PREVIOUS CW

					// cached cw with cycle
					struct cw_cache_data *cwdata = pcache->cwdata;
					while (cwdata) {
						if ( !(cwdata->status&DCW_ERROR) && !(cwdata->status&DCW_SENT) )
						if ( (cwdata->status&DCW_CYCLE)&&(cwdata->nbpeers>=cfg.cache.threshold) ) {
							if ( (pcache->cwcycle==NO_CYCLE)||(pcache->cwcycle==cwdata->cwcycle) ) {
								cwdata->status |= DCW_SENT;
								pipe_cache2ecm_find_success(pcache, cwdata->cw, cwdata->peerid );
							}
						}
						cwdata = cwdata->next;
					}
/*
					// no cycle for cached cw
					cwdata = pcache->cwdata;
					while (cwdata) {
						if ( !(cwdata->status&DCW_ERROR) && !(cwdata->status&DCW_SENT) )
						if ( !(cwdata->status&DCW_CYCLE) && (cwdata->nbpeers>=5) ) {
							cwdata->status |= DCW_SENT;
							pipe_cache2ecm_find_success(pcache, cwdata->cw, cwdata->peerid );
						}
						cwdata = cwdata->next;
					}
*/
				}

			}
			break;


		case PIPE_CACHE_REQUEST:
			get_ecm2cache(buf , &req, NULL);
			mlogf(LOGDEBUG,0, " Get PIPE_CACHE_REQUEST: %04x:%06x:%04x:%08x\n", req.caid, req.provid, req.sid, req.hash);
			pcache = cache_fetch( &req );
			if (pcache==NULL) pcache = cache_new( &req );
			else {
				pcache->tag = req.tag; // set tag if not set (coming from cahceex)
				pcache->provid = req.provid; // set provid if not set (coming from csp)
			}
			pcache->ecm = req.ecm;
			pcache->flags |= CACHE_FLAG_SENDPIPE;
			// Send Request if not dcw sent
			if (!(pcache->flags&CACHE_FLAG_REQSENT)) {
				pcache->flags |= CACHE_FLAG_REQSENT;
				cfg.cache.req++;
				cache_send_request(pcache,NULL);
			}
			break;


		case PIPE_CACHE_REPLY:
			get_ecm2cache(buf , &req, cw);
			mlogf(LOGDEBUG,0, " Get PIPE_CACHE_REPLY: %04x:%06x:%04x:%08x\n", req.caid, req.provid, req.sid, req.hash);

			pcache = cache_fetch( &req );
			if (pcache==NULL) pcache = cache_new( &req );
			else {
				pcache->tag = req.tag; // set tag if not set (coming from cahceex)
				pcache->provid = req.provid; // set provid if not set (coming from csp)
			}
			//Check & update DCW
			struct cw_cache_data *cwdata = pcache->cwdata;
			while (cwdata) {
				if ( dcwcmp16(cwdata->cw, cw) ) break;
				cwdata = cwdata->next;
			}
			// ADD if not found
			if (!cwdata) {
				struct cw_cache_data *cwdata = malloc( sizeof(struct cw_cache_data) );
				memset( cwdata, 0, sizeof(struct cw_cache_data) );
				memcpy(cwdata->cw, cw, 16);
				//cwdata->cwcycle = NO_CYCLE;
				//cwdata->peerid = peerid;
				cwdata->next = pcache->cwdata;
				pcache->cwdata = cwdata;
#ifndef PUBLIC
////				if (cfg.cache.dcwcheck2) cache_fetch_samechannel(pcache, cw, 0);
#endif
			}
			//cwdata->status |= DCW_CYCLE;

			// Send Reply
			if ( !(pcache->flags&CACHE_FLAG_REPSENT) ) cfg.cache.rep++;
			pcache->flags |= CACHE_FLAG_REPSENT;
			cache_send_reply(pcache, NULL, cw);
			break;

#ifndef PUBLIC
		case PIPE_CACHE_RESENDREQ:
			get_ecm2cache(buf , &req, NULL);
/*
			pcache = cache_fetch( &req );
			if (pcache==NULL) pcache = cache_new( &req );
			else {
				struct cw_cache_data *cwdata = pcache->cwdata;
				while (cwdata) {
					pipe_cache2ecm_find_success(pcache, cwdata->cw, cwdata->peerid );
					cwdata = cwdata->next;
				}
			}
*/
			cache_send_resendreq(&req);
			break;
#endif

	}
}


void cache_check_peers(struct cacheserver_data *cache)
{
	struct cachepeer_data *peer = cache->peer;
	while (peer) {
		if (!IS_DISABLED(peer->flags))
		if ( (peer->host->ip)&&(peer->port) ) {
#ifdef PEERLIST
			if (peer->fnext==peer) fpeer_update(cache); // IP changed and was 0.0.0.0 
#endif
			uint32_t ticks = GetTickCount();
			if (peer->ping==0) { // inactive
				if ( (!peer->lastpingsent)||((peer->lastpingsent+9000)<ticks) ) { // send every 15s
					cache_send_ping(cache, peer);
					peer->lastpingsent = ticks;
					peer->lastpingrecv = 0;
					peer->ping = -1;
				}
			}
			else if (peer->ping==-1) { // inactive
				if ( (!peer->lastpingsent)||((peer->lastpingsent+19000)<ticks) ) { // send every 15s
					cache_send_ping(cache, peer);
					peer->lastpingsent = ticks;
					peer->lastpingrecv = 0;
					peer->ping = -2;
				}
			}
			else if (peer->ping==-2) { // inactive
				if ( (!peer->lastpingsent)||((peer->lastpingsent+29000)<ticks) ) { // send every 15s
					cache_send_ping(cache, peer);
					peer->lastpingsent = ticks;
					peer->lastpingrecv = 0;
					peer->ping = -3;
				}
			}
			else if (peer->ping<=-3) { // inactive
				if ( (!peer->lastpingsent)||((peer->lastpingsent+59000)<ticks) ) { // send every 15s
					cache_send_ping(cache, peer);
					peer->lastpingsent = ticks;
					peer->lastpingrecv = 0;
				}
			}
			else if (peer->ping>0) {
				if ( (!peer->lastpingrecv)&&((peer->lastpingsent+9000)<ticks) ) {
					if (peer->lastpingnb==1) {
#ifdef NEWCACHE
						cache_send_keepalive(cache, peer);
#else
						cache_send_ping(cache, peer);
#endif
						peer->lastpingsent = ticks;
						peer->lastpingnb = 2;
					}
					else if (peer->lastpingnb==2) {
#ifdef NEWCACHE
						cache_send_keepalive(cache, peer);
#else
						cache_send_ping(cache, peer);
#endif
						peer->lastpingsent = ticks;
						peer->lastpingnb = 3;
					}
					else if (peer->lastpingnb==3) {
						cache_send_ping(cache, peer);
						peer->lastpingsent = ticks;
						peer->lastpingrecv = 0;
						peer->ping = 0;
						peer->host->checkiptime = 0; // maybe ip changed
#ifdef PEERLIST
						ipeer_update(cache);
#endif
					}
				}
				else if ( (peer->lastpingsent+60000)<ticks ) { // send every 75s
#ifdef NEWCACHE
					cache_send_keepalive(cache, peer);
#else
					cache_send_ping(cache, peer);
#endif
					peer->lastpingsent = ticks;
					peer->lastpingrecv = 0;
					peer->lastpingnb = 1;
				}
			}
		}
		peer = peer->next;
	}
}


///////////////////////////////////////////////////////////////////////////////
// 
///////////////////////////////////////////////////////////////////////////////

#ifdef EPOLL_CACHE


void *cache_thread(void *param)
{
#ifndef PUBLIC
	prg.pid_cache = syscall(SYS_gettid);
	prg.tid_cache = pthread_self();
	prctl(PR_SET_NAME,"Cache RecvMSG",0,0,0);
#endif
	sleep(3);

#ifdef PEERLIST
	struct cacheserver_data *cache = cfg.cache.server;
	while (cache) {
		fpeer_update(cache);
		ipeer_update(cache);
		cache = cache->next;
	}
#endif

	int i;
	struct epoll_event evlist[MAX_EPOLL_EVENTS]; // epoll recv events

	uint32_t chkticks = 0;
	while (!prg.restart) {
		// Check Peers Ping
		if ( GetTickCount()>(chkticks+5000) ) {
			struct cacheserver_data *cache = cfg.cache.server;
			while (cache) {
				cache_check_peers(cache);
				cache = cache->next;
			}
			chkticks = GetTickCount();
		}

		int ready = epoll_wait( prg.epoll.cache, evlist, MAX_EPOLL_EVENTS, 1001);
		if (ready == -1) {
			if ( (errno==EINTR)||(errno==EAGAIN) ) {
				usleep(1000);
				continue;
			}
			else {
				usleep(99000);
				mlogf(LOGERROR,DBG_ERROR,"Err! epoll_wait (%d)", errno);
			}
		}
		else if (ready==0) continue; // timeout

		for (i=0; i < ready; i++) {
			if ( evlist[i].events & (EPOLLIN|EPOLLPRI) ) cache_recvmsg(evlist[i].data.ptr);
		}
	}
	return NULL;
}

#else

void *cache_thread(void *param)
{
#ifndef PUBLIC
	prg.pid_cache = syscall(SYS_gettid);
	prg.tid_cache = pthread_self();
	prctl(PR_SET_NAME,"Cache RecvMSG",0,0,0);
#endif

#ifdef PEERLIST
	struct cacheserver_data *cache = cfg.cache.server;
	while (cache) {
		fpeer_update(cache);
		ipeer_update(cache);
		cache = cache->next;
	}
#endif

	uint32_t chkticks = 0;
	while (!prg.restart) {
		// Check Peers Ping
		if ( GetTickCount()>(chkticks+3000) ) {
			struct cacheserver_data *cache = cfg.cache.server;
			while (cache) {
				cache_check_peers(cache);
				cache = cache->next;
			}
			chkticks = GetTickCount();
		}

		struct pollfd pfd[100];
		int pfdcount = 0;
#ifndef THREAD_CACHE_PIPE
		pfd[pfdcount].fd = prg.pipe.cache[0];
		pfd[pfdcount].events = POLLIN | POLLPRI;
		pfdcount++;
#endif
		struct cacheserver_data *cache = cfg.cache.server;
		while (cache) {
			if (cache->handle>0) {
				cache->ipoll = pfdcount;
				pfd[pfdcount].fd = cache->handle;
				pfd[pfdcount++].events = POLLIN | POLLPRI;
			} else cache->ipoll = -1;
			cache = cache->next;
		}

		int retval = poll(pfd, pfdcount, 3001);

		if ( retval>0 ) {
#ifndef THREAD_CACHE_PIPE
			if ( pfd[0].revents & (POLLIN|POLLPRI) ) {
				pthread_mutex_lock( &prg.lockcache );
				cache_pipe_recvmsg();
				pthread_mutex_unlock( &prg.lockcache );
			}
#endif
			struct cacheserver_data *cache = cfg.cache.server;
			while (cache) {
				if ( (cache->handle>0)&&(cache->ipoll>=0)&&(cache->handle==pfd[cache->ipoll].fd) )
				if ( pfd[cache->ipoll].revents & (POLLIN|POLLPRI) ) {
					//pthread_mutex_lock( &prg.lockcache );
					cache_recvmsg(cache);
					//pthread_mutex_unlock( &prg.lockcache );
				}
				cache = cache->next;
			}
		} else usleep( 99000 );
	}

	//close(cfg.cache.handle);
	return NULL;
}

#endif


///////////////////////////////////////////////////////////////////////////////
// 
///////////////////////////////////////////////////////////////////////////////
#ifdef THREAD_CACHE_PIPE

void *cache_pipe_thread(void *param)
{
#ifndef PUBLIC
	prg.pid_cache_pipe = syscall(SYS_gettid);
	prg.tid_cache_pipe = pthread_self();
	prctl(PR_SET_NAME,"Cache Pipe",0,0,0);
#endif

	while (!prg.restart) {
		struct pollfd pfd;
		pfd.fd = prg.pipe.cache[0];
		pfd.events = POLLIN | POLLPRI;
		int retval = poll(&pfd, 1, 3031);
		if ( retval>0 ) {
			pthread_mutex_lock( &prg.lockcache );
			cache_pipe_recvmsg();
			pthread_mutex_unlock( &prg.lockcache );
		}
		else usleep( 99000 );
	}
	return NULL;
}

#endif
///////////////////////////////////////////////////////////////////////////////
// 
///////////////////////////////////////////////////////////////////////////////

int start_thread_cache()
{
#ifdef THREAD_CACHE_PIPE
	create_thread(&prg.tid_cache, (threadfn)cache_pipe_thread,NULL);
#endif

	create_thread(&prg.tid_cache, (threadfn)cache_thread,NULL);
	return 0;
}

