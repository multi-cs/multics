#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>

#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <netdb.h> 
#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <signal.h>
#include <sys/epoll.h>

#define MAX_EPOLL_EVENTS	100	// Maximum number of events to be returned from a single epoll_wait() call

#include "tools.h"
#include "debug.h"
#include "sockets.h"
#include "threads.h"
#include "convert.h"

#include "des.h"
#include "md5.h"
#include "sha1.h"

#include "msg-newcamd.h"
#ifdef CCCAM
#include "msg-cccam.h"
#endif
#ifdef RADEGAST
#include "msg-radegast.h"
#endif

#include "ecmdata.h"
#include "parser.h"
#include "config.h"
#include "httpserver.h"

#ifdef TELNET
#include "telnet.h"
#endif

#include "cacheex.h"

#include "main.h"

#include "dcw.h"

#include "pipe.c"

char config_file[256] = "/var/etc/multics.cfg";

int flag_debugscr;
#ifdef DEBUG_NETWORK
int flag_debugnet;
#endif
int flag_debugfile;
char debug_file[256];
char sms_file[256];
char ecm_file[256];
int loglevel; // Loglevel of multics

///
///
struct config_data cfg;
struct program_data prg;

uint32_t ecm_check_time = 0;



void srv_cstatadd( struct server_data *srv, int csid, int ok, uint32_t ecmoktime)
{
	int i;
	for(i=0; i<MAX_CSPORTS; i++) {
		if (!srv->cstat[i].csid) {
			srv->cstat[i].csid = csid;
			srv->cstat[i].ecmnb = 1;
			if (ok) {
				srv->cstat[i].ecmok = 1;
				srv->cstat[i].ecmoktime = ecmoktime;
			}
			else {
				srv->cstat[i].ecmok = 0;
				srv->cstat[i].ecmoktime = 0;
			}
			break;
		}
		else if (srv->cstat[i].csid==csid) {
			srv->cstat[i].ecmnb++;
			if (ok) {
				srv->cstat[i].ecmok++;
				srv->cstat[i].ecmoktime += ecmoktime;
			}
			break;
		}
	}
}



int card_sharelimits(struct sharelimit_data sharelimits[100], uint16_t caid, uint32_t provid)
{
	int i;
	int uphops1 = 10; // for 0:0
	int uphops2 = 10; // for caid:0
	for (i=0; i<100; i++) {
		if (sharelimits[i].caid==0xffff) break;
		if (!sharelimits[i].caid) {
			if (!sharelimits[i].provid) uphops1 = sharelimits[i].uphops;
		}
		else if (sharelimits[i].caid==caid) {
			if (sharelimits[i].provid==provid) return sharelimits[i].uphops;
			else if (!sharelimits[i].provid) uphops2 = sharelimits[i].uphops;
		}
	}
	if (uphops2<uphops1) return uphops2; else return uphops1;// Max UPHOPS
}


void cardsids_add(struct cs_card_data *card, uint32_t prov, uint16_t sid,int val)
{
	if (!sid) return;
	struct sid_data *sidata = malloc( sizeof(struct sid_data) );
	memset( sidata, 0, sizeof(struct sid_data) );

	sidata->sid=sid;
	sidata->prov=prov;
	sidata->val=val;
	sidata->next = card->sids[sid>>8];
	card->sids[sid>>8] = sidata;
}


int cardsids_update(struct cs_card_data *card, uint32_t prov, uint16_t sid,int val)
{
	if (!sid) return 0;

	struct sid_data *sidata = card->sids[sid>>8];
	while (sidata) {
		if (sidata->sid==sid)
		if (sidata->prov==prov) {
			if ( (sidata->val<100) && (sidata->val>-100) ) {
				if (sidata->val>0) {
					if (val>0) sidata->val +=val;
					else sidata->val =0;
				}
				else if (sidata->val<0) {
					if (val<0) sidata->val +=val;
					else sidata->val=0;
				}
				else sidata->val +=val; // else a card that has decode success one time cannot return to decode failed
			}
			return 1;
		}
		sidata = sidata->next;
	}

	if ( !sidata && sid ) {
		cardsids_add( card, prov, sid,val);
	}
	return 1;
}


///////////////////////////////////////////////////////////////////////////////
// Common profile functions
///////////////////////////////////////////////////////////////////////////////

struct cardserver_data *getcsbycaidprov( uint16_t caid, uint32_t prov)
{
	int i;
	if (!caid) return NULL;
	struct cardserver_data *cs = cfg.cardserver;
	while (cs) {
		if (cs->card.caid==caid) {
			for(i=0; i<cs->card.nbprov;i++) if (cs->card.prov[i].id==prov) return cs;
			if ( ((cs->card.caid & 0xff00)==0x1800)
				|| ((cs->card.caid & 0xff00)==0x0900)
				|| ((cs->card.caid & 0xff00)==0x0b00) ) return cs;
		}
		cs = cs->next;
	}
	return NULL;
}


struct cardserver_data *getcsbyid(uint32_t id)
{
	if (!id) return NULL;
	struct cardserver_data *cs = cfg.cardserver;
	while (cs) {
		if (cs->id==id) return cs;
		cs = cs->next;
	}
	return NULL;
}


struct cardserver_data *getcsbyport(int port)
{
	struct cardserver_data *cs = cfg.cardserver;
	while (cs) {
		if (cs->newcamd.port==port) return cs;
		cs = cs->next;
	}
	return NULL;
}


struct cardserver_data *getcsbycaprovid(uint16_t caid, uint32_t provid)
{
	int j;
	struct cardserver_data *cs = cfg.cardserver;
	while (cs) {
		if (caid==cs->card.caid) {
			for (j=0; j<cs->card.nbprov;j++) if (provid==cs->card.prov[j].id) break;
			if (j<cs->card.nbprov) break;
		}
		cs = cs->next;
	}
	return cs;
}


void sid_newecm(ECM_DATA *ecm)
{
	if (!ecm) return;
	struct cardserver_data *cs = ecm->cs;
	if (!cs) return;
 
	if (cs->sidlist.data) {
		int i;
		struct sid_chid_ecmlen_data *sids = cs->sidlist.data;
		for(i=0;i<MAX_SIDS;i++,sids++) {
			if (!sids->sid) break;
			if ( (sids->sid==ecm->sid)&&(!sids->chid||(sids->chid==ecm->chid))&&(!sids->ecmlen||(sids->ecmlen==ecm->ecmlen)) ) {
				if (ecm->dcwstatus==STAT_DCW_SUCCESS) sids->ecmok++;
				sids->ecmnb++;
				break;
			}
		}
	}
}



struct sid_chid_ecmlen_data *sid_binarysearch( struct sid_chid_ecmlen_data *sids, int max, uint16_t sid )
{
	// Returns index of sid in sids, or -1 if not found
	int xl = 0;
	int xh = max - 1;
	//
	int yl = sids[xl].sid;
	int yh = sids[xh].sid;
	//
	int xm;
	while (yl <= sid && yh >= sid) {
		xm = (xl + xh)/2;
		int ym = sids[xm].sid;
		if (ym<sid) yl = sids[xl=xm+1].sid;
		else if (ym>sid) yh = sids[xh=xm-1].sid;
		else return &sids[xm];
	}
	if (sids[xl].sid == sid) return &sids[xl];
	return NULL; // Not found
}

int accept_sid(struct cardserver_data *cs, uint32_t provid, uint16_t sid, uint16_t chid, uint16_t ecmlen, uint8_t *cw1cycle )
{
	*cw1cycle = 0;
	if (cs->sidlist.data) {
		int accepted = 0;
		struct sid_chid_ecmlen_data *s = sid_binarysearch ( cs->sidlist.data, cs->sidlist.total, sid );
		if (s) {
			if ( (!s->chid||(s->chid==chid)) && (!s->ecmlen||(s->ecmlen==ecmlen)) ) {
				accepted = 1;
				*cw1cycle = s->cw1cycle;
			}
		}
		if (cs->sidlist.deny) return !accepted; else return accepted;
	}
	else {
		int i;
		for (i=0; i<cs->card.nbprov; i++) {
			if (provid==cs->card.prov[i].id) {
				if (cs->card.prov[i].sidlist.data) {
					int accepted = 0;
					struct sid_chid_ecmlen_data *s = sid_binarysearch ( cs->card.prov[i].sidlist.data, cs->card.prov[i].sidlist.total, sid );
					if (s) {
						if ( (!s->chid||(s->chid==chid)) && (!s->ecmlen||(s->ecmlen==ecmlen)) ) {
							accepted = 1;
							*cw1cycle = s->cw1cycle;
						}
					}
					if (cs->sidlist.deny) return !accepted; else return accepted;
 				}
				break;
			}
		}
	}

	if ( !sid && !cs->option.faccept0sid ) return 0;
	return 1;
}

///////////////////////////////////////////////////////////////////////////////
// Return
//  0: not accepted
//  1: accepted
int accept_sid0(struct cardserver_data *cs, uint16_t sid, uint16_t chid, uint16_t ecmlen, uint8_t *cw1cycle )
{
	*cw1cycle = 0;
	if (cs->sidlist.data) {
		int i;
		int accepted = 0;
		struct sid_chid_ecmlen_data *sids = cs->sidlist.data;
		for(i=0;i<MAX_SIDS;i++,sids++) {
			if (!sids->sid) {
				if (!sids->chid) {
					if (!sids->ecmlen) break; // end of sids
					else if (sids->ecmlen==ecmlen) {
						accepted = 1;
						*cw1cycle = sids->cw1cycle;
						break;
					}
				}
				else if ( (sids->chid==chid)&&(!sids->ecmlen||(sids->ecmlen==ecmlen)) ) {
					accepted = 1;
					*cw1cycle = sids->cw1cycle;
					break;
				}
			}
			else if ( (sids->sid==sid)&&(!sids->chid||(sids->chid==chid))&&(!sids->ecmlen||(sids->ecmlen==ecmlen)) ) {
				accepted = 1;
				*cw1cycle = sids->cw1cycle;
				break;
			}
		}
		if (cs->sidlist.deny) return !accepted; else return accepted;
	}
	else if ( !sid && !cs->option.faccept0sid ) return 0;
	return 1;
}

int accept_prov(struct cardserver_data *cs, uint32_t prov)
{
	int i;
	// Check for provid
	for (i=0; i<cs->card.nbprov;i++) if (prov==cs->card.prov[i].id) return 1; // found
	// not found, test provid==0
	if ( !prov && cs->option.faccept0provider ) return 1;
	return 0;
}

int accept_caid(struct cardserver_data *cs, uint16_t caid)
{
	// Check for caid, accept caid=0
	if (caid==cs->card.caid) return 1;
	if ( !caid && cs->option.faccept0caid ) return 1;
	return 0;
}

int accept_ecmlen(int ecmlen)
{
	if ( (ecmlen<20)||(ecmlen>MAX_ECM_SIZE) ) return 0;
	return 1;
}

int viaccess_checkECM( uint8_t *ecmdata, int ecmlen)
{
	int nanoea10 = 0;
	int nanof008 = 0;

	unsigned char *data = ecmdata+4;

	while ( data < (ecmdata+ecmlen) )
	{
		uint8_t nano = *data;
		int nanolen = *(data+1);
		if ( (nano==0xea)&&(nanolen==0x10) ) nanoea10 = 1;
		if ( (nano==0xf0)&&(nanolen==0x08) ) nanof008 = 1;
		////printf(" NANO: %02x LEN: %d\n", nano, nanolen);
		data += 2 + nanolen;
		if ( data > (ecmlen+ecmdata) ) return 0;
	}
	if (nanoea10 && nanof008) return 1;
	return 0;
}

int cs_check_ecmlen(struct cardserver_data *cs, int len)
{
	if (!cs->ecmlen[0]) return 1;
	int count;
	for (count=0; count<30; count++) {
		if (cs->ecmlen[count]==len) return 1;
		if (!cs->ecmlen[count]) break;
	}
	return 0;
}

char *cs_accept_ecm(struct cardserver_data *cs, uint16_t caid, uint32_t provid, uint16_t sid, uint16_t chid, uint16_t ecmlen, uint8_t *ecmdata, uint8_t *cw1cycle )
{
	//
	if (cs->option.checkecmlength) {
		int len = ((ecmdata[1]&0x0F)<<8) | ecmdata[2];
		if ( (len+3)!=ecmlen ) return("ECM length corrupted");
	}
	// ecmtag
	if ( (ecmdata[0]&0xFE)!=0x80 ) return("Invalid ECM tag");
	// check for ecm length
	if (!accept_ecmlen(ecmlen)) return("Invalid ECM length");
	// Check for caid
	if ( !accept_caid(cs,caid) ) return("Wrong caid");
	// Check for provid
	if ( !accept_prov(cs,provid) ) return("Wrong provider");
	// Check for sid
	if ( !accept_sid(cs, provid, sid, chid, ecmlen, cw1cycle) ) return("Channel denied");
	// check for length
	if ( !cs_check_ecmlen(cs, ecmlen) ) return("Wrong ecm length");
	// check for viaccess
	if (cs->option.checkecm) {
		if (caid==0x0500) if ( !viaccess_checkECM( ecmdata, ecmlen ) ) return("Invalid viaccess ecm");
	}
	return NULL;
}



///////////////////////////////////////////////////////////////////////////////
void ecm_setdcw( ECM_DATA *ecm, uint8_t dcw[16], int srctype, int srcid);
int pipe_send_cacheex_push_cache(struct cache_data *pcache, uint8_t *cw, uint8_t *nodeid);

#include "clustredcache.c"

#include "cli-common.c"
#include "cli-newcamd.c"
#ifdef CCCAM_CLI
#include "cli-cccam.c"
#endif


#if defined(CAMD35_SRV) || defined(CAMD35_CLI) || defined(CS378X_SRV) || defined(CS378X_CLI)
#include "crc32.c"
#include "msg-camd35.c"
#endif

#ifdef CAMD35_CLI
#include "cli-camd35.c"
#endif
#ifdef CS378X_CLI
#include "cli-cs378x.c"
#endif


struct connect_cli_data {
	void *server;
	int sock;
	uint32_t ip;
};
void forward_cs378x(ECM_DATA *ecm);


#include "srv-newcamd.c"
#ifdef MGCAMD_SRV
#include "srv-mgcamd.c"
#endif

#ifdef CCCAM_SRV
#include "srv-cccam.c"
#endif

#ifdef FREECCCAM_SRV
#include "srv-freecccam.c"
#endif

#ifdef RADEGAST_CLI
#include "cli-radegast.c"
#endif

#ifdef RADEGAST_SRV
#include "srv-radegast.c"
#endif

#ifdef CAMD35_SRV
#include "srv-camd35.c"
#endif

#ifdef CS378X_SRV
#include "srv-cs378x.c"
#endif

#ifdef CACHEEX
#include "cacheex.c"
#endif

#include "srv-common.c"

#include "th-srv.c"  // Servers Connnection
#include "th-dns.c"  // Dns Resolving
#include "th-ecm.c"  // Check/send ecm request to servers & Check/send dcw to clients
#ifndef WIN32 
#include "th-cfg.c"  // Reread Config
#endif
#ifdef EXPIREDATE
#include "th-date.c"
#endif

///////////////////////////////////////////////////////////////////////////////


char *src2string(int srctype, int srcid, char *ret)
{
	static char ss1[] = "server";
	static char ss2[] = "cache peer";
	static char ss3[] = "newcamd client";

	if (srctype==DCW_SOURCE_SERVER) {
		struct server_data *srv = getsrvbyid(srcid&0xFFFF);
		if (srv)
			sprintf( ret,"server (%s:%d)", srv->host->name, srv->port);
		else
			sprintf( ret,"Unknow server (id=%d)", srcid);
		return ss1;
	}
	else if (srctype==DCW_SOURCE_CACHE) {
		if (srcid&PEER_CSP) {
			struct cachepeer_data *peer = getpeerbyid(srcid&0xFFFF);
			if (peer)
				sprintf( ret,"cache peer (%s:%d)", peer->host->name, peer->port);
			else
				sprintf( ret,"Unknown cache peer (id=%d)", srcid);
			return ss2;
		}
#ifdef CACHEEX
		else if (srcid&PEER_CCCAM_CLIENT) {
			struct cc_client_data *cli = getcecccamclientbyid(srcid&0xFFFF);
			if (cli)
				sprintf( ret,"CacheEx CCcam client '%s'", cli->user);
			else
				sprintf( ret,"Unknown CacheEx CCcam client (id=%d)", srcid);
			return "CacheEx CCcam client";
		}

#ifdef CAMD35_SRV
		else if (srcid&PEER_CAMD35_CLIENT) {
			struct camd35_client_data *cli = getcamd35clientbyid(srcid&0xFFFF);
			if (cli)
				sprintf( ret,"CacheEx Camd35 client '%s'", cli->user);
			else
				sprintf( ret,"Unknown CacheEx Camd35 client (id=%d)", srcid);
			return "CacheEx Camd35 client";
		}
#endif

#ifdef CS378X_SRV
		else if (srcid&PEER_CS378X_CLIENT) {
			struct camd35_client_data *cli = getcs378xclientbyid(srcid&0xFFFF);
			if (cli)
				sprintf( ret,"CacheEx cs378x client '%s'", cli->user);
			else
				sprintf( ret,"Unknown CacheEx cs378x client (id=%d)", srcid);
			return "CacheEx cs378x client";
		}
#endif

		else if (srcid&PEER_CACHEEX_SERVER) {
			struct server_data *srv = getcesrvbyid(srcid&0xFFFF);
			if (srv)
				sprintf( ret,"CacheEx server (%s:%d)", srv->host->name, srv->port);
			else
				sprintf( ret,"Unknow CacheEx server (id=%d)", srcid);
			return "CacheEx Server";
		}
#endif
	}
#ifdef SRV_CSCACHE
	else if (srctype==DCW_SOURCE_CSCLIENT) {
		// srcid =  (csid<<16)|cliid;
		struct cardserver_data *cs = getcsbyid( srcid>>16 );
		if (cs) {
			struct cs_client_data *cli = getnewcamdclientbyid( srcid&0xffff );
			if (cli) {
				sprintf( ret,"newcamd client '%s'", cli->user);
				return ss3;
			}
		}
		sprintf( ret,"Unknown newcamd client (id=%x)", srcid);
		return ss3;
	}
	else if (srctype==DCW_SOURCE_MGCLIENT) {
		// srcid =  (csid<<16)|cliid;
		struct mg_client_data *cli = getmgcamdclientbyid( srcid );
		if (cli)
			sprintf( ret,"mgcamd client '%s'", cli->user);
		else
			sprintf( ret,"Unknown mgcamd client (id=%d)", srcid);
		return ss3;
	}
#endif
	else if (srctype==DCW_SOURCE_CCCLIENT) {
		struct cc_client_data *cli = getcccamclientbyid(srcid);
		if (cli)
			sprintf( ret,"CCcam client '%s'", cli->user);
		else
			sprintf( ret,"Unknown CCcam client (id=%d)", srcid);
		return "CCcam client";
	}

	else {
		sprintf( ret,"Unknown Source (%d/%d)", srctype, srcid);
	}
	return NULL;
}

///////////////////////////////////////////////////////////////////////////////

pthread_t cli_tid;

int checkthread;

unsigned int seed2;

uint8_t fastrnd2()
{
  unsigned int offset = 12923+(GetTickCount()&0xff);
  unsigned int multiplier = 4079+(GetTickCount()&0xff);
  seed2 = seed2 * multiplier + offset;
  return (uint8_t)(seed2 % 0xFF);
}


void mainprocess()
{
#ifndef WIN32
	gettimeofday( &startime, NULL );
	//if (startime.tv_sec>1380237152) exit(0);
	//printf(" %ld\n", startime.tv_sec + (24*3600*5) ); exit(0);
#endif
// INIT
	pthread_mutex_init(&prg.lock, NULL);
	pthread_mutex_init(&prg.lockecm, NULL);

	pthread_mutex_init(&prg.lockcli, NULL);
	pthread_mutex_init(&prg.locksrv, NULL);

#ifdef CCCAM_SRV
	pthread_mutex_init(&prg.locksrvcc, NULL); // CC Client connection
	pthread_mutex_init(&prg.lockcccli, NULL);
#endif
#ifdef FREECCCAM_SRV
	pthread_mutex_init(&prg.locksrvfreecc, NULL); // CC Client connection
	pthread_mutex_init(&prg.lockfreecccli, NULL);
#endif

#ifdef MGCAMD_SRV
	pthread_mutex_init(&prg.locksrvmg, NULL); // Client connection
	pthread_mutex_init(&prg.lockclimg, NULL);
#endif

#ifdef RADEGAST_SRV
	pthread_mutex_init(&prg.lockrdgdsrv, NULL); // Client connection
	pthread_mutex_init(&prg.lockrdgdcli, NULL);
#endif

	// Main Loops(THREADS)
	pthread_mutex_init(&prg.lockdnsth, NULL); // DNS lookup Thread

	pthread_mutex_init(&prg.locksrvth, NULL);	// Connection to cardservers
	pthread_mutex_init(&prg.lockmain, NULL); // Messages Recv

	pthread_mutex_init(&prg.locksrvcs, NULL); // CS Client connection
	pthread_mutex_init(&prg.lockhttp, NULL); // HTTP Server

	pthread_mutex_init(&prg.lockdns, NULL);

	pthread_mutex_init(&prg.lockdcw, NULL);

	pthread_mutex_init(&prg.lockcache, 0);


	pthread_mutex_init(&prg.lockthreaddate, NULL);

#ifdef CACHEEX
	pthread_mutex_init(&prg.lockcacheex, NULL);
#endif
	gettimeofday( &prg.exectime, NULL );

	memset(&trace, 0, sizeof(struct trace_data) );

	/* Create the pipe. */

	if ( pipe(prg.pipe.cache) < 0 ) { perror("pipe()"); exit(1); }
	SetSoketNonBlocking(prg.pipe.cache[0]);
	SetSoketNonBlocking(prg.pipe.cache[1]);

	if ( pipe(prg.pipe.ecm) < 0 ) { perror("pipe()"); exit(1); }
	SetSoketNonBlocking(prg.pipe.ecm[0]);
	SetSoketNonBlocking(prg.pipe.ecm[1]);

#ifdef CACHEEX
	if ( pipe(prg.pipe.cacheex) < 0 ) { perror("pipe()"); exit(1); }
	SetSoketNonBlocking(prg.pipe.cacheex[0]);
	SetSoketNonBlocking(prg.pipe.cacheex[1]);
#endif

	if ( pipe(prg.pipe.cs378x) < 0 ) { perror("pipe()"); exit(1); }
	SetSoketNonBlocking(prg.pipe.cs378x[0]);
	SetSoketNonBlocking(prg.pipe.cs378x[1]);
	if ( pipe(prg.pipe.cs378x_cex) < 0 ) { perror("pipe()"); exit(1); }
	SetSoketNonBlocking(prg.pipe.cs378x_cex[0]);
	SetSoketNonBlocking(prg.pipe.cs378x_cex[1]);

	if ( pipe(prg.pipe.cccam) < 0 ) { perror("pipe()"); exit(1); }
	SetSoketNonBlocking(prg.pipe.cccam[0]);
	SetSoketNonBlocking(prg.pipe.cccam[1]);

	if ( pipe(prg.pipe.mgcamd) < 0 ) { perror("pipe()"); exit(1); }
	SetSoketNonBlocking(prg.pipe.mgcamd[0]);
	SetSoketNonBlocking(prg.pipe.mgcamd[1]);

	if ( pipe(prg.pipe.newcamd) < 0 ) { perror("pipe()"); exit(1); }
	SetSoketNonBlocking(prg.pipe.newcamd[0]);
	SetSoketNonBlocking(prg.pipe.newcamd[1]);

	if ( pipe(prg.pipe.freecccam) < 0 ) { perror("pipe()"); exit(1); }
	SetSoketNonBlocking(prg.pipe.freecccam[0]);
	SetSoketNonBlocking(prg.pipe.freecccam[1]);

	if ( pipe(dcwpipe) < 0 ) { perror("pipe()"); exit(1); }
	SetSoketNonBlocking(dcwpipe[0]);
	SetSoketNonBlocking(dcwpipe[1]);

	if ( pipe(prg.pipe.con.cccam) < 0 ) { perror("pipe()"); exit(1); }
	SetSoketNonBlocking(prg.pipe.con.cccam[0]);
	SetSoketNonBlocking(prg.pipe.con.cccam[1]);

	if ( pipe(prg.pipe.con.mgcamd) < 0 ) { perror("pipe()"); exit(1); }
	SetSoketNonBlocking(prg.pipe.con.mgcamd[0]);
	SetSoketNonBlocking(prg.pipe.con.mgcamd[1]);

	// EPOLL
#ifdef EPOLL_CACHE
	prg.epoll.cache = epoll_create( MAX_EPOLL_EVENTS );
	epoll_add(prg.epoll.cache, prg.pipe.cache[0], NULL);
#endif

	//
	srand (time(NULL));

#ifdef CCCAM 
// NODE ID: 8675e141 217e6912
	prg.nodeid[0] = 'R';
	prg.nodeid[1] = '8';
	prg.nodeid[2] = '2';
	prg.nodeid[3] = 'N';
	prg.nodeid[4] = 0xff & fastrnd2();
	prg.nodeid[5] = 0xff & fastrnd2();
	prg.nodeid[6] = 0xff & fastrnd2();
	prg.nodeid[7] = 0xff & fastrnd2();
#endif

#ifndef WIN32
	start_thread_config();
#endif

	usleep(100000);

	init_ecmdata();

// THREADS - detached
	start_thread_dns();
	start_thread_srv();
	start_thread_recv_msg();
#ifdef EXPIREDATE
	start_thread_date();
#endif

#ifdef TELNET
	start_thread_telnet();
#endif

	start_thread_cache();

#ifdef CACHEEX
	start_thread_cacheex();
#endif

	sleep(3);

	pthread_t cli_tid;
#ifdef RADEGAST_SRV
	create_thread(&cli_tid, (threadfn)rdgd_connect_cli_thread, NULL); // Lock server
#endif

	start_thread_newcamd();

#ifdef MGCAMD_SRV
	start_thread_mgcamd();
#endif

#ifdef CCCAM_SRV
	start_thread_cccam();
#endif

#ifdef FREECCCAM_SRV
	start_thread_freecccam();
#endif

#ifdef CS378X_SRV
	start_thread_cs378x();
#endif

#ifdef CAMD35_SRV
	start_thread_camd35();
#endif

#ifdef MONOTHREAD_ACCEPT
	create_thread(&cli_tid, (threadfn)connect_cli_thread, NULL); // Lock server
#endif

	start_thread_http();

	while (!prg.restart) {
		sleep(5);
	}

}


#ifdef SIG_HANDLER

#include <execinfo.h>
#include <ucontext.h>

static void x64_sighandlerPrint(int signo, int code, ucontext_t *context, void *bt [], int bt_size)
{
	time_t ttime = time (NULL);

	FILE *fd;
	fd = fopen(debug_file, "at");
	if (!fd) {
		printf(" Error opening file\n");
		return;
	}
	fprintf(fd, "\n## %s", ctime (&ttime));
	fprintf(fd, "PID=%d\n", getpid ());
	fprintf(fd, "signo=%d/%s\n", signo, strsignal (signo));
	fprintf(fd, "code=%d (not always applicable)\n", code);
	fprintf(fd, "\nContext: 0x%08lx\n", (unsigned long) context);

	fprintf(fd,
		"R8= 0x%08lx\n"
		"R9= 0x%08lx\n"
		"R10= 0x%08lx\n"
		"R11= 0x%08lx\n"
		"R12= 0x%08lx\n"
		"R13= 0x%08lx\n"
		"R14= 0x%08lx\n"
		"R15= 0x%08lx\n"
		"RDI= 0x%08lx\n"
		"RSI= 0x%08lx\n"
		"RBP= 0x%08lx\n"
		"RBX= 0x%08lx\n"
		"RDX= 0x%08lx\n"
		"RAX= 0x%08lx\n"
		"RCX= 0x%08lx\n"
		"RSP= 0x%08lx\n"
		"RIP= 0x%08lx\n"
		"EFL= 0x%08lx\n"
		"CSGSFS= 0x%08lx\n"
		"ERR= 0x%08lx\n"
		"TRAPNO= 0x%08lx\n"
		"OLDMASK= 0x%08lx\n"
		"CR2= 0x%08lx\n",
		(uint64_t)context->uc_mcontext.gregs[REG_R8],
		(uint64_t)context->uc_mcontext.gregs[REG_R9],
		(uint64_t)context->uc_mcontext.gregs[REG_R10],
		(uint64_t)context->uc_mcontext.gregs[REG_R11],
		(uint64_t)context->uc_mcontext.gregs[REG_R12],
		(uint64_t)context->uc_mcontext.gregs[REG_R13],
		(uint64_t)context->uc_mcontext.gregs[REG_R14],
		(uint64_t)context->uc_mcontext.gregs[REG_R15],
		(uint64_t)context->uc_mcontext.gregs[REG_RDI],
		(uint64_t)context->uc_mcontext.gregs[REG_RSI],
		(uint64_t)context->uc_mcontext.gregs[REG_RBP],
		(uint64_t)context->uc_mcontext.gregs[REG_RBX],
		(uint64_t)context->uc_mcontext.gregs[REG_RDX],
		(uint64_t)context->uc_mcontext.gregs[REG_RAX],
		(uint64_t)context->uc_mcontext.gregs[REG_RCX],
		(uint64_t)context->uc_mcontext.gregs[REG_RSP],
		(uint64_t)context->uc_mcontext.gregs[REG_RIP],
		(uint64_t)context->uc_mcontext.gregs[REG_EFL],
		(uint64_t)context->uc_mcontext.gregs[REG_CSGSFS],
		(uint64_t)context->uc_mcontext.gregs[REG_ERR],
		(uint64_t)context->uc_mcontext.gregs[REG_TRAPNO],
		(uint64_t)context->uc_mcontext.gregs[REG_OLDMASK],
		(uint64_t)context->uc_mcontext.gregs[REG_CR2]
	);
	fprintf(fd, "\n%d elements in backtrace\n", bt_size);

	backtrace_symbols_fd (bt, bt_size, fileno (fd));

	fprintf(fd, "\n");
	fflush( fd );
	fclose(fd);
}

void sighandler(int signo, struct siginfo *si, void *ctx)
{
	void *bt[128];
	int bt_size;

	bt_size = backtrace (bt, sizeof(bt) );

	x64_sighandlerPrint (signo, si->si_code, (ucontext_t *) ctx, bt, bt_size);
	exit (1);
}

void install_handler (void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sigaction));
	sa.sa_sigaction = (void *)sighandler;
	sigemptyset (&sa.sa_mask);
	sa.sa_flags = SA_RESTART | SA_SIGINFO; //SA_ONESHOT
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGFPE, &sa, NULL);
	sigaction(SIGABRT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);

	sigaction(SIGILL, &sa, NULL);
	sigaction(SIGFPE, &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);
	sigaction(SIGSTOP, &sa, NULL);
	sigaction(SIGTSTP, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
}

#endif


//#include "iplock.c"

int main(int argc, char *argv[])
{
	int option_background = 0; // default
	int fork_return;
	char *args;
	int i,j;

/*
	printf(" cmp_cards = %p\n", &cmp_cards);
	printf(" cs_accept_ecm() = %p\n", &cs_accept_ecm);


	uint8_t *data_offset = (uint8_t *)&cmp_cards;
	uint32_t data_size = (uint32_t) ( ((void*)&cs_accept_ecm) - ((void*)&cmp_cards) );

	uint32_t datacrc = crc32(0L, data_offset, data_size);

	char str[101*3];
	array2hex( data_offset, str, 100);
	printf("%s\n(%d) %08x\n", str, data_size, datacrc);

	uint8_t pass[4] = { 1, 2, 3, 4 };
	message_decrypt( data_offset, data_size, pass );
	datacrc = crc32(0L, data_offset, data_size);
	array2hex( data_offset, str, 100);
	printf("%s\n(%d) %08x\n", str, data_size, datacrc);

	return 0;
*/

	char pg[] = "Multi CardServer r"REVISION_STR"-"GIT_COMMIT" based on the work by ";
	char evil[] = "evileyes";
	char email[] = " (http://www.infosat.org)\n";

	printf("%s", pg);

#ifdef SIG_HANDLER
	install_handler();
#endif

	printf("%s", evil );

	flag_debugscr = 0;
	flag_debugfile = 0;
#ifdef DEBUG_NETWORK
	flag_debugnet = 0;
#endif

	printf("%s", email );
	if (IP_ADRESS) printf("*Server IP: %s\n", ip2string(IP_ADRESS)); 
	// Extract filename
	char *p = argv[0];
	char *slash = p;
	char *dot = NULL;
	while (*p) {
		if (*p=='/') slash = p+1;
		else if (*p=='.') dot = p;
		p++;
	}
	char path[255];
	if (dot>slash) memcpy( path, slash, dot-slash); else strcpy(path, slash);

#ifdef WIN32
	// Set Config name
	sprintf( config_file, "%s.cfg", path);
//	sprintf( sid_file, "/var/etc/%s.sid", path);
//	sprintf( card_file, "/var/etc/%s.card", path);
	sprintf( debug_file, "%s.log", path);
	sprintf( sms_file, "%s.sms", path);
#else
	// Set Config name
	sprintf( config_file, "/var/etc/%s.cfg", path);
//	sprintf( sid_file, "/var/etc/%s.sid", path);
//	sprintf( card_file, "/var/etc/%s.card", path);
	sprintf( debug_file, "/var/tmp/%s.log", path);
	sprintf( sms_file, "/var/tmp/%s.sms", path);
	sprintf( ecm_file, "/var/tmp/%s.ecm", path);
#endif
	loglevel=LOGINFO; // Default initial loglevel

	// Parse Options
	for (i=1;i<argc;i++) {
		args = *(argv+i);
		if (args[0]=='-') {
			if (args[1]=='h') {
				printf("USAGE\n\tmultics [-b] [-v] [-f] [-n] [-C <configfile>]\n\
OPTIONS\n\
\t-b               run in background\n\
\t-C <configfile>  use <configfile> instead of default config file (/var/etc/multics.cfg)\n\
\t-f               write to log file (/var/tmp/multics.log)\n\
\t-n               print network packets\n\
\t-v               print on screen\n\
\t-h               this help message\n");
				return 0;
			}
			else if (args[1]=='C') {
				i++;
				if (i<argc) {
					args = *(argv+i);
					strcpy( config_file, args );
				}
			}
			else {
				for(j=1; j<strlen(args); j++) {
					if (args[j]=='b') option_background = 1;
					else if (args[j]=='v') flag_debugscr = 1;
#ifdef DEBUG_NETWORK
					else if (args[j]=='n') flag_debugnet = 1;
#endif
					else if (args[j]=='f') flag_debugfile = 1;
				}
			}
		}
	}

	if (option_background==1) {
		fork_return = fork();
		if( fork_return < 0) {
			mlogf(LOGCRITICAL,0," unable to create child process, exiting.\n");
			exit(-1);
		}
		if (fork_return>0) {
			//mlogf(LOGDEBUG,0," main process, exiting.\n");
			exit(0);
		}
		//else mainprocess();
	}

	prg.pid_main = getpid();

	prg.restart = 0;

	// check for load average
	while (1)
	{
		FILE *fp = fopen ("/proc/loadavg", "r");
		if (fp) {
			float avg;
			if ( fscanf(fp, "%f", &avg)>0 )
				if (avg<7) break;
			fclose(fp);
		} else break;
		sleep(3);
	}

	mainprocess();

	if (prg.restart==1) { // restart()
		mlogf(LOGINFO,0," Restarting...\n");
		//TODO:stop threads
		int fork_return;
		done_config(&cfg);
		fork_return = vfork();
		if ( fork_return < 0) {
			printf("unable to create child process, exiting.\n");
		}
		else if (fork_return==0) {
			fork_return = vfork();
			if (fork_return < 0) {
				printf("unable to create child process, exiting.\n");
			}
			else if (fork_return==0) {
				execvp( argv[0], argv );
				perror("execvp");
			}
			exit(0);
		}
		mlogf(LOGWARNING,0," Stopped.\n");
		exit(0);
	}
	return 0;
}

