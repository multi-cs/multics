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

#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <poll.h>

#endif

#include "debug.h"
#include "convert.h"
#include "tools.h"
#include "threads.h"
#include "dcw.h"
#include "ecmdata.h"

#ifdef CCCAM
#include "msg-cccam.h"
#endif

#include "config.h"
extern struct config_data cfg;

struct ecm_request *ecmdata = NULL;

int ecmindex = 0;


void init_ecmdata()
{
	ecmdata = NULL;
}

uint32_t hashCode( uint8_t *buf, int count)
{
	int h = 0;
	int i;
    for (i = 0; i < count; i++) h = 31*h + buf[i];
    return h;
}

inline uint8_t checkECMD5(uint8_t *ecmd5)
{
	int8_t i;
	for (i=0;i<16;i++)
		if (ecmd5[i]) return 1;
	return 0;
}

uint32_t ecm_getprovid( uint8_t *ecm, uint16_t caid )
{
	int32_t i, len, descriptor_length = 0;
	uint32_t provid = 0;

	switch(caid >> 8) {
		case 0x01: // seca
			provid = (ecm[3]<<8)|ecm[4];
			break;

		case 0x05:
			// viaccess
			i = (ecm[4] == 0xD2) ? ecm[5]+2 : 0;  // skip d2 nano
			if((ecm[5+i] == 3) && ((ecm[4+i] == 0x90) || (ecm[4+i] == 0x40)))
				provid = (ecm[i+6]<<16)|(ecm[i+7]<<8)|(ecm[i+8]&0xF0);

			i = (ecm[6] == 0xD2) ? ecm[7]+2 : 0;  // skip d2 nano long ecm
			if((ecm[7+i] == 7) && ((ecm[6+i] == 0x90) || (ecm[6+i] == 0x40)))
				provid = (ecm[i+8]<<16)|(ecm[i+9]<<8)|(ecm[i+10]&0xF0);
			break;

		case 0x0D:
			// cryptoworks
			len = (((ecm[1] & 0xf) << 8) | ecm[2])+3;
			for(i=8; i<len; i+=descriptor_length+2) {
				descriptor_length = ecm[i+1];
				if (ecm[i] == 0x83) {
					provid = (uint32_t)ecm[i+2] & 0xFE;
					break;
				}
			}
			break;
	}
	return(provid);
}

uint16_t ecm_getchid( uint8_t *ecm, uint16_t caid )
{
	if ( (caid>>8)==0x06 )	return (ecm[6]<<8)|ecm[7];
	return 0;
}

int ecm_isnanoe0( uint8_t *ecm, uint16_t caid )
{
        int32_t i;

        switch(caid >> 8) {
                case 0x05: 
                        // viaccess
			i=6;
                        if (ecm[i] == 0xD2) // skip d2 nano 
			{
				i += ecm[i+1]+2;
			}
			if((ecm[i] == 0x90 || ecm[i] == 0x40) && (ecm[i+1] == 0x03 || ecm[i+1] == 0x07)) // skip next nano
			{
				i += ecm[i+1]+2;
			}
			if(ecm[i] == 0xDE && ecm[i+1] == 0x04)
			{
				i += 6;
			}
			// E0 (seen so far in logs: E0020002 or E0022002, but not in all cases delivers invalid cw so just detect!)
                        if(ecm[i] == 0xE0 && ecm[i+1] == 0x02)
			{
				return 1;
			}
			break;

		default:
			return 0;
        }
	return 0;
}


///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

void cs_addecmdata(struct cardserver_data *cs, struct ecm_request *new )
{
	if (!cs->ecmdata) {
		new->csnext = NULL;
		new->csprev = NULL;
		cs->ecmdata = new;
	}
	else if (!cs->ecmdata->csnext) {
		cs->ecmdata->csnext = new;
		cs->ecmdata->csprev = new;
		new->csnext = cs->ecmdata;
		new->csprev = cs->ecmdata;
		cs->ecmdata = new;
	}
	else {
		struct ecm_request *prev = cs->ecmdata->csprev;
		struct ecm_request *next = cs->ecmdata;
		new->csnext = next;
		new->csprev = prev;
		prev->csnext = new;
		next->csprev = new;
		cs->ecmdata = new;
	}
	cs->totalecm++;
	//mlogf(LOGDEBUG,0," [%s] new ecmdata %p size = %d\n", cs->name, cs->ecmdata, cs->totalecm);
}

void cs_delecmdata(struct cardserver_data *cs, struct ecm_request *old )
{
	if (!cs->ecmdata) {
		old->csprev = NULL;
		old->csnext = NULL;
		return;
	}
	if (cs->ecmdata==old) {
		// move to next
		if (!cs->ecmdata->csnext) {
			cs->ecmdata = NULL;
		}
		else {
			cs->ecmdata = old->csnext;
			if (old->csnext==old->csprev) { // only 2 ecmdata
				cs->ecmdata->csnext = NULL;
				cs->ecmdata->csprev = NULL;
			}
			else {
				old->csprev->csnext = old->csnext;
				old->csnext->csprev = old->csprev;
			}
		}
	}
	else if (old->csnext==old->csprev) {
		cs->ecmdata->csnext = NULL;
		cs->ecmdata->csprev = NULL;
	}
	else {
		old->csprev->csnext = old->csnext;
		old->csnext->csprev = old->csprev;
	}

	old->csprev = NULL;
	old->csnext = NULL;
	cs->totalecm--;
}


///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

int totalecm = 0;

struct ecm_request *store_ecmdata(struct cardserver_data *cs,uint8_t *ecm,int ecmlen, unsigned short sid, unsigned short caid, unsigned int provid)
{
	struct ecm_request *new;
	uint32_t ticks = GetTickCount();
	// add new or use dead data
	if (!ecmdata) {
		// nothing so add new
		//mlogf(LOGDEBUG,0," first ecmdata\n");
		totalecm++;
		new = malloc( sizeof(struct ecm_request) );
		memset( new, 0,  sizeof(struct ecm_request) );
		new->next = NULL;
		new->prev = NULL;
		ecmdata = new; // it becomes the current one
	}
	else if (!ecmdata->next) {
		//mlogf(LOGDEBUG,0," second ecmdata\n");
		totalecm++;
		new = malloc( sizeof(struct ecm_request) );
		memset( new, 0,  sizeof(struct ecm_request) );

		new->prev = ecmdata;
		new->next = ecmdata;

		ecmdata->prev = new;
		ecmdata->next = new;

		ecmdata = new; // it becomes the current one
	}
	else {
		new = ecmdata->prev;
		if ( (new->recvtime+TIME_ECMALIVE*2) < ticks ) {
			cs_delecmdata(new->cs, new);
			// cache is dead, add data to this one without allocating new data
			struct ecm_request *tmp = new->prev; // store previous
			memset( new, 0,  sizeof(struct ecm_request) );
			new->prev = tmp;
			new->next = ecmdata;
			ecmdata = new; // it becomes the current one			
		}
		else { // allocate new data
			totalecm++;
			//mlogf(LOGDEBUG,0," new ecmdata size = %d\n", totalecm);
			new = malloc( sizeof(struct ecm_request) );
			memset( new, 0,  sizeof(struct ecm_request) );
			new->prev = ecmdata->prev;
			new->next = ecmdata;
			//
			new->prev->next = new;
			//
			ecmdata->prev = new;
			//
			ecmdata = new; // it becomes the current one			
		}
	}
	cs_addecmdata(cs, new);
	//
	memcpy( new->ecm, ecm, ecmlen);
	new->cs = cs;
	new->chid = ecm_getchid(ecm, caid);
	new->ecmlen = ecmlen;
	new->recvtime = ticks;
	new->lastrecvtime = ticks;
	new->hash = hashCode(ecm+3, ecmlen-3);
#ifdef CACHEEX
	int32_t offset = 3;
	if ( (caid>>8)==0x17 ) offset = 13;
	MD5( ecm+offset, ecmlen-offset, new->ecmd5);
#endif
	new->dcwstatus = STAT_DCW_WAIT;
	new->sid = sid;
	new->caid = caid;
	new->provid = provid;
//	new->id = ecmindex;
	memset( &new->server, 0, sizeof(new->server) );
	new->waitcache = 0;
	new->cachestatus = 0; //ECM_CACHE_NONE;
	//new->dcwsrvtype = DCW_SOURCE_NONE;

	new->period = 1; // First try

#ifdef CHECK_NEXTDCW
	//checkfreeze_storeECM(new);
#endif
	return new;
}

////////////////////////////////////////////////////////////////////////////////
// SEARCH FUNCTIONS
////////////////////////////////////////////////////////////////////////////////

struct ecm_request *search_ecmdata_dcw( uint8_t *ecm, int ecmlen, unsigned short sid)
{
	uint32_t ticks = GetTickCount();
	uint32_t hash =  hashCode(ecm+3, ecmlen-3);
	struct ecm_request *req = ecmdata;
	while (req) {
		if ( (req->recvtime+TIME_ECMALIVE) < ticks ) return NULL;
		if (req->dcwstatus!=STAT_DCW_FAILED)
		if (hash==req->hash)
		if (ecm[0]==req->ecm[0])
		if (ecmlen==req->ecmlen)
		if (sid==req->sid)
		if ( !memcmp(ecm+3, req->ecm+3, ecmlen-3) ) return req;
		req = req->next;
		if (req==ecmdata) break;
	}
	return NULL;
}


struct ecm_request *search_ecmdata_any(struct cardserver_data *cs, uint8_t *ecm, int ecmlen, unsigned short sid, unsigned short caid)
{
	uint32_t hash =  hashCode(ecm+3, ecmlen-3);
	uint32_t ticks = GetTickCount();
	struct ecm_request *req = cs->ecmdata;
	while (req) {
		if ( (req->recvtime+TIME_ECMALIVE) < ticks ) return NULL;

		if (hash==req->hash)
		if (ecmlen==req->ecmlen)
		if (sid==req->sid)
		if (caid==req->caid)
		if ( !memcmp(ecm, req->ecm, ecmlen) ) return req;

		req = req->csnext;
		if (req==cs->ecmdata) break;
	}
	return NULL;
}


struct ecm_request *search_ecmdata_byhash( uint16_t caid, uint16_t sid,uint32_t hash )
{
	uint32_t ticks = GetTickCount();
	struct ecm_request *req = ecmdata;
	while (req) {
		if ( (req->recvtime+TIME_ECMALIVE) < ticks ) return NULL;

		if (hash==req->hash)
		if (caid==req->caid)
		if (sid==req->sid) return req;

		req = req->next;
		if (req==ecmdata) break;
	}
	return NULL;
}

#ifdef CACHEEX
struct ecm_request *search_ecmdata_byecmd5( uint16_t caid, uint32_t provid, uint8_t ecmd5[16] )
{
	uint32_t ticks = GetTickCount();
	struct ecm_request *req = ecmdata;
	while (req) {
		if ( (req->recvtime+TIME_ECMALIVE) < ticks ) return NULL;

		if (caid==req->caid)
		if (provid==req->provid)
		if ( !memcmp(ecmd5, req->ecmd5, 16) ) return req;

		req = req->next;
		if (req==ecmdata) break;
	}
	return NULL;
}
#endif

///////////////////////////////////////////////////////////////////////////////
//
///////////////////////////////////////////////////////////////////////////////

int ecmdata_check_cw( uint8_t tag, uint32_t hash, unsigned short caid, unsigned int provid , unsigned short sid, uint8_t cw[16], int cwpart )
{
	struct ecm_request *req = ecmdata;
	while (req) {

		if (req->dcwstatus==STAT_DCW_SUCCESS)
		if (hash!=req->hash)
		if (provid==req->provid)
		if (caid==req->caid)
		if (sid==req->sid) {
			switch (cwpart) {
				case 0:
					if ( dcwcmp8(req->cw,cw) ) return 0;
					if ( dcwcmp8(req->cw+8,cw) ) return 0;
					break;
				case 1:
					if ( dcwcmp8(req->cw,cw+8) ) return 0;
					if ( dcwcmp8(req->cw+8,cw+8) ) return 0;
					break;
				case 2:
					if ( dcwcmp16(req->cw,cw) ) return 0;
					break;
			}
		}

		req = req->next;
		if (req==ecmdata) break;
	}
	return 1;
}


////////////////////////////////////////////////////////////////////////////////
// IP FUNCTIONS
////////////////////////////////////////////////////////////////////////////////

// Client IP
void ecm_addip( ECM_DATA *ecm, unsigned int ip)
{
	register int i;
	for(i=0; i<20; i++) {
		if (!ecm->iplist[i]) {
			ecm->iplist[i] = ip;
			return;
		}
		if (ecm->iplist[i]==ip) return;
	}
}

int ecm_checkip(ECM_DATA *ecm, unsigned int ip)
{
	register int i;
	for(i=0; i<20; i++) {
		if (!ecm->iplist[i]) return FALSE;
		if (ecm->iplist[i]==ip) return TRUE; // found
	}
	return FALSE;
}

//SRV IP
void ecm_addsrvip(ECM_DATA *ecm, unsigned int ip)
{
	register int i;
	for(i=0; i<20; i++) {
		if (!ecm->srviplist[i]) {
			ecm->srviplist[i] = ip;
			return;
		}
		if (ecm->srviplist[i]==ip) return;
	}
}

int ecm_checksrvip(ECM_DATA *ecm, unsigned int ip)
{
	register int i;
	for(i=0; i<20; i++) {
		if (!ecm->srviplist[i]) return FALSE;
		if (ecm->srviplist[i]==ip) return TRUE; // found
	}
	return FALSE;
}

////////////////////////////////////////////////////////////////////////////////
// SERVER FUNCTIONS
////////////////////////////////////////////////////////////////////////////////

int ecm_nbservers(ECM_DATA *ecm)
{
	int i;
	int count=0;
	for(i=0; i<20; i++) {
		if (ecm->server[i].srvid) {
			count++;
		} else break;
	}
	return count;
}

int ecm_nbsentsrv(ECM_DATA *ecm)
{
	int i;
	int count=0;
	for(i=0; i<20; i++) {
		if (ecm->server[i].srvid) {
			if (ecm->server[i].flag!=ECM_SRV_EXCLUDE) count++;
		} else break;
	}
	return count;
}

int ecm_nbwaitsrv(ECM_DATA *ecm)
{
	int i;
	int count=0;
	for(i=0; i<20; i++) {
		if (ecm->server[i].srvid) {
			if (ecm->server[i].flag==ECM_SRV_REQUEST) count++;
		} else break;
	}
	return count;
}

int ecm_addsrv(ECM_DATA *ecm, unsigned int srvid)
{
	int i;
	uint32_t ticks = GetTickCount();
	for(i=0; i<20; i++) {
		if (!ecm->server[i].srvid) {
			ecm->server[i].srvid = srvid;
			ecm->server[i].flag = ECM_SRV_REQUEST;
			ecm->server[i].sendtime = ticks;
			ecm->server[i].statustime = ticks; // last changed status time
			ecm->server_totalsent = ecm_nbsentsrv(ecm);
			ecm->server_totalwait = ecm_nbwaitsrv(ecm);
			return 1;
		}
	}
	return 0;
}

int ecm_setsrvflag(ECM_DATA *ecm, unsigned int srvid, int flag)
{
	int i;
	for(i=0; i<20; i++) {
		if (ecm->server[i].srvid) {
			if (ecm->server[i].srvid==srvid) {
				ecm->server[i].flag=flag;
				ecm->server[i].statustime = GetTickCount();
				ecm->server_totalsent = ecm_nbsentsrv(ecm);
				ecm->server_totalwait = ecm_nbwaitsrv(ecm);
				return 1;
			}
		} else break;
	}
	return 0;
}

int ecm_setsrvflagdcw(ECM_DATA *ecm, unsigned int srvid, int flag, uint8_t dcw[16])
{
	int i;
	for(i=0; i<20; i++) {
		if (ecm->server[i].srvid) {
			if (ecm->server[i].srvid==srvid) {
				ecm->server[i].flag=flag;
				ecm->server[i].statustime = GetTickCount();
				memcpy(ecm->server[i].dcw, dcw, 16);
				ecm->server_totalsent = ecm_nbsentsrv(ecm);
				ecm->server_totalwait = ecm_nbwaitsrv(ecm);
				return 1;
			}
		} else break;
	}
	return 0;
}

int ecm_getsrvflag(ECM_DATA *ecm, unsigned int srvid)
{
	int i;
	for(i=0; i<20; i++) {
		if (ecm->server[i].srvid) {
			if (ecm->server[i].srvid==srvid) {
				return ecm->server[i].flag;
			}
		} else break;
	}
	return 0;
}


///////////////////////////////////////////////////////////////////////////////
// DCW CHECK
///////////////////////////////////////////////////////////////////////////////

#ifdef CHECK_NEXTDCW

// Get Last DCW for the same Channel
void checkfreeze_storeECM(ECM_DATA *ecm)
{
	struct ecm_request *xecm = NULL;

	// find after storing ecm
	if (!ecm) return;

	if ( (!ecm->lastdecode.ecm)&&(ecm->dcwstatus!=STAT_DCW_SUCCESS) ) {
		//mlogf(LOGDEBUG,0," \n[SROTE ECM] New (%04x:%06x:%04x/%08x)\n",ecm->caid, ecm->provid, ecm->sid, ecm->hash);

		uint32_t ticks = GetTickCount();
		struct ecm_request *oldecm = ecm->csnext;
		while (oldecm) {
			if ( (oldecm->recvtime+TIME_ECMALIVE*2) < ticks ) break;

			if ( (oldecm->ecmlen==ecm->ecmlen)&&(oldecm->caid==ecm->caid)&&(oldecm->provid==ecm->provid)&&(oldecm->sid==ecm->sid) ) {

				if ( (oldecm->dcwstatus==STAT_DCW_SUCCESS)&&(oldecm->hash!=ecm->hash)&&(oldecm->ecm[0]!=ecm->ecm[0]) ) {
					//ecm->lastdecode.request = oldecm;
					if ( (oldecm->lastdecode.ecm)&&(oldecm->lastdecode.counter>1) ) {
						if ((ecm->recvtime-oldecm->recvtime)<(oldecm->lastdecode.dcwchangetime*3/2)) xecm = oldecm;
						break;
					}
					else if (!xecm) xecm = oldecm;
				}

				else if ( (oldecm->dcwstatus==STAT_DCW_FAILED)&&(oldecm->hash==ecm->hash)&& !memcmp(oldecm->ecm+3, ecm->ecm+3, ecm->ecmlen-3) ) { // the same channel but we have freeze
					memcpy( &ecm->lastdecode, &oldecm->lastdecode, sizeof(ecm->lastdecode) );
					return; // copy and exit
					//mlogf(LOGDEBUG,0," Updating Cycles data after freeze ch %04x:%06x:%04x:%08x (%d)\n",ecm->caid, ecm->provid, ecm->sid, ecm->hash, ecm->lastdecode.counter);
				}

			}
			oldecm = oldecm->csnext;
			if (oldecm==ecm) break;
		}


		if (xecm) {
			ecm->lastdecode.ecm = xecm; // status -> last ecm
			ecm->lastdecode.counter = xecm->lastdecode.counter;
			ecm->lastdecode.dcwchangetime = (xecm->lastdecode.dcwchangetime*xecm->lastdecode.counter+(ecm->recvtime-xecm->recvtime)) / (xecm->lastdecode.counter+1);
			ecm->lastdecode.dcwchangetime = ((ecm->lastdecode.dcwchangetime+500)/1000)*1000;
			memcpy( ecm->lastdecode.dcw, xecm->lastdecode.dcw, 16); // Store latest DCW
#ifdef TESTCHANNEL
			int testchannel = ( (ecm->caid==cfg.testchn.caid) && (ecm->provid==cfg.testchn.provid) && (ecm->sid==cfg.testchn.sid) );
			if (testchannel) {
				char dump[64];
				array2hex( xecm->cw, dump, 16);
				mlogf(LOGINFO,0," Update Cycle ch %04x:%06x:%04x %02x:%08x ( %02x:%08x %s/%d)\n",ecm->caid, ecm->provid, ecm->sid, ecm->ecm[0],ecm->hash,
					xecm->ecm[0], xecm->hash, dump, ecm->lastdecode.counter);
			}
#endif
		}

	}
}

void checkfreeze_checkECM( ECM_DATA *ecm, ECM_DATA *oldecm )
{
	if (!ecm) return;
	if (!oldecm) return;
	if (ecm->lastdecode.ecm==oldecm) return;

	if ( (ecm->recvtime-oldecm->recvtime) > TIME_ECMALIVE*2) return;

	if ( (oldecm->ecmlen==ecm->ecmlen) && (oldecm->caid==ecm->caid) && (oldecm->provid==ecm->provid) && (oldecm->sid==ecm->sid) ) {

		if ( (oldecm->dcwstatus==STAT_DCW_SUCCESS) && (oldecm->ecm[0]!=ecm->ecm[0]) && (oldecm->hash!=ecm->hash) ) {
			if ( (oldecm->lastdecode.ecm)&&(oldecm->lastdecode.counter>1) ) {
				if ((ecm->recvtime-oldecm->recvtime)<(oldecm->lastdecode.dcwchangetime*2)) {
					// Setup Cw Cycle
					if (oldecm->lastdecode.cwcycle=='0') ecm->lastdecode.cwcycle = '1';
					else if (oldecm->lastdecode.cwcycle=='1') ecm->lastdecode.cwcycle = '0';
					else return;
					// check for cw1cycle
					if (ecm->cw1cycle==0x80) { // cw1 cycle on tag=0x80
						if ( (ecm->ecm[0]==0x80)&&(ecm->lastdecode.cwcycle!='1') ) return;
						if ( (ecm->ecm[0]==0x81)&&(ecm->lastdecode.cwcycle!='0') ) return;
					}
					else if (ecm->cw1cycle==0x81) { // cw1 cycle on tag=0x81
						if ( (ecm->ecm[0]==0x81)&&(ecm->lastdecode.cwcycle!='1') ) return;
						if ( (ecm->ecm[0]==0x80)&&(ecm->lastdecode.cwcycle!='0') ) return;
					}
					//
					ecm->lastdecode.ecm = oldecm;
					ecm->lastdecode.counter = oldecm->lastdecode.counter;
					// get average of ecm change time
					ecm->lastdecode.dcwchangetime = (oldecm->lastdecode.dcwchangetime*oldecm->lastdecode.counter+(ecm->recvtime-oldecm->recvtime)) / (oldecm->lastdecode.counter+1);
					ecm->lastdecode.dcwchangetime = ((ecm->lastdecode.dcwchangetime+300)/1000)*1000;
					memcpy( ecm->lastdecode.dcw, oldecm->cw, 16); // Store latest DCW
				}
			}
			else { //if (!ecm->lastdecode.ecm) {
				// maybe??
				ecm->lastdecode.ecm = oldecm;
				ecm->lastdecode.counter = oldecm->lastdecode.counter;
				ecm->lastdecode.dcwchangetime = ecm->recvtime-oldecm->recvtime;
				memcpy( ecm->lastdecode.dcw, oldecm->cw, 16); // Store latest DCW
			}
#ifdef TESTCHANNEL
			int testchannel = ( (ecm->caid==cfg.testchn.caid) && (ecm->provid==cfg.testchn.provid) && (ecm->sid==cfg.testchn.sid) );
			if (testchannel) {
				char dump[64];
				array2hex( oldecm->cw, dump, 16);
				mlogf(LOGINFO,0," Update Cycle ch %04x:%06x:%04x %02x:%08x ( %02x:%08x %s/%d)\n",ecm->caid, ecm->provid, ecm->sid, ecm->ecm[0],ecm->hash,
					oldecm->ecm[0], oldecm->hash, dump, ecm->lastdecode.counter);
			}
#endif
		}
		else if ( (oldecm->dcwstatus==STAT_DCW_FAILED) && (oldecm->hash==ecm->hash) && (oldecm->ecm[0]==ecm->ecm[0]) && !memcmp(oldecm->ecm+3, ecm->ecm+3, ecm->ecmlen-3) ){ // the same channel but we have freeze
			memcpy( &ecm->lastdecode, &oldecm->lastdecode, sizeof(ecm->lastdecode) );
#ifdef TESTCHANNEL
			int testchannel = ( (ecm->caid==cfg.testchn.caid) && (ecm->provid==cfg.testchn.provid) && (ecm->sid==cfg.testchn.sid) );
			if (testchannel) {
				char dump[64];
				array2hex( oldecm->cw, dump, 16);
				mlogf(LOGINFO,0," Update Cycle after freeze ch %04x:%06x:%04x:%08x (%s/%d)\n",ecm->caid, ecm->provid, ecm->sid, ecm->hash, dump, ecm->lastdecode.counter);
			}
#endif
		}
	}
}


// 1: success
// 2: inc
// 4: cwcycle
// return 0:wrong dcw, 1: good dcw
int checkfreeze_setdcw( ECM_DATA *ecm, uint8_t dcw[16] )
{
	char nullcw[8] = "\0\0\0\0\0\0\0\0";

	if (!ecm) return 0;

	if (!ecm->lastdecode.ecm) return 1; // no old successful decode, random select

	if ( dcwcmp16(dcw,ecm->lastdecode.dcw) ) return 0;

	if ( dcwcmp8(dcw,nullcw) || dcwcmp8(dcw+8,nullcw) ) return 0; // HALFNULLED --> cannot check for freeze

	if ( ecm->cw1cycle ) {
		if ( dcwcmp8(dcw,ecm->lastdecode.dcw) && !dcwcmp8(dcw+8,ecm->lastdecode.dcw+8) && (ecm->cw1cycle==ecm->ecm[0]) ) return 7;
		else if ( !dcwcmp8(dcw,ecm->lastdecode.dcw) && dcwcmp8(dcw+8,ecm->lastdecode.dcw+8) && (ecm->cw1cycle!=ecm->ecm[0]) ) return 3;
		else if (ecm->lastdecode.counter>0) return 0;
		else return 1;
	}

	else if ( ecm->lastdecode.cwcycle ) {
		if ( dcwcmp8(dcw,ecm->lastdecode.dcw) && !dcwcmp8(dcw+8,ecm->lastdecode.dcw+8) && (ecm->lastdecode.cwcycle=='1') ) return 7;
		else if ( !dcwcmp8(dcw,ecm->lastdecode.dcw) && dcwcmp8(dcw+8,ecm->lastdecode.dcw+8) && (ecm->lastdecode.cwcycle=='0') ) return 3;
		else if (ecm->lastdecode.counter>0) return 0;
		else return 1;
	}

	else {
		if ( dcwcmp8(dcw,ecm->lastdecode.dcw) && !dcwcmp8(dcw+8,ecm->lastdecode.dcw+8) ) return 7;
		else if ( !dcwcmp8(dcw,ecm->lastdecode.dcw) && dcwcmp8(dcw+8,ecm->lastdecode.dcw+8) ) return 3;
		else return 1;
	}

	return 0;
}


#endif

