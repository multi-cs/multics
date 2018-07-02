#include "common.h"

#include <stdio.h>
#include <stdlib.h>
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

#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <poll.h>

#endif

#include "common.h"
#include "convert.h"
#include "tools.h"
#include "debug.h"
#include "ecmdata.h"
#include "sockets.h"


#ifdef CCCAM
#include "msg-cccam.h"
#endif

#include "parser.h"
#include "config.h"
#include "main.h"

#define MAX_MIMES  20

struct {
	char ext[5];
	char mime[32];
} mimes[MAX_MIMES] = {
	{ "bin", "application/octet-stream" }, // default
	{ "txt", "text/plain" },
	{ "cfg", "text/plain" },
	{ "html", "text/html" },
	{ "htm", "text/html" },
	{ "pdf", "application/pdf" },
	{ "gif", "image/gif" },
	{ "jpg", "image/jpeg" },
	{ "jpeg", "image/jpeg" },
	{ "bmp", "image/bmp" },
	{ "png" , "image/png" },
	{ "tiff", "image/tiff" },
	{ "tif", "image/tiff" },
	{ "zip", "application/zip" },
	{ "rar", "application/x-rar-compressed" },
	{ "gz", "application/x-compressed" },
	{ "tgz", "application/x-compressed" },
	{ "bz2", "application/x-rar-compressed" },
	{ "z", "application/x-compress" },
	{ "tar", "application/x-tar" },
};


void sid_arrange( struct sid_chid_ecmlen_data *sids, int max )
{
	int i,j;
	struct sid_chid_ecmlen_data tmp;
	for(i=0; i<(max-1); i++)
		for(j=i+1; j<max; j++)
			if (sids[i].sid>sids[j].sid) {
				memcpy( &tmp, &sids[i], sizeof(struct sid_chid_ecmlen_data) );
				memcpy( &sids[i], &sids[j], sizeof(struct sid_chid_ecmlen_data) );
				memcpy( &sids[j], &tmp, sizeof(struct sid_chid_ecmlen_data) );
			}
}

///////////////////////////////////////////////////////////////////////////////
// HOST LIST
///////////////////////////////////////////////////////////////////////////////
void *dns_child_thread(struct host_data *host);

struct host_data *add_host( struct config_data *cfg, char *hostname)
{
	struct host_data *host = cfg->host;
	// Search
	while (host) {
		if ( !strcmp(host->name, hostname) ) return host;
		host = host->next;
	}
	// Create
	host = malloc( sizeof(struct host_data) );
	memset( host, 0, sizeof(struct host_data) );
	strcpy( host->name, hostname );
	host->ip = 0;
	host->checkiptime = 0;
	host->next = cfg->host;
	cfg->host = host;
	//dns_child_thread( host );
	return host;
}

void free_allhosts( struct config_data *cfg )
{
	while (cfg->host) {
		struct host_data *host = cfg->host;
		cfg->host = host->next;
		free(host);
	}
}

#if defined(CAMD35_SRV) || defined(CAMD35_CLI)
void camd35_init_data( char *user, char *pass, AES_KEY *encryptkey, AES_KEY *decryptkey, uint32_t *ucrc);
#endif

///////////////////////////////////////////////////////////////////////////////
// READ CONFIG
///////////////////////////////////////////////////////////////////////////////

// Default Newcamd DES key 
int cc_build[] = { 2892, 2971, 3094, 3165, 3367, 0 };

uint8_t defdeskey[14] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14 };

char *cc_version[] = { "2.0.11", "2.1.1", "2.1.2", "2.1.3", "2.3.0", "" };

char currentline[10240];

void init_cccamserver(struct cccam_server_data *cccam)
{
	memset( cccam, 0, sizeof(struct cccam_server_data) );
#ifdef CCCAM_SRV
	cccam->client = NULL;
	cccam->handle = -1;
	cccam->port = 0;
#endif
}

void init_mgcamdserver(struct mgcamdserver_data *mgcamd)
{
	memset( mgcamd, 0, sizeof(struct mgcamdserver_data) );
	mgcamd->client = NULL;
	mgcamd->handle = -1;
	mgcamd->port = 0;
	memcpy( mgcamd->key, defdeskey, 14);
}

void init_cacheserver(struct cacheserver_data *cache)
{
	memset( cache, 0, sizeof(struct cacheserver_data) );
	cache->peer = NULL;
	cache->handle = -1;
	cache->port = 0;
}

void init_config(struct config_data *cfg)
{
	// Init config data
	memset( cfg, 0, sizeof(struct config_data) );

	cfg->delay.thread = 19000;
	cfg->delay.connect = 100;

	cfg->clientid = 1;
	cfg->serverid = 1;
	cfg->cardserverid = 0x64; // Start like in CCcam 

	cfg->newcamd.clientid = 0;
	cfg->newcamd.dcwcheck = 1;

#ifdef HTTP_SRV
	cfg->http.port = 5500;
	cfg->http.handle = -1;
	cfg->http.autorefresh = 0;
	strcpy(cfg->http.title, "Multi CardServer");
#endif

	// CACHE
	cfg->cache.peerid = 1;
	cfg->cache.serverid = 1;
	cfg->cache.server = NULL;
	cfg->cache.faccept0onid = 1;
	cfg->cache.alivetime = 45000;
	cfg->cache.filter = 1;
	cfg->cache.filtertime = 0;
	cfg->cache.threshold = 1;
/*
	cfg->cache.port = 0;
	cfg->cache.hits = 0;
	cfg->cache.handle = 0;
*/

	memcpy(cfg->nodeid, prg.nodeid, 8);

#ifdef CCCAM
	//2.2.1 build 3316
	strcpy(cfg->cccam.version, cc_version[0]);
	sprintf(cfg->cccam.build, "%d", cc_build[0]);
	cfg->cccam.clientid = 1;
	cfg->cccam.serverid = 1;
	cfg->cccam.server = NULL;
	cfg->cccam.dcwcheck = 1;
	//init_cccamserver( &cfg->cccam ); cfg->cccam.id = cfg->cccamserverid; cfg->cccamserverid++;
#endif

#ifdef FREECCCAM_SRV
	//2.2.1 build 3316
	strcpy(cfg->freecccam.version, cc_version[0]);//"2.0.11");
	sprintf(cfg->freecccam.build, "%d", cc_build[0]);

	cfg->freecccam.server.client = NULL;
	cfg->freecccam.server.handle = -1;
	cfg->freecccam.server.port = 0;
	cfg->freecccam.maxusers = 0;
#endif

#ifdef MGCAMD_SRV
	cfg->mgcamd.clientid = 1;
	cfg->mgcamd.serverid = 1;
	cfg->mgcamd.server = NULL;
	cfg->mgcamd.dcwcheck = 1;
#endif

#ifdef TESTCHANNEL
	cfg->testchn.sid = 0;
	cfg->testchn.caid = 0;
	cfg->testchn.provid = 0;
#endif

	cfg->camd35.clientid = 1;
	cfg->camd35.serverid = 1;

	cfg->cs378x.clientid = 1;
	cfg->cs378x.serverid = 1;

}


void init_cardserver(struct cardserver_data *cs)
{
	memset( cs, 0, sizeof(struct cardserver_data) );

	cs->newcamd.port = 8000;

	cs->option.dcw.timeout = 3000;
	cs->option.server.max = 0;		// Max cs per ecm ( 0:unlimited )
	cs->option.server.interval = 1000;	// interval between 2 same ecm to diffrent cs
	cs->option.server.timeout = 2000; // timeout for resending ecm to cs
	cs->option.server.timeperecm = 0; // min time to do a request
	cs->option.server.validecmtime = 0; // cardserver max ecm reply time
	//cs->option.retry.cccam = 0; // Max number of retries for CCcam servers

	// Flags
	cs->option.faccept0caid = 1;
	cs->option.faccept0provider = 1;
	cs->option.faccept0sid = 0;
	cs->option.fallownewcamd = 1;  // Allow newcamd server protocol to decode ecm
	cs->option.fallowcccam = 1;    // Allow cccam server protocol to decode ecm
	cs->option.fallowradegast = 1;
	cs->option.fallowcamd35 = 1;
	cs->option.fallowcs378x = 1;
	//cs->option.fallowskipcwc = 0; // default : skip cwc disabled

	cs->option.fallowcache = 1;
#ifdef CACHEEX
	cs->option.fallowcacheex = 0;
	cs->option.cacheexvalidtime = 7000;
#endif
	cs->option.cacheresendreq = 0;
	cs->option.cachesendrep = 1;
	cs->option.cachesendreq = 1;

	//cs->fmaxuphops = 2;     // allowed cards distance to decode ecm
	cs->option.cssendcaid = 1;
	cs->option.cssendprovid = 1;
	cs->option.cssendsid = 1;
	memcpy( cs->newcamd.key, defdeskey, 14);
	cs->option.dcw.check = 0; // default: off
	// Shares
	cs->option.fsharecccam = 1;
	cs->option.fsharenewcamd = 1;
	cs->option.fsharemgcamd = 1;

	cs->option.checkecmlength = 1;
}

void init_server(struct server_data *srv)
{
	memset(srv,0,sizeof(struct server_data) );
	memcpy( srv->key, defdeskey, 14);
	srv->handle = -1;
}



struct global_user_data
{
	struct global_user_data *next;
	char user[64];
	char pass[64];
	unsigned short csport[MAX_CSPORTS];
#ifdef CHECK_NEXTDCW
	int dcwcheck;
#endif
};


void parse_option_shares( struct sharelimit_data sharelimits[100] )
{
	char str[512];
	int i;
	int count = 0;
	while ( parse_hex(str)>0 ) {
		uint16_t caid;
		uint32_t provid[16];
		int nbprovid = 0;
		int uphops = 0;
		caid = hex2int(str);
		parse_spaces();
		if (*iparser==':') { // PROVIDER ID
			iparser++;
			while (parse_hex(str)>0) {
				provid[nbprovid] = hex2int(str);
				nbprovid++;
				parse_spaces();
				if (*iparser=='&') iparser++; else break;
			}
			parse_spaces();
			if (*iparser==':') { // UPHOPS(optional)
				iparser++;
				if (parse_hex(str)>0) uphops = hex2int(str); else break; // ERROR
			}
		} else break; // ERROR
		for (i=0; i<nbprovid; i++) {
			sharelimits[count].caid = caid;
			sharelimits[count].provid = provid[i];
			sharelimits[count].uphops = uphops;
			count++;
			if (count>=99) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(,%d): too many share limits...\n",iparser-currentline);
				break;
			}
		}
		if (count>=99) break;
		parse_spaces();
		if (*iparser==',') iparser++;
	}
	sharelimits[count].caid = 0xFFFF;
}

void parse_server_data( struct server_data *tsrv )
{
	char str[255];
	int i,j;
	// DEFAULTS
	tsrv->sharelimits[0].caid = 0xFFFF;
#ifdef CACHEEX
	tsrv->cacheex_maxhop = -1;
#endif

	parse_spaces();
	if (*iparser=='{') { // Get Ports List & User Info
		iparser++;
		parse_spaces();
		if ( (*iparser>='0')&&(*iparser<='9') ) {
			i = 0;
			while (i<MAX_CSPORTS) {
				if ( parse_int(str)>0 ) {
					tsrv->csport[i] = atoi(str);
					for (j=0; j<i; j++) if ( tsrv->csport[j] && (tsrv->csport[j]==tsrv->csport[i]) ) break;
					if (j>=i) i++; else tsrv->csport[i] = 0;
				}
				else break;
				parse_spaces();
				if (*iparser==',') iparser++;
			}
		}
		else {
			while (1) {
				parse_spaces();
				if (*iparser=='}') break;
				// NAME1=value1; Name2=Value2 ... }
				parse_value(str,"\r\n\t =");
				// '='
				parse_spaces();
				if (*iparser!='=') {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(,%d): '=' expected\n",iparser-currentline);
					break;
				}
				iparser++;
				// Value
				// Check for PREDEFINED names
				if (!strcmp(str,"profiles")) {
					i = 0;
					while (i<MAX_CSPORTS) {
						if ( parse_int(str)>0 ) {
							tsrv->csport[i] = atoi(str);
							for (j=0; j<i; j++) if ( tsrv->csport[j] && (tsrv->csport[j]==tsrv->csport[i]) ) break;
							if (j>=i) i++; else tsrv->csport[i] = 0;
						}
						else break;
						parse_spaces();
						if (*iparser==',') iparser++;
					}
				}
				else if (!strcmp(str,"sids")) {
					int count = 0;
					struct sid_chid_data *sids;
					sids = malloc ( sizeof(struct sid_chid_data) * MAX_SIDS );
					memset( sids, 0, sizeof(struct sid_chid_data) * MAX_SIDS );
					tsrv->sids = sids;
					while ( parse_hex(str)>0 ) {
						sids->sid = hex2int(str);
						parse_spaces();
						if (*iparser==':') { // CHID
							iparser++;
							if (parse_hex(str)>0) sids->chid = hex2int(str);
						}
						count++;
						sids++;
						if (count>=MAX_SIDS) {
							mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(,%d): too many sids...\n",iparser-currentline);
							break;
						}
						parse_spaces();
						if (*iparser==',') iparser++;
					}
					sids->sid = 0;
					sids->chid = 0;
				}
				else if (!strcmp(str,"shares")) parse_option_shares( tsrv->sharelimits );
				else if (!strcmp(str,"priority")) {
					if (parse_int(str)) tsrv->priority = atoi(str);
				}
#ifdef CACHEEX
				else if (!strcmp(str,"cacheex_mode")) {
					if (parse_hex(str)) tsrv->cacheex_mode = hex2int(str);
				}
				else if (!strcmp(str,"cacheex_maxhop")) {
					if (parse_hex(str)) tsrv->cacheex_maxhop = hex2int(str);
				}
#ifndef PUBLIC
				else if (!strcmp(str,"cacheex_forward")) {
					if (parse_hex(str)) tsrv->cacheex_forward = hex2int(str);
				}
#endif
#endif

				parse_spaces();
				if (*iparser==';') iparser++; else break;
			}
		}	
		if (*iparser!='}') mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(,%d): '}' expected\n",iparser-currentline);
	}
/*
	char line[1024];
	server2string( tsrv, line );
	printf(">> %s\n", line);
*/
}



void cfg_addserver(struct config_data *cfg, struct server_data *srv)
{
#ifdef CACHEEX
	if (srv->cacheex_mode) {
		struct server_data *tmp = cfg->cacheexserver;
		srv->next = NULL;
		if (tmp) {
			while (tmp->next) tmp = tmp->next;
			tmp->next = srv;
		} else cfg->cacheexserver = srv;
	}
	else
#endif
	{
		struct server_data *tmp = cfg->server;
		srv->next = NULL;
		if (tmp) {
			while (tmp->next) tmp = tmp->next;
			tmp->next = srv;
		} else cfg->server = srv;
	}
}

void cfg_addprofile(struct config_data *cfg, struct cardserver_data *cs)
{
	struct cardserver_data *tmp = cfg->cardserver;
	if (tmp) {
		while (tmp->next) tmp = tmp->next;
		tmp->next = cs;
	} else cfg->cardserver = cs;
	cs->next = NULL;
}

void cs_addnewcamdclient(struct cardserver_data *cs, struct cs_client_data *cli)
{
	struct cs_client_data *tmp = cs->newcamd.client;
	cli->next = NULL;
	if (tmp) {
		while (tmp->next) tmp = tmp->next;
		tmp->next = cli;
	} else cs->newcamd.client = cli;
}

void cfg_addmgcamdclient(struct mgcamdserver_data *srv, struct mg_client_data *cli)
{
	cli->parent = srv;
	struct mg_client_data *tmp = srv->client;
	cli->next = NULL;
	if (tmp) {
		while (tmp->next) tmp = tmp->next;
		tmp->next = cli;
	} else srv->client = cli;
}

void cfg_addmgcamdserver(struct config_data *cfg, struct mgcamdserver_data *srv)
{
	struct mgcamdserver_data *tmp = cfg->mgcamd.server;
	srv->next = NULL;
	if (tmp) {
		while (tmp->next) tmp = tmp->next;
		tmp->next = srv;
	}
	else cfg->mgcamd.server = srv;
}


void cfg_addcccamclient(struct cccam_server_data *cccam, struct cc_client_data *cli)
{
	cli->parent = cccam;
#ifdef CACHEEX
	if (cli->cacheex_mode) {
		struct cc_client_data *tmp = cccam->cacheexclient;
		cli->next = NULL;
		if (tmp) {
			while (tmp->next) tmp = tmp->next;
			tmp->next = cli;
		} else cccam->cacheexclient = cli;
	}
	else
#endif
	{
		struct cc_client_data *tmp = cccam->client;
		cli->next = NULL;
		if (tmp) {
			while (tmp->next) tmp = tmp->next;
			tmp->next = cli;
		} else cccam->client = cli;
	}
}

void cfg_addcccamserver(struct config_data *cfg, struct cccam_server_data *srv)
{
	struct cccam_server_data *tmp = cfg->cccam.server;
	srv->next = NULL;
	if (tmp) {
		while (tmp->next) tmp = tmp->next;
		tmp->next = srv;
	}
	else cfg->cccam.server = srv;
}

#if defined(CAMD35_SRV) || defined(CS378X_SRV)
void cfg_addcamd35client(struct camd35_server_data *camd35, struct camd35_client_data *cli)
{
#ifdef CACHEEX
	if (cli->cacheex_mode) {
		struct camd35_client_data *tmp = camd35->cacheexclient;
		cli->next = NULL;
		if (tmp) {
			while (tmp->next) tmp = tmp->next;
			tmp->next = cli;
		} else camd35->cacheexclient = cli;
	}
	else
#endif
	{
		struct camd35_client_data *tmp = camd35->client;
		cli->next = NULL;
		if (tmp) {
			while (tmp->next) tmp = tmp->next;
			tmp->next = cli;
		} else camd35->client = cli;
	}
}
#endif

#ifdef CAMD35_SRV
void cfg_addcamd35server(struct config_data *cfg, struct camd35_server_data *srv)
{
	struct camd35_server_data *tmp = cfg->camd35.server;
	srv->next = NULL;
	if (tmp) {
		while (tmp->next) tmp = tmp->next;
		tmp->next = srv;
	}
	else cfg->camd35.server = srv;
}
#endif

#ifdef CS378X_SRV
void cfg_addcs378xserver(struct config_data *cfg, struct camd35_server_data *srv)
{
	struct camd35_server_data *tmp = cfg->cs378x.server;
	srv->next = NULL;
	if (tmp) {
		while (tmp->next) tmp = tmp->next;
		tmp->next = srv;
	}
	else cfg->cs378x.server = srv;
}
#endif

void cfg_addcachepeer(struct cacheserver_data *srv, struct cachepeer_data *peer)
{
	struct cachepeer_data *tmp = srv->peer;
	peer->next = NULL;
	if (tmp) {
		while (tmp->next) tmp = tmp->next;
		tmp->next = peer;
	} else srv->peer = peer;
}

void cfg_addcacheserver(struct config_data *cfg, struct cacheserver_data *srv)
{
	struct cacheserver_data *tmp = cfg->cache.server;
	srv->next = NULL;
	if (tmp) {
		while (tmp->next) tmp = tmp->next;
		tmp->next = srv;
	}
	else cfg->cache.server = srv;
}


///////////////////////////////////////////////////////////////////////////////
// FILE LIST
///////////////////////////////////////////////////////////////////////////////

struct filename_data *add_filename( struct config_data *cfg, char *name)
{
	struct filename_data *tmp = cfg->files;
	// Search
	while (tmp) {
		if ( !strcmp(tmp->name, name) ) return tmp;
		tmp = tmp->next;
	}
	// Create
	tmp = malloc( sizeof(struct filename_data) );
	memset( tmp, 0, sizeof(struct filename_data) );
	strcpy( tmp->name, name );
	tmp->next = NULL;
	// ADD
	struct filename_data *last = cfg->files;
	if (last) {
		while (last->next) last = last->next;
		last->next = tmp;
	} else cfg->files = tmp;
	// return
	return tmp;
}

void free_filenames( struct config_data *cfg )
{
	while (cfg->files) {
		struct filename_data *tmp = cfg->files;
		cfg->files = tmp->next;
		free(tmp);
	}
}

///////////////////////////////////////////////////////////////////////////////
// INCLUDE FILES
///////////////////////////////////////////////////////////////////////////////

struct includefile_data
{
	struct includefile_data *next;
	char name[512];
	FILE *fd;
	int nbline;
};

struct includefile_data *newfile(char *name)
{
	FILE *fd = fopen(name,"rt");
	if (fd==NULL) {
		mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," file not found '%s'\n",name);
		return NULL;
	} 
	struct includefile_data *data = malloc( sizeof(struct includefile_data) );
	data->fd = fd;
	data->next = NULL;
	strcpy(data->name, name);
	data->nbline = 0;
	mlogf(LOGINFO,getdbgflag(DBG_CONFIG,0,0)," config: parsing file '%s'\n",name);
	return data;
}

struct port_data
{
	struct port_data *next;
	int first;
	int last;
};


int read_config(struct config_data *cfg)
{
	int i;
	char str[255];
	struct cardserver_data *cardserver = NULL; // Must be pointer for local server pointing
	struct cs_client_data *usr;
	struct server_data *srv;
	int err = 0; // no error
	struct cardserver_data defaultcs;

	struct global_user_data *guser=NULL;

	struct cccam_server_data *cccam = NULL;
	struct mgcamdserver_data *mgcamd = NULL;
	struct cacheserver_data *cache = NULL;
	struct camd35_server_data *camd35 = NULL;
	struct camd35_server_data *cs378x = NULL;

	struct includefile_data *file = newfile(config_file);
	if (!file) return -1;

	struct filename_data *currentfile = add_filename( cfg, config_file );

	// Init defaultcs
	init_cardserver(&defaultcs);

	while (1) {
		memset(currentline, 0, sizeof(currentline) );
		if ( !fgets(currentline, 10239, file->fd) ) {
			struct includefile_data *tmp = file->next;
			fclose( file->fd );
			free( file );
			file = tmp;
			if (file) continue;
			else break;
		} else file->nbline++;

		while (1) {
			char *pos;
			// Remove Comments
			pos = currentline;
			while (*pos) { 
				if (*pos=='#') {
					*pos=0;
					break;
				}
				pos++;
			}
			// delete from the end '\r' '\n' ' ' '\t'
			pos = currentline + strlen(currentline) - 1 ;
			while ( (*pos=='\r')||(*pos=='\n')||(*pos=='\t')||(*pos==' ') ) { 
				*pos=0; pos--;
				if (pos<=currentline) break;
			}
			if (*pos=='\\') {
				if ( !fgets(pos, 10239-(pos-currentline), file->fd) ) {
					*pos=0;
					break;
				}
			} else break;
		}
		//printf("%s\n", currentline);
		iparser = currentline;
		parse_spaces();

		if (*iparser==0) continue;

		if (*iparser=='[') {
			iparser++;
			parse_value(str, "\r\n]" );
			if (*iparser!=']') {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ']' expected\n",file->nbline,iparser-currentline);
				continue;
			} else iparser++;

			cardserver = malloc( sizeof(struct cardserver_data) );
			memcpy( cardserver, &defaultcs, sizeof(struct cardserver_data) );
			// Newcamd Port
			cardserver->newcamd.port = defaultcs.newcamd.port;
			if (defaultcs.newcamd.port) defaultcs.newcamd.port++;
			// Name
			strcpy(cardserver->name, str);
			cfg_addprofile(cfg, cardserver);
			continue;
		}

		if ( (*iparser<'A') || ((*iparser>'Z')&&(*iparser<'a')) || (*iparser>'z') ) continue; // each line iparser with a word
		if (!parse_name(str)) continue;
		uppercase(str);
		err = 0; // no error


		if (!strcmp(str,"INCLUDE")) {
			parse_spaces();
			if ((*iparser==':')||(*iparser=='=')) iparser++;
			parse_spaces();
			if ( parse_quotes('"',str) ) {
				struct includefile_data *new = newfile( str );
				if (new) {
					currentfile = add_filename( cfg, str );
					new->next = file;
					file = new;
					continue;
				}
			} 
		}

		else if ( !strcmp(str,"UPDATE") ) {
			parse_name(str);
			uppercase(str);
			if (!strcmp(str,"ONCHANGE")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				currentfile->nowatch = !parse_boolean();
			}
		}

		else if ( !strcmp(str,"EDITFILE") ) {
			parse_spaces();
			if ((*iparser!=':')&&(*iparser!='=')) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
				continue;
			} else iparser++;
			currentfile->noeditor = !parse_boolean();
		}

		else if (!strcmp(str,"N")) {
			parse_spaces();
			if ((*iparser!=':')&&(*iparser!='=')) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
				continue;
			} else iparser++;
			struct server_data tsrv;
			memset(&tsrv,0,sizeof(struct server_data) );
			tsrv.type = TYPE_NEWCAMD;
			parse_str(str);
			tsrv.host = add_host(cfg, str);

			struct port_data *ports = NULL;
			while ( parse_int(str) ) {
				// Ports
				struct port_data *new = malloc( sizeof(struct port_data) );
				memset(new, 0, sizeof(struct port_data) );
				new->next = NULL;
				new->first = atoi(str);
				new->last = new->first;
				// ADD
				struct port_data *tmp = ports;
				if (tmp) {
					while (tmp->next) tmp = tmp->next;
					tmp->next = new;
				} else ports = new;
				// Parse Last
				if (*iparser==':') {
					iparser++;
					if ( parse_int(str) ) new->last = atoi( str );
				}
				if (*iparser==',') iparser++; else break;
			}
			if ( ports==NULL ) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Error reading newcamd port\n",file->nbline,iparser-currentline);
				continue;
			} 
			// user&pass
			parse_str(tsrv.user);
			parse_str(tsrv.pass);
			for(i=0; i<14; i++)
				if ( parse_hex(str)!=2 ) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Error reading DES-KEY\n",file->nbline,iparser-currentline);
					err++;
					break;
				} 
				else {
					tsrv.key[i] = hex2int(str);
				}
			if (err) {
				continue;
			}

			parse_server_data( &tsrv );
			tsrv.handle = -1;

			// Create Servers
			while (ports) {
				for (i=ports->first; i<=ports->last; i++) {
					struct server_data *srv = malloc( sizeof(struct server_data) );
					memcpy(srv,&tsrv,sizeof(struct server_data) );
					srv->port = i;
					pthread_mutex_init( &srv->lock, NULL );
					cfg_addserver(cfg, srv);
				}
				// Remove Ports
				struct port_data *tmp = ports;
				ports = ports->next;
				free(tmp);
			}
		}

#ifdef RADEGAST_CLI
		//R: host port caid providers
		else if (!strcmp(str,"R")) {
link_radegast_server:
			parse_spaces();
			if ((*iparser!=':')&&(*iparser!='=')) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
				continue;
			} else iparser++;
			srv = malloc( sizeof(struct server_data) );
			memset(srv,0,sizeof(struct server_data) );
			srv->type = TYPE_RADEGAST;
			parse_str(str);
			srv->host = add_host(cfg, str);
			parse_int(str);
			srv->port = atoi( str );
			// Card
			struct cs_card_data *card = malloc( sizeof(struct cs_card_data) );
			memset(card, 0, sizeof(struct cs_card_data) );
			srv->card = card;
			parse_hex(str);
			card->caid = hex2int( str );
			card->nbprov = 0;
			card->uphops = 1;
			for(i=0;i<CARD_MAXPROV;i++) {
				if ( parse_hex(str)>0 ) {
					card->prov[i] = hex2int( str );
					card->nbprov++;
				} else break;
				parse_spaces();
				if (*iparser==',') iparser++;
			}
			srv->handle = -1;
			pthread_mutex_init( &srv->lock, NULL );
			cfg_addserver(cfg, srv);
		}
#endif



		else if (!strcmp(str,"NEWCAMD")) {
			parse_name(str);
			uppercase(str);
			if (!strcmp(str,"CLIENTID")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_hex(str);
				cfg->newcamd.clientid = hex2int(str);
			}
			else if (!strcmp(str,"DCW")) {
				parse_name(str);
				uppercase(str);
				if (!strcmp(str,"CHECK")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0),"':' expected\n");
						continue;
					} else iparser++;
					cfg->newcamd.dcwcheck = parse_boolean();
				}
			}
			else if (!strcmp(str,"KEEPALIVE")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				cfg->newcamd.keepalive = parse_boolean();
			}
		}

		else if (!strcmp(str,"PORT")) {
			if (!cardserver) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Skip PORT, undefined profile\n",file->nbline,iparser-currentline);
				continue;
			}
			parse_spaces();
			if ((*iparser!=':')&&(*iparser!='=')) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
				continue;
			} else iparser++;
			parse_spaces();
			if (*iparser=='+') {
				iparser++;
				//cardserver->newcamd.port = defaultcs.newcamd.port;
				//defaultcs.newcamd.port++;
			}
			else {
				parse_int(str);
				//mlogf(LOGDEBUG,getdbgflag(DBG_CONFIG,0,0),"port:%s\n", str);
				parse_spaces();
				cardserver->newcamd.port = atoi(str);
				defaultcs.newcamd.port = cardserver->newcamd.port;
				if (defaultcs.newcamd.port) defaultcs.newcamd.port++;
			}			
		}

		else if (!strcmp(str,"KEY")) {
			if (!cardserver) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Skip KEY, undefined profile\n",file->nbline,iparser-currentline);
				continue;
			}
			parse_spaces();
			if ((*iparser!=':')&&(*iparser!='=')) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
				continue;
			} else iparser++;
			for (i=0; i<14; i++) {
				if ( parse_hex(str)!=2 ) {
					memset( cardserver->newcamd.key, 0, 16 );
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Error reading DES-KEY\n",file->nbline,iparser-currentline);
					break;
				} 
				else {
					cardserver->newcamd.key[i] = hex2int(str);
				}
			}
		}



#ifdef CAMD35_SRV
		else if (!strcmp(str,"CAMD35")) {
			parse_name(str);
			uppercase(str);
			if (!strcmp(str,"PORT")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0),"':' expected\n");
					continue;
				} else iparser++;
				parse_int(str);
				// Create New
				camd35 = malloc( sizeof(struct camd35_server_data) );
				memset( camd35, 0, sizeof(struct camd35_server_data) );
				camd35->port = atoi(str);
				camd35->handle = -1;
				camd35->id = 0;
				cfg_addcamd35server(cfg, camd35);
			}
#ifdef CAMD35_CLI
			else if (!strcmp(str,"SERVER")) {
				goto link_camd35_server;
			}
#endif
			else if (!strcmp(str,"USER")) {
				if (!camd35) {
					mlogf(LOGINFO,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Skip Camd35 user, undefined Camd35 Server\n",file->nbline,iparser-currentline);
					continue;
				}
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				// must check for reuse of same user
				struct camd35_client_data *cli = malloc( sizeof(struct camd35_client_data) );
				memset(cli,0,sizeof(struct camd35_client_data) );
				// init default
				cli->handle = -1;
				cli->flags |= FLAG_DEFCONFIG;
				//
				parse_str(cli->user);
				cli->userhash = hashCode( (unsigned char *)cli->user, strlen(cli->user) );
				parse_str(cli->pass);

				cli->sharelimits[0].caid = 0xFFFF;
				parse_spaces();
				if (*iparser=='{') { // Get Ports List & User Info
					iparser++;
					parse_spaces();
					while (1) {
						parse_spaces();
						if (*iparser=='}') break;
						// NAME1=value1; Name2=Value2 ... }
						parse_value(str,"\r\n\t =");
						//printf(" NAME: '%s'\n", str);
						// '='
						parse_spaces();
						if (*iparser!='=') break;
						iparser++;
						// Value
						// Check for PREDEFINED names
						if (!strcmp(str,"profiles")) {
							i = 0;
							while (i<MAX_CSPORTS) {
								if ( parse_int(str)>0 ) {
									// check for port
									int n = cli->csport[i] = atoi(str);
									int j;
									for (j=0; j<i; j++) if ( cli->csport[j] && (cli->csport[j]==n) ) break;
									if (j>=i) { 
										cli->csport[i] = n;
										i++;
									}
								}
								else break;
								parse_spaces();
								if (*iparser==',') iparser++;
							}
						}

						else if (!strcmp(str,"shares")) parse_option_shares( cli->sharelimits );
#ifdef CACHEEX
						else if (!strcmp(str,"cacheex_mode")) {
							if (parse_hex(str)) cli->cacheex_mode = hex2int(str);
						}
#endif
						parse_spaces();
						if (*iparser==';') iparser++; else break;
					}
					if (*iparser!='}') mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): '}' expected\n",file->nbline,iparser-currentline);
				}
				camd35_init_data( cli->user, cli->pass, &cli->encryptkey, &cli->decryptkey, &cli->ucrc);
				cfg_addcamd35client(camd35, cli);
			}
		}

#endif

#ifdef CS378X_SRV
		else if (!strcmp(str,"CS378X")) {
			parse_name(str);
			uppercase(str);
			if (!strcmp(str,"PORT")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_int(str);
				// Create New
				cs378x = malloc( sizeof(struct camd35_server_data) );
				memset( cs378x, 0, sizeof(struct camd35_server_data) );
				cs378x->client = NULL;
				cs378x->port = atoi(str);
				cs378x->handle = -1;
				cs378x->id = 0;
				cs378x->next = NULL;
				// Add to config
				cfg_addcs378xserver(cfg, cs378x);
			}
			else if (!strcmp(str,"USER")) {
				if (!cs378x) {
					mlogf(LOGINFO,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Skip cs378x user, undefined cs378x Server\n",file->nbline,iparser-currentline);
					continue;
				}
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				// must check for reuse of same user
				struct camd35_client_data *cli = malloc( sizeof(struct camd35_client_data) );
				memset(cli,0,sizeof(struct camd35_client_data) );
				// init default
				cli->handle = -1;
				cli->flags |= FLAG_DEFCONFIG;
				//
				parse_str(cli->user);
				cli->userhash = hashCode( (unsigned char *)cli->user, strlen(cli->user) );
				parse_str(cli->pass);

				cli->sharelimits[0].caid = 0xFFFF;
				parse_spaces();
				if (*iparser=='{') { // Get Ports List & User Info
					iparser++;
					parse_spaces();
					while (1) {
						parse_spaces();
						if (*iparser=='}') break;
						// NAME1=value1; Name2=Value2 ... }
						parse_value(str,"\r\n\t =");
						//printf(" NAME: '%s'\n", str);
						// '='
						parse_spaces();
						if (*iparser!='=') break;
						iparser++;
						// Value
						// Check for PREDEFINED names
						if (!strcmp(str,"profiles")) {
							i = 0;
							while (i<MAX_CSPORTS) {
								if ( parse_int(str)>0 ) {
									// check for port
									int n = cli->csport[i] = atoi(str);
									int j;
									for (j=0; j<i; j++) if ( cli->csport[j] && (cli->csport[j]==n) ) break;
									if (j>=i) { 
										cli->csport[i] = n;
										i++;
									}
								}
								else break;
								parse_spaces();
								if (*iparser==',') iparser++;
							}
						}

						else if (!strcmp(str,"shares")) parse_option_shares( cli->sharelimits );
#ifdef CACHEEX
						else if (!strcmp(str,"cacheex_mode")) {
							if (parse_hex(str)) cli->cacheex_mode = hex2int(str);
						}
#endif
						parse_spaces();
						if (*iparser==';') iparser++; else break;
					}
					if (*iparser!='}') mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): '}' expected\n",file->nbline,iparser-currentline);
				}
				camd35_init_data( cli->user, cli->pass, &cli->encryptkey, &cli->decryptkey, &cli->ucrc);
				//
				cfg_addcamd35client( cs378x, cli);
			}
			else if (!strcmp(str,"SERVER")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				srv = malloc( sizeof(struct server_data) );
				memset(srv,0,sizeof(struct server_data) );
				srv->type = TYPE_CS378X;
				parse_str(str);
				srv->host = add_host(cfg, str);
				parse_int(str);
				srv->port = atoi( str );
				if (*iparser==',') iparser++; // like in oscam (device = host,port)
				parse_str(srv->user);
				parse_str(srv->pass);
				/// if (parse_int(str)) srv->uphops = atoi( str ); else srv->uphops=1; removed
				parse_server_data( srv );
				srv->handle = -1;
				pthread_mutex_init( &srv->lock, NULL );
				cfg_addserver(cfg, srv);
				camd35_init_data( srv->user, srv->pass, &srv->encryptkey, &srv->decryptkey, &srv->ucrc);
			}
			else if (!strcmp(str,"KEEPALIVE")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				cfg->cs378x.keepalive = parse_boolean();
			}
		}
#endif


#ifdef CAMD35_CLI
		else if (!strcmp(str,"L")) {
link_camd35_server:
			parse_spaces();
			if ((*iparser!=':')&&(*iparser!='=')) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
				continue;
			} else iparser++;
			srv = malloc( sizeof(struct server_data) );
			memset(srv,0,sizeof(struct server_data) );
			srv->type = TYPE_CAMD35;
			parse_str(str);
			srv->host = add_host(cfg, str);
			parse_int(str);
			srv->port = atoi( str );
			if (*iparser==',') iparser++; // like in oscam (device = host,port)
			parse_str(srv->user);
			parse_str(srv->pass);
			/// if (parse_int(str)) srv->uphops = atoi( str ); else srv->uphops=1; removed
			parse_server_data( srv );
			srv->handle = -1;
			pthread_mutex_init( &srv->lock, NULL );
			cfg_addserver(cfg, srv);
			camd35_init_data( srv->user, srv->pass, &srv->encryptkey, &srv->decryptkey, &srv->ucrc);
		}
#endif




#ifndef PUBLIC
		else if (!strcmp(str,"DELAY")) {
			parse_name(str);
			uppercase(str);
			if (!strcmp(str,"THREAD")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0),"':' expected\n");
					continue;
				} else iparser++;
				if (parse_int(str)) cfg->delay.thread = atoi(str);
			}
			else if (!strcmp(str,"CONNECT")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0),"':' expected\n");
					continue;
				} else iparser++;
				if (parse_int(str)) cfg->delay.connect = atoi(str);
			}
		}
#endif

		else if (!strcmp(str,"LOGLEVEL")) {
			parse_spaces();
			if ((*iparser!=':')&&(*iparser!='=')) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0),"':' expected\n");
				continue;
			} else iparser++;
			if (parse_int(str)) 
			{
				int tmploglevel=atoi(str);
				if (tmploglevel<0 || tmploglevel>6)
				{
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0),"LOGLEVEL must be between 0 and 5\n");
					continue;
				}
				else
				{
					loglevel=tmploglevel;
				}
			}
		}

#ifdef TELNET
		else if (!strcmp(str,"TELNET")) {
			parse_name(str);
			uppercase(str);
			if (!strcmp(str,"PORT")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0),"':' expected\n");
					continue;
				} else iparser++;
				parse_int(str);
				mlogf(LOGDEBUG,getdbgflag(DBG_CONFIG,0,0),"telnet port:%s\n", str);
				parse_spaces();
				if (!cardserver) cfg->telnet.port = atoi(str);
				else mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config: skip telnet port, defined within profile\n");
			}
			else if (!strcmp(str,"USER")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0),"':' expected\n");
					continue;
				} else iparser++;
				parse_str(cfg->telnet.user);
			}
			else if (!strcmp(str,"PASS")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0),"':' expected\n");
					continue;
				} else iparser++;
				parse_str(cfg->telnet.pass);
			}
		}
#endif

#ifdef HTTP_SRV
		else if (!strcmp(str,"HTTP")) {
			parse_name(str);
			uppercase(str);
			if (!strcmp(str,"PORT")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0),"':' expected\n");
					continue;
				} else iparser++;
				parse_int(str);
				mlogf(LOGDEBUG,getdbgflag(DBG_CONFIG,0,0),"http port:%s\n", str);
				parse_spaces();
				if (!cardserver) cfg->http.port = atoi(str);
				else mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config: skip http port, defined within profile\n");
			}
/*
http show editor:
http show restart
http show cccam
http hide cccam

sid deny:
sid accept: 

			else if (!strcmp(str,"ADMINUSER")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0),"':' expected\n");
					continue;
				} else iparser++;
				parse_str(cfg->http.user);
			}
			else if (!strcmp(str,"ADMINPASS")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0),"':' expected\n");
					continue;
				} else iparser++;
				parse_str(cfg->http.user);
			}
*/

			else if (!strcmp(str,"USER")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0),"':' expected\n");
					continue;
				} else iparser++;
				parse_str(cfg->http.user);
			}
			else if (!strcmp(str,"PASS")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0),"':' expected\n");
					continue;
				} else iparser++;
				parse_str(cfg->http.pass);
			}

			else if (!strcmp(str,"CACHE")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0),"':' expected\n");
					continue;
				} else iparser++;
				cfg->http.show.nocache = !parse_boolean();
			}
			else if (!strcmp(str,"CACHEEX")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0),"':' expected\n");
					continue;
				} else iparser++;
				cfg->http.show.nocacheex = !parse_boolean();
			}
			else if (!strcmp(str,"NEWCAMD")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0),"':' expected\n");
					continue;
				} else iparser++;
				cfg->http.show.nonewcamd = !parse_boolean();
			}
			else if (!strcmp(str,"MGCAMD")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0),"':' expected\n");
					continue;
				} else iparser++;
				cfg->http.show.nomgcamd = !parse_boolean();
			}
			else if (!strcmp(str,"CCCAM")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0),"':' expected\n");
					continue;
				} else iparser++;
				cfg->http.show.nocccam = !parse_boolean();
			}
			else if (!strcmp(str,"SERVERS")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0),"':' expected\n");
					continue;
				} else iparser++;
				cfg->http.show.noservers = !parse_boolean();
			}
			else if (!strcmp(str,"PROFILES")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0),"':' expected\n");
					continue;
				} else iparser++;
				cfg->http.show.noprofiles = !parse_boolean();
			}
			else if (!strcmp(str,"DEBUG")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0),"':' expected\n");
					continue;
				} else iparser++;
				cfg->http.show.nodebug = !parse_boolean();
			}


			else if (!strcmp(str,"EDITOR")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0),"':' expected\n");
					continue;
				} else iparser++;
				cfg->http.show.noeditor = !parse_boolean();
			}
			else if (!strcmp(str,"RESTART")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0),"':' expected\n");
					continue;
				} else iparser++;
				cfg->http.show.norestart = !parse_boolean();
			}

			else if (!strcmp(str,"AUTOREFRESH")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0),"':' expected\n");
					continue;
				} else iparser++;
				parse_int(str);
				uppercase(str);
				if (!strcmp(str,"OFF")) cfg->http.autorefresh = 0;
				else {
					cfg->http.autorefresh = atoi(str);
					if (cfg->http.autorefresh<0) cfg->http.autorefresh = 0;
					else if (cfg->http.autorefresh>600) cfg->http.autorefresh = 600;
				}
			}

			else if (!strcmp(str,"TITLE")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_spaces();
				if ( parse_quotes('"',str) ) strcpy( cfg->http.title, str );
			}

			else if (!strcmp(str,"FILE")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_spaces();
				if ( parse_quotes('"',str) ) {
					parse_spaces();
					if (*iparser!=',') continue;
					iparser++;
					struct http_file_data *file = malloc( sizeof(struct http_file_data) );
					strcpy( file->path, str );
					parse_quotes('"', file->url);
					if (*iparser==',') {
						iparser++;
						parse_quotes('"', file->mime);
					}
					else {
						strcpy(file->mime, mimes[0].mime); // default
						// get extention
						char *ext = strrchr(file->url,'.');
						if (ext) {
							int i;
							for(i=0; i<MAX_MIMES; i++) {
								if ( !strcmp(mimes[i].ext, ext+1) ) {
									strcpy(file->mime, mimes[i].mime);
									break;
								}
							}
						}
						else {
							ext = strrchr(file->path,'.');
							if (ext) {
								int i;
								for(i=0; i<MAX_MIMES; i++) {
									if ( !strcmp(mimes[i].ext, ext+1) ) {
										strcpy(file->mime, mimes[i].mime);
										break;
									}
								}
							}
						}
					}
					file->next = cfg->http.files;
					cfg->http.files = file;
				}
			}

		}
#endif

		else if (!strcmp(str,"BAD-DCW")) {
			parse_spaces();
			if ((*iparser!=':')&&(*iparser!='=')) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
				continue;
			} else iparser++;
			struct dcw_data *dcw = malloc( sizeof(struct dcw_data) );
			memset(dcw,0,sizeof(struct dcw_data) );
			int error = 0;
			for(i=0; i<16; i++)
				if ( parse_hex(str)!=2 ) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Error reading BAD-DCW\n",file->nbline,iparser-currentline);
					error++;
					break;
				} 
				else {
					dcw->dcw[i] = hex2int(str);
				}
			if (error)
				free(dcw);
			else {
				dcw->next = cfg->bad_dcw;
				cfg->bad_dcw = dcw;
			}
		}


#ifdef TESTCHANNEL
		else if (!strcmp(str,"TESTCHANNEL")) {
			parse_spaces();
			if ((*iparser!=':')&&(*iparser!='=')) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0),"':' expected\\n");
				continue;
			} else iparser++;
			//
			parse_hex(str);
			cfg->testchn.caid = hex2int(str);
			//
			parse_spaces();
			if (*iparser!=':') {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0),"':' expected\\n");
				continue;
			} else iparser++;
			parse_hex(str);
			cfg->testchn.provid = hex2int(str);
			//
			parse_spaces();
			if (*iparser!=':') {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0),"':' expected\\n");
				continue;
			} else iparser++;
			parse_hex(str);
			cfg->testchn.sid = hex2int(str);
			mlogf(LOGDEBUG,getdbgflag(DBG_CONFIG,0,0), " Test Channel %04x:%06x:%04x\n", cfg->testchn.caid, cfg->testchn.provid, cfg->testchn.sid);
		}
#endif


		else if (!strcmp(str,"FILE")) {
			parse_name(str);
			uppercase(str);
			if (!strcmp(str,"CHANNELINFO")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_spaces();
				if ( parse_quotes('"',str) ) {
					strcpy( cfg->channelinfo_file, str );
					read_chinfo( cfg );
				}
			}
			else if (!strcmp(str,"PROVIDERINFO")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_spaces();
				if ( parse_quotes('"',str) ) strcpy( cfg->providers_file, str );
			}
			else if (!strcmp(str,"IP2COUNTRY")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_spaces();
				if ( parse_quotes('"',str) ) strcpy( cfg->ip2country_file, str );
			}
			else if (!strcmp(str,"STYLESHEET")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_spaces();
				if ( parse_quotes('"',str) ) strcpy( cfg->stylesheet_file, str );
			}
            else if (!strcmp(str,"JAVASCRIPT")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_spaces();
				if ( parse_quotes('"',str) ) {
					mlogf(LOGINFO,getdbgflag(DBG_CONFIG,0,0)," config: read JAVASCRIPT file %s\n",str);
					strcpy( cfg->javascript_file, str );
				}
			}
		}


#ifdef TWIN
///////////////////////////////////////////////////////////////////////////////
// TWIN PROTOCOL
///////////////////////////////////////////////////////////////////////////////
		else if (!strcmp(str,"TWIN")) {
			parse_name(str);
			uppercase(str);
			if (!strcmp(str,"DEVICE")) {
				parse_spaces();
				if ( (*iparser!=':')&&(*iparser!='=') ) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;

				cfg->twin.serial.handle=-1;
				parse_quotes('"',cfg->twin.serial.device);
				//debug("SERIAL = '%s', '%s'\n", twin->device, twin->chninfo.fname);
			}
			else if (!strcmp(str,"CHANNELINFO")) {
				parse_spaces();
				if ( (*iparser!=':')&&(*iparser!='=') ) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_quotes('"', cfg->twin.chninfo.fname);
				twin_read_chninfo(cfg);
				//debug("SERIAL = '%s', '%s'\n", cfg->twin.device, cfg->twin.chninfo.fname);
			}
		}
#endif

///////////////////////////////////////////////////////////////////////////////
// DEFAULT
///////////////////////////////////////////////////////////////////////////////


		else if (!strcmp(str,"DEFAULT")) {
			parse_name(str);
			uppercase(str);
			if (!strcmp(str,"KEY")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				for(i=0; i<14; i++) if ( parse_hex(str)!=2 ) break; else defaultcs.newcamd.key[i] = hex2int(str);
			}

			else if (!strcmp(str,"PORT")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_int(str);
				defaultcs.newcamd.port = atoi(str);
			}

			else if (!strcmp(str,"DCW")) {
				parse_name(str);
				uppercase(str);
				if (!strcmp(str,"TIMEOUT")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue; 
					} else iparser++;
					parse_int(str);
					parse_spaces();
					defaultcs.option.dcw.timeout = atoi(str);
					if (defaultcs.option.dcw.timeout<300) defaultcs.option.dcw.timeout=300;
					else if (defaultcs.option.dcw.timeout>9999) defaultcs.option.dcw.timeout=9999;
				}
				else if (!strcmp(str,"MAXFAILED")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					parse_int(str);
					parse_spaces();
					defaultcs.option.maxfailedecm = atoi(str);
					if (defaultcs.option.maxfailedecm<0) defaultcs.option.maxfailedecm=0;
					else if (defaultcs.option.maxfailedecm>100) defaultcs.option.maxfailedecm=100;
				}
				else if (!strcmp(str,"RETRY")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					parse_int(str);
					parse_spaces();
					defaultcs.option.dcw.retry = atoi(str);
					if (defaultcs.option.dcw.retry<0) defaultcs.option.dcw.retry=0;
					else if (defaultcs.option.dcw.retry>5) defaultcs.option.dcw.retry=5;
				}
#ifdef CHECK_NEXTDCW
				else if (!strcmp(str,"CHECK")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					defaultcs.option.dcw.check = parse_boolean();
				}
#endif
			}
			else if ( !strcmp(str,"SERVER") ) {
				parse_name(str);
				uppercase(str);
				if (!strcmp(str,"TIMEOUT")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					parse_int(str);
					defaultcs.option.server.timeout = atoi(str);
					if ( (defaultcs.option.server.timeout<300)||(defaultcs.option.server.timeout>10000) ) defaultcs.option.server.timeout=300;
				}
				else if (!strcmp(str,"MAX")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					parse_int(str);
					defaultcs.option.server.max = atoi(str);
					if (defaultcs.option.server.max<0) defaultcs.option.server.max=0;
					else if (defaultcs.option.server.max>10) defaultcs.option.server.max=10;
				}
				else if (!strcmp(str,"INTERVAL")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					parse_int(str);
					defaultcs.option.server.interval = atoi(str);
					if (defaultcs.option.server.interval<100) defaultcs.option.server.interval=100;
					else if (defaultcs.option.server.interval>3000) defaultcs.option.server.interval=3000;
				}
				else if (!strcmp(str,"VALIDECMTIME")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					parse_int(str);
					defaultcs.option.server.validecmtime = atoi(str);
					if (defaultcs.option.server.validecmtime>5000) defaultcs.option.server.validecmtime=5000;
				}
				else if (!strcmp(str,"FIRST")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					parse_int(str);
					defaultcs.option.server.first = atoi(str);
					if (defaultcs.option.server.first<0) defaultcs.option.server.first = 0;
					else if (defaultcs.option.server.first>5) defaultcs.option.server.first = 5;
				}
#ifndef PUBLIC
				else if ( (!strcmp(str,"ECMTIME"))||(!strcmp(str,"TIMEPERECM")) ) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					parse_int(str);
					defaultcs.option.server.timeperecm = atoi(str);
					if (defaultcs.option.server.timeperecm>5000) defaultcs.option.server.timeperecm=5000;
				}
				else if (!strcmp(str,"THRESHOLD")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					parse_int(str);
					defaultcs.option.server.threshold = atoi(str);
					if (defaultcs.option.server.threshold<0) defaultcs.option.server.threshold = 0;
					else if (defaultcs.option.server.threshold>30) defaultcs.option.server.threshold = 30;
				}
				else if (!strcmp(str,"SEND")) {
					parse_name(str);
					uppercase(str);
					if (!strcmp(str,"SID")) {
						parse_spaces();
						if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
							continue;
						} else iparser++;
						defaultcs.option.cssendsid = parse_boolean();
					}
					else if (!strcmp(str,"CAID")) {
						parse_spaces();
						if ((*iparser!=':')&&(*iparser!='=')) {
							mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
							continue;
						} else iparser++;
						defaultcs.option.cssendcaid = parse_boolean();
					}
					else if (!strcmp(str,"PROVIDER")) {
						parse_spaces();
						if ((*iparser!=':')&&(*iparser!='=')) {
							mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
							continue;
						} else iparser++;
						defaultcs.option.cssendprovid = parse_boolean();
					}
					else mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): cardserver send variable expected\n",file->nbline,iparser-currentline);
				}
#endif
				else mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): profile variable expected\n",file->nbline,iparser-currentline);
			}
			else if ( !strcmp(str,"RETRY") ) {
				parse_name(str);
				uppercase(str);
				if (!strcmp(str,"NEWCAMD")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					parse_int(str);
					defaultcs.option.retry.newcamd = atoi(str);
					if (defaultcs.option.retry.newcamd<0) defaultcs.option.retry.newcamd=0;
					else if (defaultcs.option.retry.newcamd>3) defaultcs.option.retry.newcamd=3;
				}
				else if (!strcmp(str,"CCCAM")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					parse_int(str);
					defaultcs.option.retry.cccam = atoi(str);
					if (defaultcs.option.retry.cccam<0) defaultcs.option.retry.cccam=0;
					else if (defaultcs.option.retry.cccam>10) defaultcs.option.retry.cccam=10;
				}
				else mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): profile variable expected\n",file->nbline,iparser-currentline);
			}

#ifdef CACHEEX
			else if ( !strcmp(str,"CACHEEX") ) {
				parse_name(str);
				uppercase(str);
				if (!strcmp(str,"VALIDECMTIME")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					parse_int(str);
					defaultcs.option.cacheexvalidtime = atoi(str);
					if ( defaultcs.option.cacheexvalidtime>7000 ) defaultcs.option.cacheexvalidtime = 7000;
				}
				else if (!strcmp(str,"MAXHOP")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					parse_int(str);
					defaultcs.option.cacheex.maxhop = atoi(str);
					if ( defaultcs.option.cacheex.maxhop<1 ) defaultcs.option.cacheex.maxhop = 1;
					else if ( defaultcs.option.cacheex.maxhop>2 ) defaultcs.option.cacheex.maxhop = 2;
				}
			}
#endif

			else if ( !strcmp(str,"CACHE") ) {
				parse_name(str);
				uppercase(str);
				if (!strcmp(str,"TIMEOUT")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					parse_int(str);
					defaultcs.option.cachetimeout = atoi(str);
					if (defaultcs.option.cachetimeout<0) defaultcs.option.cachetimeout = 0;
					else if (defaultcs.option.cachetimeout>5000) defaultcs.option.cachetimeout = 5000;
				}
				else if (!strcmp(str,"SENDREQ")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue; 
					} else iparser++;
					defaultcs.option.cachesendreq = parse_boolean();
				}
#ifndef PUBLIC
				else if (!strcmp(str,"STATIC")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue; 
					} else iparser++;
					defaultcs.option.cachestatic = parse_boolean();
				}
				else if (!strcmp(str,"RESENDREQ")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue; 
					} else iparser++;
					defaultcs.option.cacheresendreq = parse_boolean();
				}
				else if (!strcmp(str,"SENDREP")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue; 
					} else iparser++;
					defaultcs.option.cachesendrep = parse_boolean();
				}
#endif
			}
			else if ( !strcmp(str,"ACCEPT") ) {
				parse_name(str);
				uppercase(str);
				if (!strcmp(str,"NULL")) {
					parse_name(str);
					uppercase(str);
					if (!strcmp(str,"SID")) {
						parse_spaces();
						if ((*iparser!=':')&&(*iparser!='=')) {
							mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
							continue;
						} else iparser++;
						defaultcs.option.faccept0sid = parse_boolean();
					}
					else if (!strcmp(str,"CAID")) {
						parse_spaces();
						if ((*iparser!=':')&&(*iparser!='=')) {
							mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
							continue;
						} else iparser++;
						defaultcs.option.faccept0caid = parse_boolean();
					}
					else if (!strcmp(str,"PROVIDER")) {
						parse_spaces();
						if ((*iparser!=':')&&(*iparser!='=')) {
							mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
							continue;
						} else iparser++;
						defaultcs.option.faccept0provider = parse_boolean();
					}
				}
			}
			else if (!strcmp(str,"DISABLE")) {
				parse_name(str);
				uppercase(str);
				if (!strcmp(str,"CCCAM")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					defaultcs.option.fallowcccam = !parse_boolean();
				}
				else if (!strcmp(str,"NEWCAMD")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					defaultcs.option.fallownewcamd = !parse_boolean();
				}
				else if (!strcmp(str,"RADEGAST")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					defaultcs.option.fallowradegast = !parse_boolean();
				}
				else if (!strcmp(str,"CACHE")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					defaultcs.option.fallowcache = !parse_boolean();
				}
				else if (!strcmp(str,"CAMD35")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					defaultcs.option.fallowcamd35 = !parse_boolean();
				}
				else if (!strcmp(str,"CS378X")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					defaultcs.option.fallowcs378x = !parse_boolean();
				}
				/* else if (!strcmp(str,"SKIPCWC")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					defaultcs.option.fallowskipcwc = !parse_boolean();
				} */
#ifdef CACHEEX
				else if (!strcmp(str,"CACHEEX")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					defaultcs.option.fallowcacheex = !parse_boolean();
				}
#endif
			}
			else if (!strcmp(str,"ENABLE")) {
				parse_name(str);
				uppercase(str);
				if (!strcmp(str,"CCCAM")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					defaultcs.option.fallowcccam = parse_boolean();
				}
				else if (!strcmp(str,"NEWCAMD")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					defaultcs.option.fallownewcamd = parse_boolean();
				}
				else if (!strcmp(str,"RADEGAST")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					defaultcs.option.fallowradegast = parse_boolean();
				}
				else if (!strcmp(str,"CACHE")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					defaultcs.option.fallowcache = parse_boolean();
				}
				else if (!strcmp(str,"CAMD35")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					defaultcs.option.fallowcamd35 = parse_boolean();
				}
				else if (!strcmp(str,"CS378X")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					defaultcs.option.fallowcs378x = parse_boolean();
				}
				/* else if (!strcmp(str,"SKIPCWC")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					defaultcs.option.fallowskipcwc = parse_boolean();
				} */
#ifdef CACHEEX
				else if (!strcmp(str,"CACHEEX")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					defaultcs.option.fallowcacheex = parse_boolean();
				}
#endif
			}
		}

///////////////////////////////////////////////////////////////////////////////


#ifdef CCCAM_CLI
		else if (!strcmp(str,"C")) {
link_cccam_server:
			parse_spaces();
			if ((*iparser!=':')&&(*iparser!='=')) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
				continue;
			} else iparser++;
			srv = malloc( sizeof(struct server_data) );
			memset(srv,0,sizeof(struct server_data) );
			srv->type = TYPE_CCCAM;
			parse_str(str);
			srv->host = add_host(cfg, str);
			parse_int(str);
			srv->port = atoi( str );
			if (*iparser==',') iparser++; // like in oscam (device = host,port)
			parse_str(srv->user);
			parse_str(srv->pass);
			/// if (parse_int(str)) srv->uphops = atoi( str ); else srv->uphops=1; removed
			parse_server_data( srv );
			srv->handle = -1;
			pthread_mutex_init( &srv->lock, NULL );
			cfg_addserver(cfg, srv);
		}
#endif

#ifdef CCCAM_SRV
		else if (!strcmp(str,"F")) {
link_cccam_client:
			if (!cccam) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Skip F line, undefined CCcam Server\n",file->nbline,iparser-currentline);
				continue;
			}
			// F : user pass <downhops> <uphops>
			parse_spaces();
			if ((*iparser!=':')&&(*iparser!='=')) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
				continue;
			} else iparser++;
			struct cc_client_data *cli = malloc( sizeof(struct cc_client_data) );
			memset(cli, 0, sizeof(struct cc_client_data) );
			// init Default
			cli->dnhops = 0;
			cli->uphops = 0;
			cli->dcwcheck = cfg->cccam.dcwcheck;
			// <user> <pass> <downhops> <uphops> { <CardserverPort>,... }
			parse_str(cli->user);
			cli->userhash = hashCode( (unsigned char *)cli->user, strlen(cli->user) );
			parse_str(cli->pass);
			// TODO: Check for same user 
			if (parse_int(str)) {
				cli->dnhops = atoi(str);
				if (parse_int(str)) {
					cli->uphops = atoi(str);
				}
			}

			cli->sharelimits[0].caid = 0xFFFF;
			parse_spaces();
			if (*iparser=='{') { // Get Ports List & User Info
				iparser++;
				parse_spaces();
				if ( (*iparser>='0')&&(*iparser<='9') ) {
					i = 0;
					while (i<MAX_CSPORTS) {
						if ( parse_int(str)>0 ) {
							// check for uphops
							if (i==0) {
								parse_spaces();
								if (*iparser==':') {
									iparser++;
									cli->uphops = atoi(str);
									continue;
								}
							}
							// check for port
							cli->csport[i] = atoi(str);
							int j;
							for (j=0; j<i; j++) if ( cli->csport[j] && (cli->csport[j]==cli->csport[i]) ) break;
							if (j>=i) i++; else cli->csport[i] = 0;
						}
						else break;
						parse_spaces();
						if (*iparser==',') iparser++;
					}
				}
				else {
					while (1) {
						parse_spaces();
						if (*iparser=='}') break;
						// NAME1=value1; Name2=Value2 ... }
						parse_value(str,"\r\n\t =");
						//printf(" NAME: '%s'\n", str);
						// '='
						parse_spaces();
						if (*iparser!='=') break;
						iparser++;
						// Value
						// Check for PREDEFINED names
						if (!strcmp(str,"profiles")) {
							i = 0;
							while (i<MAX_CSPORTS) {
								if ( parse_int(str)>0 ) {
									// check for port
									int n = cli->csport[i] = atoi(str);
									int j;
									for (j=0; j<i; j++) if ( cli->csport[j] && (cli->csport[j]==n) ) break;
									if (j>=i) { 
										cli->csport[i] = n;
										i++;
									}
								}
								else break;
								parse_spaces();
								if (*iparser==',') iparser++;
							}
						}

						else if (!strcmp(str,"nodeid")) {
							if ( parse_hex(str)==16 ) hex2array( str, cli->option.nodeid );
						}
						else if (!strcmp(str,"version")) {
							parse_str(str);
							for(i=0; cc_version[i]; i++) {
								if ( !strcmp(cc_version[i],str) ) {
									strcpy(cli->option.version,cc_version[i]);
									break;
								}
							}
						}

						else if (!strcmp(str,"shares")) parse_option_shares( cli->sharelimits );
#ifdef CHECK_NEXTDCW
						else if (!strcmp(str,"dcwcheck")) cli->dcwcheck = parse_boolean();
#endif
#ifdef CACHEEX
						else if (!strcmp(str,"cacheex_mode")) {
							if (parse_hex(str)) cli->cacheex_mode = hex2int(str);
						}
#endif
						else {
							struct client_info_data *info = malloc( sizeof(struct client_info_data) );
							strcpy(info->name, str);
							parse_spaces();
							parse_value(str,"\r\n;}");
							for(i=strlen(str)-1; ( (str[i]==' ')||(str[i]=='\t') ) ; i--) str[i] = 0; // Remove spaces
							//printf(" VALUE: '%s'\n", str);
							strcpy(info->value, str);
							info->next = cli->info;
							cli->info = info;
						}
						parse_spaces();
						if (*iparser==';') iparser++; else break;
					}
					// Set Info Data
					struct client_info_data *info = cli->info;
					while (info) {
						strcpy(str,info->name);
						uppercase(str);
						if (!strcmp(str,"NAME")) cli->realname = info->value;
#ifdef EXPIREDATE
						else if ( !strcmp(str,"ENDDATE") || !strcmp(str,"EXPIRE") ) {
							if ( (info->value[4]=='-')&&(info->value[7]=='-') ) strptime(  info->value, "%Y-%m-%d %H", &cli->enddate);
							else if ( (info->value[2]=='-')&&(info->value[5]=='-') ) strptime(  info->value, "%d-%m-%Y %H", &cli->enddate);
 						}
#endif
						else if (!strcmp(str,"HOST")) {
							cli->host = add_host(cfg,info->value);
 						}
						info = info->next;
					}
				}
				if (*iparser!='}') mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): '}' expected\n",file->nbline,iparser-currentline);
			}

			cli->handle = -1;
			cfg_addcccamclient(cccam,cli);
		}
#endif

		//else if (!strcmp(str,"NODEID")) {
		//	parse_spaces();
		//	if ((*iparser!=':')&&(*iparser!='=')) {
		//		mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
		//		continue;
		//	} else iparser++;
		//	if ( parse_hex(str)==16 ) hex2array( str, cfg->nodeid );
		//}

#ifdef CCCAM
		else if (!strcmp(str,"CCCAM")) {
			parse_name(str);
			uppercase(str);
			if (!strcmp(str,"VERSION")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_str(str);
				for(i=0; cc_version[i]; i++)
					if ( !strcmp(cc_version[i],str) ) {
						strcpy(cfg->cccam.version,cc_version[i]);
						sprintf(cfg->cccam.build, "%d", cc_build[i]);
						break;
					}
			}

			else if (!strcmp(str,"DCW")) {
				parse_name(str);
				uppercase(str);
				if (!strcmp(str,"CHECK")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0),"':' expected\n");
						continue;
					} else iparser++;
					cfg->cccam.dcwcheck = parse_boolean();
				}
			}

#ifdef CCCAM_CLI
			else if (!strcmp(str,"SERVER")) {
				goto link_cccam_server;
			}
#endif

#ifdef CCCAM_SRV
			else if (!strcmp(str,"USER")) {
				goto link_cccam_client;
			}
			else if (!strcmp(str,"PORT")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_int(str);

				// Create New
				cccam = malloc( sizeof(struct cccam_server_data) );
				init_cccamserver(cccam);
				cccam->id = 0; //cfg->cccam.serverid++;
				cccam->port = atoi(str);
				cccam->next = NULL;
				// Add to config
				cfg_addcccamserver(cfg, cccam);
			}
			else if (!strcmp(str,"PROFILES")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				for(i=0;i<MAX_CSPORTS;i++) {
					if ( parse_int(str)>0 ) {
						cfg->cccam.csport[i] = atoi(str);
					}
					else break;
					parse_spaces();
					if (*iparser==',') iparser++;
				}
			}

			else if (!strcmp(str,"KEEPALIVE")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				cfg->cccam.keepalive = parse_boolean();
			}
#endif
		}
#endif

#ifdef FREECCCAM_SRV
		else if (!strcmp(str,"FREECCCAM")) {
			parse_name(str);
			uppercase(str);
			if (!strcmp(str,"PORT")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_int(str);
				cfg->freecccam.server.port = atoi(str);
			}
			else if (!strcmp(str,"MAXUSERS")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_int(str);
				cfg->freecccam.maxusers = atoi(str);
			}
			else if (!strcmp(str,"USERNAME")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_str(cfg->freecccam.user);
			}
			else if (!strcmp(str,"PASSWORD")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_str(cfg->freecccam.pass);
			}
			else if (!strcmp(str,"PROFILES")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				for(i=0;i<MAX_CSPORTS;i++) {
					if ( parse_int(str)>0 ) {
						cfg->freecccam.csport[i] = atoi(str);
					}
					else break;
					parse_spaces();
					if (*iparser==',') iparser++;
				}
			}
		}
#endif

#ifdef MGCAMD_SRV
		else if ( !strcmp(str,"MG")||!strcmp(str,"MGUSER") ) {
link_mgcamd_user:
			if (!mgcamd) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Skip MGUSER, undefined Mgcamd Server\n",file->nbline,iparser-currentline);
				continue;
			}
			parse_spaces();
			if ((*iparser!=':')&&(*iparser!='=')) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
				continue;
			} else iparser++;
			struct mg_client_data *cli = malloc( sizeof(struct mg_client_data) );
			memset(cli, 0, sizeof(struct mg_client_data) );
			// init Default
			cli->dcwcheck = cfg->mgcamd.dcwcheck;
			// <user> <pass> { <CardserverPort>,... }
			parse_str(cli->user);
			cli->userhash = hashCode( (unsigned char *)cli->user, strlen(cli->user) );
			parse_str(cli->pass);
			// TODO: Check for same user 
			cli->sharelimits[0].caid = 0xFFFF;
			parse_spaces();
			if (*iparser=='{') { // Get Ports List & User Info
				iparser++;
				parse_spaces();
				if ( (*iparser>='0')&&(*iparser<='9') ) {
					i = 0;
					while (i<MAX_CSPORTS) {
						if ( parse_int(str)>0 ) {
							// check for port
							cli->csport[i] = atoi(str);
							int j;
							for (j=0; j<i; j++) if ( cli->csport[j] && (cli->csport[j]==cli->csport[i]) ) break;
							if (j>=i) i++; else cli->csport[i] = 0;
						}
						else break;
						parse_spaces();
						if (*iparser==',') iparser++;
					}
				}
				else {
					while (1) {
						parse_spaces();
						if (*iparser=='}') break;
						// NAME1=value1; Name2=Value2 ... }
						parse_value(str,"\r\n\t =");
						//printf(" NAME: '%s'\n", str);
						// '='
						parse_spaces();
						if (*iparser!='=') break;
						iparser++;
						// Value
						// Check for PREDEFINED names
						if (!strcmp(str,"profiles")) {
							i = 0;
							while (i<MAX_CSPORTS) {
								if ( parse_int(str)>0 ) {
									// check for port
									int n = cli->csport[i] = atoi(str);
									int j;
									for (j=0; j<i; j++) if ( cli->csport[j] && (cli->csport[j]==n) ) break;
									if (j>=i) { 
										cli->csport[i] = n;
										i++;
									}
								}
								else break;
								parse_spaces();
								if (*iparser==',') iparser++;
							}
						}
#ifdef CHECK_NEXTDCW
						else if (!strcmp(str,"dcwcheck")) cli->dcwcheck = parse_boolean();
#endif
						else if (!strcmp(str,"shares")) parse_option_shares( cli->sharelimits );
						else {
							struct client_info_data *info = malloc( sizeof(struct client_info_data) );
							strcpy(info->name, str);
							parse_spaces();
							parse_value(str,"\r\n;}");
							for(i=strlen(str)-1; ( (str[i]==' ')||(str[i]=='\t') ) ; i--) str[i] = 0; // Remove spaces
							//printf(" VALUE: '%s'\n", str);
							strcpy(info->value, str);
							info->next = cli->info;
							cli->info = info;
						}
						parse_spaces();
						if (*iparser==';') iparser++; else break;
					}
					// Set Info Data
					struct client_info_data *info = cli->info;
					while (info) {
						strcpy(str,info->name);
						uppercase(str);
						if (!strcmp(str,"NAME")) cli->realname = info->value;
#ifdef EXPIREDATE
						else if ( !strcmp(str,"ENDDATE") || !strcmp(str,"EXPIRE") ) {
							if (info->value[4]=='-') strptime(  info->value, "%Y-%m-%d %H", &cli->enddate);
							else strptime(  info->value, "%d-%m-%Y:%H", &cli->enddate);
 						}
#endif
						else if (!strcmp(str,"HOST")) cli->host = add_host(cfg,info->value);
						info = info->next;
					}
				}	
				if (*iparser!='}') mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): '}' expected\n",file->nbline,iparser-currentline);
			}

			cli->handle = -1;
			cfg_addmgcamdclient(mgcamd,cli);
		}
		else if (!strcmp(str,"MGCAMD")) {
			parse_name(str);
			uppercase(str);
			if (!strcmp(str,"PORT")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_int(str);
				// Create New
				mgcamd = malloc( sizeof(struct mgcamdserver_data) );
				init_mgcamdserver(mgcamd);
				mgcamd->id = 0; //cfg->mgcamd.serverid++;
				mgcamd->port = atoi(str);
				mgcamd->next = NULL;
				// Add to config
				cfg_addmgcamdserver(cfg, mgcamd);
			}
			else if (!strcmp(str,"USER")) {
				goto link_mgcamd_user;
			}
			else if (!strcmp(str,"KEY")) {
				if (!mgcamd) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Skip MGCAMD KEY, undefined Mgcamd Server\n",file->nbline,iparser-currentline);
					continue;
				}
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				for(i=0; i<14; i++)
					if ( parse_hex(str)!=2 ) {
						memcpy( mgcamd->key, defdeskey, 14);
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Error reading DES-KEY\n",file->nbline,iparser-currentline);
						break;
					} 
					else {
						mgcamd->key[i] = hex2int(str);
					}
			}
			else if (!strcmp(str,"DCW")) {
				parse_name(str);
				uppercase(str);
				if (!strcmp(str,"CHECK")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0),"':' expected\n");
						continue;
					} else iparser++;
					cfg->mgcamd.dcwcheck = parse_boolean();
				}
			}
			else if (!strcmp(str,"PROFILES")) {
				if (!mgcamd) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Skip MGCAMD PROFILES, undefined Mgcamd Server\n",file->nbline,iparser-currentline);
					continue;
				}
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				for(i=0;i<MAX_CSPORTS;i++) {
					if ( parse_int(str)>0 ) {
						mgcamd->csport[i] = atoi(str);
					}
					else break;
					parse_spaces();
					if (*iparser==',') iparser++;
				}
			}
			else if (!strcmp(str,"KEEPALIVE")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				cfg->mgcamd.keepalive = parse_boolean();
			}
		}
#endif

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

#ifndef PUBLIC
		else if (!strcmp(str,"HOST")) {
			parse_spaces();
			if ((*iparser!=':')&&(*iparser!='=')) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
				continue;
			} else iparser++;
			parse_str(str);
			cfg->srvhost = add_host(cfg, str);
		}
#endif

#ifdef CACHEEX
		else if ( !strcmp(str,"CACHEEX") ) {
			parse_name(str);
			uppercase(str);
			if (!strcmp(str,"VALIDECMTIME")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_int(str);
				if (cardserver) {
					cardserver->option.cacheexvalidtime = atoi(str);
					if ( cardserver->option.cacheexvalidtime>7000 ) cardserver->option.cacheexvalidtime = 7000;
				}
			}
			else if (!strcmp(str,"MAXHOP")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_int(str);
				if (cardserver) {
					cardserver->option.cacheex.maxhop = atoi(str);
					if ( cardserver->option.cacheex.maxhop<1 ) cardserver->option.cacheex.maxhop = 1;
					else if ( cardserver->option.cacheex.maxhop>2 ) cardserver->option.cacheex.maxhop = 2;
				}
			}
		}
#endif

		else if (!strcmp(str,"CACHE")) {
			parse_name(str);
			uppercase(str);
			if (!strcmp(str,"PORT")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_int(str);
				// Create New Server
				cache = malloc( sizeof(struct cacheserver_data) );
				init_cacheserver(cache);
				cache->id = 0; // set id's at the end
				cache->port = atoi(str);
				cache->next = NULL;
				// Add to config
				cfg_addcacheserver(cfg, cache);
			}
			else if (!strcmp(str,"PEER")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				// must check for reuse of same user
				struct cachepeer_data *peer = malloc( sizeof(struct cachepeer_data) );
				memset(peer,0,sizeof(struct cachepeer_data) );
				peer->flags = FLAG_CACHE_SENDREQ | FLAG_CACHE_SENDREP;
				// default
				peer->autoadd = 1;
				parse_name(str);
				peer->host = add_host(cfg, str);
				parse_spaces();
				if ( *(iparser)==':' ) iparser++;
				parse_int(str);
				peer->port = atoi(str);
				if (parse_bin(str)) peer->fblock0onid = str[0]=='1';
#ifndef PUBLIC
				peer->sharelimits[0].caid = 0xFFFF;
#endif
				parse_spaces();
				if (*iparser=='{') { // Get Ports List
					iparser++;
					//
					while (1) {
						parse_spaces();
						if (*iparser=='}') break;
						// NAME1=value1; Name2=Value2 ... }
						parse_value(str,"\r\n\t =");
						// '='
						parse_spaces();
						if (*iparser!='=') {
							mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(,%d): '=' expected\n",iparser-currentline);
							break;
						}
						iparser++;
						// Value
						// Check for PREDEFINED names
						if (!strcmp(str,"csp")) {
							peer->csp = parse_boolean();
						}
						else if (!strcmp(str,"autoadd")) {
							peer->autoadd = parse_boolean();
						}
						else if (!strcmp(str,"sendreq")) {
							if (parse_boolean()) peer->flags |= FLAG_CACHE_SENDREQ; else peer->flags &= ~FLAG_CACHE_SENDREQ;
						}
#ifndef PUBLIC
						else if (!strcmp(str,"fwd")) {
							peer->fwd = parse_boolean();
						}
						else if (!strcmp(str,"sendrep")) {
							if (parse_boolean()) peer->flags |= FLAG_CACHE_SENDREP; else peer->flags &= ~FLAG_CACHE_SENDREP;
						}
						else if (!strcmp(str,"shares")) parse_option_shares( peer->sharelimits );
#endif
						parse_spaces();
						if (*iparser==';') iparser++; else break;
					}
					if (*iparser!='}') mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): '}' expected\n",file->nbline,iparser-currentline);
				}
				peer->reqnb=0;
				peer->reqnb=0;
				peer->hitnb=0;
				cfg_addcachepeer(cache, peer);
			}
			else if (!strcmp(str,"TIMEOUT")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_int(str);
				if (cardserver) {
					cardserver->option.cachetimeout = atoi(str);
					if (cardserver->option.cachetimeout<0) cardserver->option.cachetimeout = 0;
					else if (cardserver->option.cachetimeout>5000) cardserver->option.cachetimeout = 5000;
				}
				else {
					defaultcs.option.cachetimeout = atoi(str);
					if (defaultcs.option.cachetimeout<0) defaultcs.option.cachetimeout = 0;
					else if (defaultcs.option.cachetimeout>5000) defaultcs.option.cachetimeout=5000;
				}
			}
			else if (!strcmp(str,"ALIVETIME")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue; 
				} else iparser++;
				if ( parse_int(str) ) {
					int x = atoi(str);
					if (x<5) x = 5;
					else if (x>45) x = 45;
					cfg->cache.alivetime = x * 1000;
				}
				else mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Invalid integer (ALIVETIME)\n",file->nbline,iparser-currentline);
			}
			else if (!strcmp(str,"AUTOADD")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue; 
				} else iparser++;
				cfg->cache.autoadd = parse_boolean();
				if (cfg->cache.autoadd) {
					parse_spaces();
					if (*iparser==',') iparser++;
					cfg->cache.autoenable = parse_boolean();
				}
			}
			else if (!strcmp(str,"THRESHOLD")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_int(str);
				cfg->cache.threshold = atoi(str);
				if (cfg->cache.threshold<1) cfg->cache.threshold = 1;
				else if (cfg->cache.threshold>30) cfg->cache.threshold = 30;
			}

			else if (!strcmp(str,"FILTER")) {
				parse_spaces();
				if ((*iparser==':')||(*iparser=='=')) {
					iparser++;
					cfg->cache.filter = parse_boolean();
					continue;
				}
				parse_name(str);
				uppercase(str);
				if (!strcmp(str,"TIME")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue; 
					} else iparser++;
					if ( parse_int(str) ) {
						int x = atoi(str);
						if (x<0) x = 0;
						else if (x>10) x = 10;
						cfg->cache.filtertime = x * 1000;
					}
					else mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Invalid integer (FILTER TIME)\n",file->nbline,iparser-currentline);
				}
			}
#ifndef PUBLIC
			else if (!strcmp(str,"DCWCHECK2")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue; 
				} else iparser++;
				cfg->cache.dcwcheck2 = parse_boolean();
			}

			else if (!strcmp(str,"DCWCHECK3")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue; 
				} else iparser++;
				cfg->cache.dcwcheck3 = parse_boolean();
			}
#endif

			else if (!strcmp(str,"FORWARD")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue; 
				} else iparser++;
				cfg->cache.forward = parse_boolean();
			}

			else if (!strcmp(str,"SENDREQ")) {
				if (!cardserver) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Skip CACHE RESENDREQ, undefined profile\n",file->nbline,iparser-currentline);
					continue;
				}
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue; 
				} else iparser++;
				parse_name(str);
				uppercase(str);
				if (!strcmp(str,"NO")) cardserver->option.cachesendreq = 0;
				else if (!strcmp(str,"YES")) cardserver->option.cachesendreq = 1;
			}

#ifndef PUBLIC
			else if (!strcmp(str,"STATIC")) {
				if (!cardserver) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Skip CACHE STATIC, undefined profile\n",file->nbline,iparser-currentline);
					continue;
				}
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue; 
				} else iparser++;
				parse_name(str);
				uppercase(str);
				if (!strcmp(str,"NO")) cardserver->option.cachestatic = 0;
				else if (!strcmp(str,"YES")) cardserver->option.cachestatic = 1;
			}
			else if (!strcmp(str,"RESENDREQ")) {
				if (!cardserver) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Skip CACHE RESENDREQ, undefined profile\n",file->nbline,iparser-currentline);
					continue;
				}
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue; 
				} else iparser++;
				parse_name(str);
				uppercase(str);
				if (!strcmp(str,"NO")) cardserver->option.cacheresendreq = 0;
				else if (!strcmp(str,"YES")) cardserver->option.cacheresendreq = 1;
			}
			else if (!strcmp(str,"SENDREP")) {
				if (!cardserver) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Skip CACHE RESENDREQ, undefined profile\n",file->nbline,iparser-currentline);
					continue;
				}
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue; 
				} else iparser++;
				parse_name(str);
				uppercase(str);
				if (!strcmp(str,"NO")) cardserver->option.cachesendrep = 0;
				else if (!strcmp(str,"YES")) cardserver->option.cachesendrep = 1;
			}
#endif

		}


///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

		else if (!strcmp(str,"CAID")) {
			if (!cardserver) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Skip CAID, undefined profile\n",file->nbline,iparser-currentline);
				continue;
			}
			parse_spaces();
			if ((*iparser!=':')&&(*iparser!='=')) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
				continue;
			} else iparser++;
			parse_hex(str);
			cardserver->card.caid = hex2int( str );
			//mlogf(LOGDEBUG,getdbgflag(DBG_CONFIG,0,0)," *caid %04X\n",cardserver->card.caid);
		}
		else if (!strcmp(str,"PROVIDERS")) {
			if (!cardserver) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Skip PROVIDERS, undefined profile\n",file->nbline,iparser-currentline);
				continue;
			}
			parse_spaces();
			if ((*iparser!=':')&&(*iparser!='=')) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
				continue;
			} else iparser++;
			cardserver->card.nbprov = 0;
			for(i=0;i<16;i++) {
				if ( parse_hex(str)>0 ) {
					cardserver->card.prov[i].id = hex2int( str );
					cardserver->card.nbprov++;
				}
				else break;
				parse_spaces();
				if (*iparser==',') iparser++;
			}
			//for(i=0;i<cardserver->card.nbprov;i++) mlogf(LOGDEBUG,getdbgflag(DBG_CONFIG,0,0)," *provider %d = %06X\n",i,cardserver->card.prov[i].id); 
		}

		else if (!strcmp(str,"USER")) {
			parse_spaces();
			if ((*iparser!=':')&&(*iparser!='=')) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
				continue;
			} else iparser++;

			if (cardserver) {
				// must check for reuse of same user
				usr = malloc( sizeof(struct cs_client_data) );
				memset(usr,0,sizeof(struct cs_client_data) );
				cs_addnewcamdclient(cardserver, usr);
				// init default
				usr->handle = -1;
				usr->flags |= FLAG_DEFCONFIG;
#ifdef CHECK_NEXTDCW
				usr->dcwcheck = cfg->newcamd.dcwcheck;
#endif
				//
				parse_str(usr->user);
				usr->userhash = hashCode( (unsigned char *)usr->user, strlen(usr->user) );
				parse_str(usr->pass);
				// USER: name pass { CAID:PROVIDER1,PROVIDER2,... } 
				if ( parse_expect('{') ) { // Read Caid Providers
					while (1) {
						parse_spaces();
						if (*iparser=='}') break;
						// NAME1=value1; Name2=Value2 ... }
						parse_value(str,"\r\n\t =");
						// '='
						parse_spaces();
						if (*iparser!='=') {
							mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): '=' expected\n",file->nbline,iparser-currentline);
							break;
						}
						iparser++;
						// Value
						// Check for PREDEFINED names
						if (!strcmp(str,"card")) {
							if (parse_hex(str)) {
								usr->card.caid = hex2int(str);
								if (!parse_expect(':')) {
									usr->card.caid = 0;
									mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
									break;
								}
								usr->card.nbprov = 0;
								for(i=0;i<16;i++) {
									if ( parse_hex(str)>0 ) {
										usr->card.prov[i] = hex2int( str );
										usr->card.nbprov++;
									}
									else break;
									parse_spaces(); if (*iparser==',') iparser++;
								}
							}
						}
#ifdef CHECK_NEXTDCW
						else if (!strcmp(str,"dcwcheck")) usr->dcwcheck = parse_boolean();
#endif

						parse_spaces();
						if (*iparser==';') iparser++; else break;
					}
					if (!parse_expect('}')) {
						usr->card.caid = 0;
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): '}' expected\n",file->nbline,iparser-currentline);
						continue;
					}
				}
			}
			else { // global user
				struct global_user_data *gl = malloc( sizeof(struct global_user_data) );
				memset(gl,0,sizeof(struct global_user_data) );
				/// ADD
				struct global_user_data *tmp = guser;
				if (tmp) {
					while (tmp->next) tmp = tmp->next;
					tmp->next = gl;
				} else guser = gl;
				gl->next = NULL;
#ifdef CHECK_NEXTDCW
				gl->dcwcheck = cfg->newcamd.dcwcheck;
#endif
				//
				parse_str(gl->user);
				parse_str(gl->pass);
				// user: username pass { csports }
				parse_spaces();

				if (*iparser=='{') { // Get Ports List & User Info
					iparser++;
					parse_spaces();
					if ( (*iparser>='0')&&(*iparser<='9') ) {
						i = 0;
						while (i<MAX_CSPORTS) {
							if ( parse_int(str)>0 ) {
								// check for port
								gl->csport[i] = atoi(str);
								int j;
								for (j=0; j<i; j++) if ( gl->csport[j] && (gl->csport[j]==gl->csport[i]) ) break;
								if (j>=i) i++; else gl->csport[i] = 0;
							}
							else break;
							parse_spaces();
							if (*iparser==',') iparser++;
						}
					}
					else {
						while (1) {
							parse_spaces();
							if (*iparser=='}') break;
							// NAME1=value1; Name2=Value2 ... }
							parse_value(str,"\r\n\t =");
							// '='
							parse_spaces();
							if (*iparser!='=') break;
							iparser++;
							// Value
							// Check for PREDEFINED names
							if (!strcmp(str,"profiles")) {
								i = 0;
								while (i<MAX_CSPORTS) {
									if ( parse_int(str)>0 ) {
										// check for port
										int n = gl->csport[i] = atoi(str);
										int j;
										for (j=0; j<i; j++) if ( gl->csport[j] && (gl->csport[j]==n) ) break;
										if (j>=i) { 
											gl->csport[i] = n;
											i++;
										}
									}
									else break;
									parse_spaces();
									if (*iparser==',') iparser++;
								}
							}
#ifdef CHECK_NEXTDCW
							else if (!strcmp(str,"dcwcheck")) gl->dcwcheck = parse_boolean();
#endif
							parse_spaces();
							if (*iparser==';') iparser++; else break;
						}
					}
					if (*iparser!='}') mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): '}' expected\n",file->nbline,iparser-currentline);
				}
			}
		}

		else if (!strcmp(str,"ECM")) {
			if (!cardserver) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Skip ECM, undefined profile\n",file->nbline,iparser-currentline);
				continue;
			}
			parse_name(str);
			uppercase(str);
			if (!strcmp(str,"LENGTH")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;

				int count = 0;
				while ( parse_hex(str)>0 ) {
					cardserver->ecmlen[count] = hex2int(str);
					count++;
					if (count>29) break;
					parse_spaces();
					if (*iparser==',') iparser++;
				}
				cardserver->ecmlen[count] = 0;
			}
			else if (!strcmp(str,"CHECK")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					parse_name(str);
					uppercase(str);
					if (!strcmp(str,"LENGTH")) {
						parse_spaces();
						if ((*iparser!=':')&&(*iparser!='=')) {
							mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
							continue;
						} else iparser++;
						cardserver->option.checkecmlength = parse_boolean();
					}
				}
				else {
					iparser++;
					cardserver->option.checkecm = parse_boolean();
				}
			}
		}

		else if (!strcmp(str,"DCW")) {
			if (!cardserver) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Skip DCW, undefined profile\n",file->nbline,iparser-currentline);
				continue;
			}
			parse_name(str);
			uppercase(str);
			if (!strcmp(str,"TIMEOUT")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue; 
				} else iparser++;
				parse_int(str);
				parse_spaces();
				cardserver->option.dcw.timeout = atoi(str);
				if (cardserver->option.dcw.timeout<300) cardserver->option.dcw.timeout=300;
				else if (cardserver->option.dcw.timeout>9999) cardserver->option.dcw.timeout=9999;
			}
			else if (!strcmp(str,"MAXFAILED")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_int(str);
				parse_spaces();
				cardserver->option.maxfailedecm = atoi(str);
				if (cardserver->option.maxfailedecm<0) cardserver->option.maxfailedecm=0;
				else if (cardserver->option.maxfailedecm>100) cardserver->option.maxfailedecm=100;
			}
			else if (!strcmp(str,"RETRY")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_int(str);
				parse_spaces();
				cardserver->option.dcw.retry = atoi(str);
				if (cardserver->option.dcw.retry<0) cardserver->option.dcw.retry=0;
				else if (cardserver->option.dcw.retry>5) cardserver->option.dcw.retry=5;
			}

#ifdef CHECK_NEXTDCW
			else if (!strcmp(str,"CHECK")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				cardserver->option.dcw.check = parse_boolean();
			}
			else if (!strcmp(str,"HALFNULLED")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				cardserver->option.dcw.halfnulled = parse_boolean();
			}
#ifdef DCWSWAP
			else if (!strcmp(str,"SWAP")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				cardserver->option.dcw.swap = parse_boolean();
			}
#endif
#endif
		}

		else if (!strcmp(str,"SERVER")) {
			if (!cardserver) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Skip SERVER, undefined profile\n",file->nbline,iparser-currentline);
				continue;
			}
			parse_name(str);
			uppercase(str);
			if (!strcmp(str,"TIMEOUT")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_int(str);
				cardserver->option.server.timeout = atoi(str);
				if ( (cardserver->option.server.timeout<300)||(cardserver->option.server.timeout>10000) ) cardserver->option.server.timeout=300;
			}
			else if (!strcmp(str,"MAX")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_int(str);
				cardserver->option.server.max = atoi(str);
				if (cardserver->option.server.max<0) cardserver->option.server.max=0;
				else if (cardserver->option.server.max>10) cardserver->option.server.max=10;
			}
			else if (!strcmp(str,"INTERVAL")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_int(str);
				cardserver->option.server.interval = atoi(str);
				if (cardserver->option.server.interval<100) cardserver->option.server.interval=100;
				else if (cardserver->option.server.interval>3000) cardserver->option.server.interval=3000;
			}
			else if (!strcmp(str,"VALIDECMTIME")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_int(str);
				cardserver->option.server.validecmtime = atoi(str);
				if (cardserver->option.server.validecmtime>5000) cardserver->option.server.validecmtime=5000;
			}
			else if (!strcmp(str,"FIRST")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_int(str);
				cardserver->option.server.first = atoi(str);
				if (cardserver->option.server.first<0) cardserver->option.server.first = 0;
				else if (cardserver->option.server.first>3) cardserver->option.server.first = 3;
			}
#ifndef PUBLIC
			else if ( (!strcmp(str,"ECMTIME"))||(!strcmp(str,"TIMEPERECM")) ) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_int(str);
				cardserver->option.server.timeperecm = atoi(str);
				if (cardserver->option.server.timeperecm>5000) cardserver->option.server.timeperecm=5000;
			}
			else if (!strcmp(str,"THRESHOLD")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_int(str);
				cardserver->option.server.threshold = atoi(str);
				if (cardserver->option.server.threshold<0) cardserver->option.server.threshold = 0;
				else if (cardserver->option.server.threshold>30) cardserver->option.server.threshold = 30;
			}
			else if (!strcmp(str,"SEND")) {
				parse_name(str);
				uppercase(str);
				if (!strcmp(str,"SID")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					parse_int(str);
					cardserver->option.cssendsid = atoi(str);
				}
				else if (!strcmp(str,"CAID")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					parse_int(str);
					cardserver->option.cssendcaid = atoi(str);
				}
				else if (!strcmp(str,"PROVID")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					parse_int(str);
					cardserver->option.cssendprovid = atoi(str);
				}
				else mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): cardserver send variable expected\n",file->nbline,iparser-currentline);
			}
#endif
			else mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): cardserver variable expected\n",file->nbline,iparser-currentline);
		}

		else if ( !strcmp(str,"RETRY") ) {
			if (!cardserver) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Skip RETRY, undefined profile\n",file->nbline,iparser-currentline);
				continue;
			}
			parse_name(str);
			uppercase(str);
			if (!strcmp(str,"NEWCAMD")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_int(str);
				cardserver->option.retry.newcamd = atoi(str);
				if (cardserver->option.retry.newcamd<0) cardserver->option.retry.newcamd=0;
				else if (cardserver->option.retry.newcamd>3) cardserver->option.retry.newcamd=3;
			}
			else if (!strcmp(str,"CCCAM")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_int(str);
				cardserver->option.retry.cccam = atoi(str);
				if (cardserver->option.retry.cccam<0) cardserver->option.retry.cccam=0;
				else if (cardserver->option.retry.cccam>10) cardserver->option.retry.cccam=10;
			}
			else mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): cardserver variable expected\n",file->nbline,iparser-currentline);
		}

		else if (!strcmp(str,"RADEGAST")) {
			if (!cardserver) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Skip PORT, undefined profile\n",file->nbline,iparser-currentline);
				continue;
			}
			parse_name(str);
			uppercase(str);
			if (!strcmp(str,"SERVER")) {
				goto link_radegast_server;
			}
#ifdef RADEGAST_SRV
			else if (!strcmp(str,"PORT")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_int(str);
				cardserver->radegast.port = atoi(str);
			}
#endif
		}
		else if (!strcmp(str,"ONID")) {
			if (!cardserver) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Skip ONID, undefined profile\n",file->nbline,iparser-currentline);
				continue;
			}
			parse_spaces();
			if ((*iparser!=':')&&(*iparser!='=')) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
				continue;
			} else iparser++;
			parse_hex(str);
			cardserver->option.onid = hex2int(str);
		}

		else if ( !strcmp(str,"ACCEPT") ) {
			parse_name(str);
			uppercase(str);
			if (!strcmp(str,"NULL")) {
				if (!cardserver) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Skip ACCEPT, undefined profile\n",file->nbline,iparser-currentline);
					continue;
				}
				parse_name(str);
				uppercase(str);
				if (!strcmp(str,"SID")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					cardserver->option.faccept0sid = parse_boolean();
				}
				else if (!strcmp(str,"CAID")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					cardserver->option.faccept0caid = parse_boolean();
				}
				else if (!strcmp(str,"PROVIDER")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					cardserver->option.faccept0provider = parse_boolean();
				}

				else if (!strcmp(str,"ONID")) {
					parse_spaces();
					if ((*iparser!=':')&&(*iparser!='=')) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
						continue;
					} else iparser++;
					cfg->cache.faccept0onid = parse_boolean();
				}
			}
		}

		else if (!strcmp(str,"DISABLE")) {
			if (!cardserver) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Skip DISABLE, undefined profile\n",file->nbline,iparser-currentline);
				continue;
			}
			parse_name(str);
			uppercase(str);
			if (!strcmp(str,"CCCAM")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				cardserver->option.fallowcccam = !parse_boolean();
			}
			else if (!strcmp(str,"NEWCAMD")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				cardserver->option.fallownewcamd = !parse_boolean();
			}
			else if (!strcmp(str,"RADEGAST")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				cardserver->option.fallowradegast = !parse_boolean();
			}
			else if (!strcmp(str,"CACHE")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				cardserver->option.fallowcache = !parse_boolean();
			}
			/* else if (!strcmp(str,"SKIPCWC")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				cardserver->option.fallowskipcwc = !parse_boolean();
			}*/
#ifdef CACHEEX
			else if (!strcmp(str,"CACHEEX")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				cardserver->option.fallowcacheex = !parse_boolean();
			}
#endif
		}


		else if (!strcmp(str,"ENABLE")) {
			if (!cardserver) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Skip DISABLE, undefined profile\n",file->nbline,iparser-currentline);
				continue;
			}
			parse_name(str);
			uppercase(str);
			if (!strcmp(str,"CCCAM")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				cardserver->option.fallowcccam = parse_boolean();
			}
			else if (!strcmp(str,"NEWCAMD")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				cardserver->option.fallownewcamd = parse_boolean();
			}
			else if (!strcmp(str,"RADEGAST")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				cardserver->option.fallowradegast = parse_boolean();
			}
			else if (!strcmp(str,"CACHE")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				cardserver->option.fallowcache = parse_boolean();
			}
			/* else if (!strcmp(str,"SKIPCWC")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				cardserver->option.fallowskipcwc = parse_boolean();
			}*/
#ifdef CACHEEX
			else if (!strcmp(str,"CACHEEX")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				cardserver->option.fallowcacheex = parse_boolean();
			}
#endif
		}


		else if (!strcmp(str,"SHARE")) {
			if (!cardserver) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Skip DISABLE, undefined profile\n",file->nbline,iparser-currentline);
				continue;
			}
			parse_name(str);
			uppercase(str);
			if (!strcmp(str,"CCCAM")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				cardserver->option.fsharecccam = parse_boolean();
			}
			else if (!strcmp(str,"NEWCAMD")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				cardserver->option.fsharenewcamd = parse_boolean();
			}
			else if (!strcmp(str,"MGCAMD")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				cardserver->option.fsharemgcamd = parse_boolean();
			}
#ifndef PUBLIC
			else if (!strcmp(str,"EXPIRED")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				cardserver->option.fshareexpired = parse_boolean();
			}
#endif
		}

		else if (!strcmp(str,"BLOCK")) {
			parse_name(str);
			uppercase(str);
			if (!strcmp(str,"COUNTRY")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				memset( cfg->blockcountry, 0, sizeof(cfg->blockcountry) );
				int counter = 0;
				while (1) {
					parse_spaces();
					if ( parse_value(str, " ,;\t\r\n")!=2 ) break;
					uppercase(str);
					strcpy( cfg->blockcountry[counter], str);
					counter++;
					if (counter>=512) {
						mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): too many countries...\n",file->nbline,iparser-currentline);
						break;
					}
					parse_spaces();
					if (*iparser==',') iparser++;
				}
			}
		}

		else if (!strcmp(str,"SID")) {
			if (!cardserver) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Skip SID, undefined profile\n",file->nbline,iparser-currentline);
				continue;
			}
			parse_name(str);
			uppercase(str);
			if (!strcmp(str,"LIST")) {
				parse_spaces();
                int denylist = 0;
				if (*iparser=='!') {
					denylist = 1;
					iparser++;
				}
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;

				int count = 0;
				struct sid_chid_ecmlen_data *sids;
				if (!cardserver->sidlist.data) {
					sids = malloc ( sizeof(struct sid_chid_ecmlen_data) * MAX_SIDS );
					memset( sids, 0, sizeof(struct sid_chid_ecmlen_data) * MAX_SIDS );
					cardserver->sidlist.data = sids;
					cardserver->sidlist.deny = denylist;
				}
				else {
					count = cardserver->sidlist.total;
					sids = &(cardserver->sidlist.data[count]);
				}

				while ( parse_hex(str)>0 ) {
					sids->sid = hex2int(str);
					if (*iparser==':') { // CHID
						iparser++;
						if (parse_hex(str)>0) sids->chid = hex2int(str);
						if (*iparser==':') { // ECMLEN
							iparser++;
							if (parse_hex(str)>0) sids->ecmlen = hex2int(str);
						}
					}
					if (*iparser=='.') { // when cw1 cycle
						iparser++;
						if (parse_hex(str)>0) sids->cw1cycle = hex2int(str);
						//mlogf(LOGDEBUG,0,"sid%d %04x:%04x:%02x.%02x\n", count, sids->sid, sids->chid, sids->ecmlen, sids->cw1cycle );
					}

					for(i=0;i<count;i++) {
						if (sids->sid==cardserver->sidlist.data[i].sid) {
							memcpy( &(cardserver->sidlist.data[i]), sids, sizeof(struct sid_chid_ecmlen_data) );
							memset( sids,0, sizeof(struct sid_chid_ecmlen_data) );
							break;
						}
					}
					if (i>=count) {
						//mlogf(LOGDEBUG,getdbgflag(DBG_CONFIG,0,0),"sid%d %04x:%04x:%02x\n", count, sids->sid, sids->chid, sids->ecmlen );
						count++;
						sids++;
						if (count>=MAX_SIDS) {
							mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): too many sids...\n",file->nbline,iparser-currentline);
							break;
						}
					}
					parse_spaces();
					if (*iparser==',') iparser++;
				}
				sids->sid = 0;
				sids->chid = 0;
				cardserver->sidlist.total = count;
				// Arrange sid list by sid
				sid_arrange( cardserver->sidlist.data, cardserver->sidlist.total );
			}

			else if (!strcmp(str,"DENYLIST")) {
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				cardserver->sidlist.deny = parse_boolean();
			}

			else if (!strcmp(str,"FILE")) {
				parse_spaces();
                int denylist = 0;
				if (*iparser=='!') {
					denylist = 1;
					iparser++;
				}
				parse_spaces();
				if ((*iparser!=':')&&(*iparser!='=')) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
					continue;
				} else iparser++;
				parse_spaces();
				if (*iparser=='"') {
					if ( parse_quotes('"',str) ) {
						// parse file
					}
				}
				else {
					parse_name(str);
					uppercase(str);
					if (!strcmp(str,"CHANNELINFO")) {
						struct sid_chid_ecmlen_data *sids = NULL;

						struct chninfo_data *chn = cfg->chninfo;
						while (chn) {
							if (chn->caid==cardserver->card.caid) {
								int i;
								for ( i=0; i<cardserver->card.nbprov; i++) {
									if ( chn->prov==cardserver->card.prov[i].id ) {
										if ( cardserver->card.prov[i].sidlist.data==NULL ) {
											sids = malloc ( sizeof(struct sid_chid_ecmlen_data) * MAX_SIDS );
											memset( sids, 0, sizeof(struct sid_chid_ecmlen_data) * MAX_SIDS );
											cardserver->card.prov[i].sidlist.data = sids;
											cardserver->card.prov[i].sidlist.total = 0;
											cardserver->card.prov[i].sidlist.deny = denylist;
										} else sids = &(cardserver->card.prov[i].sidlist.data[ cardserver->card.prov[i].sidlist.total ]);
										// ADD
										sids->sid = chn->sid;
										sids->chid = 0;
										sids->cw1cycle = chn->cw1cycle;
										cardserver->card.prov[i].sidlist.total++;
										//printf(" sidlist: %04x:%06x:%04x\n", cardserver->card.caid, cardserver->card.prov[i].id, sids->sid );
										break;
									}
								}
							}
							chn = chn->next;
						}

						int i;
						for ( i=0; i<cardserver->card.nbprov; i++) {
							if ( cardserver->card.prov[i].sidlist.data ) {
								// Arrange sid list by sid
								sid_arrange( cardserver->card.prov[i].sidlist.data, cardserver->card.prov[i].sidlist.total );
							}
						}

					}

				}
			}

		}


///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

/*
		else if (!strcmp(str,"TRACE")) {
			parse_spaces();
			if ((*iparser!=':')&&(*iparser!='=')) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): ':' expected\n",file->nbline,iparser-currentline);
				continue;
			} else iparser++;
			
			if ( parse_bin(str)!=1 ) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): Error reading Trace\n",file->nbline,iparser-currentline);
				break;
			} 
			if (str[0]=='0') flag_debugtrace = 0;
			else if (str[0]=='1') {
				parse_str(trace.host);
				parse_int(str);
				trace.port = atoi(str);
				trace.ip = hostname2ip(trace.host);
				memset( &trace.addr, 0, sizeof(trace.addr) );
				trace.addr.sin_family = AF_INET;
				trace.addr.sin_addr.s_addr = trace.ip;
				trace.addr.sin_port = htons(trace.port);
				flag_debugtrace = 0;
				if (trace.port && trace.ip) {
					if (trace.sock<=0) trace.sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
					if (trace.sock>0) flag_debugtrace = 1;
				}
			}
			else {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): expected 0/1\n",file->nbline,iparser-currentline);
				break;
			}
		}
*/

	}

#ifdef FREECCCAM_SRV
	//Create clients
	for(i=0; i< cfg->freecccam.maxusers; i++) {
		struct cc_client_data *cli = malloc( sizeof(struct cc_client_data) );
		memset(cli, 0, sizeof(struct cc_client_data) );
		// init Default
		cli->id = i+1;
		cli->handle = -1;
		cli->dnhops = 0;
		cli->uphops = 0;
		cli->sharelimits[0].caid = 0xFFFF;
		cli->next = cfg->freecccam.server.client;
		cfg->freecccam.server.client = cli;
	}
#endif

// ADD GLOBAL USERS TO PROFILES
	struct global_user_data *gl = guser;
	while(gl) {
		struct cardserver_data *cs = cfg->cardserver;
		while(cs) {
			int i;
			for(i=0; i<MAX_CSPORTS; i++ ) {
				if (!gl->csport[i]) break;
				if (gl->csport[i]==cs->newcamd.port) {
					i=0;
					break;
				}
			}
			if (i==0) { // ADD TO PROFILE
				// must check for reuse of same user
				struct cs_client_data *usr = malloc( sizeof(struct cs_client_data) );
				memset(usr,0,sizeof(struct cs_client_data) );
				cs_addnewcamdclient(cs, usr);
				usr->handle = -1;
				usr->flags |= FLAG_DEFCONFIG;
				strcpy(usr->user, gl->user);
				usr->userhash = hashCode( (unsigned char *)usr->user, strlen(usr->user) );
				strcpy(usr->pass, gl->pass);
				usr->dcwcheck = gl->dcwcheck;
				// Setup global id
				 //usr->gid = cfg-
			}
			cs = cs->next;
		}
		struct global_user_data *oldgl = gl;
		gl = gl->next;
		free( oldgl );
	}

#ifndef PUBLIC
	read_cccam_nodeid(cfg);
#endif

//	read_chinfo(cfg);

	read_providers(cfg);
	read_ip2country(cfg);

	return 0;
}



///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
#ifndef PUBLIC
int read_cccam_nodeid( struct config_data *cfg )
{
	if (!cfg->cccam.server) return 0;

	FILE *fhandle;
	char str[128];
	// Open Config file
	fhandle = fopen("/var/etc/cccam.nodeid","rt");
	if (fhandle==0) {
		//mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config: file not found\n");
		return -1;
	}// else mlogf(LOGINFO,getdbgflag(DBG_CONFIG,0,0)," config: parsing file\n");
	// Read data
	while (!feof(fhandle))
	{
		if ( !fgets(currentline, 10239, fhandle) ) break;
		iparser = &currentline[0];
		parse_spaces();
		// get username
		parse_name(str);
		// search into db
		struct cc_client_data *cli = cfg->cccam.server->client;
		while (cli) {
			if (!strcmp(cli->user,str)) {
				// Read nodeid
				if ( parse_hex(str)==16 ) {
					hex2array( str, cli->option.nodeid );
					//printf(" update user nodeid %s %02x%02x%02x%02x%02x%02x%02x%02x\n", cli->user, cli->option.nodeid[0], cli->option.nodeid[1], cli->option.nodeid[2], cli->option.nodeid[3], cli->option.nodeid[4], cli->option.nodeid[5], cli->option.nodeid[6], cli->option.nodeid[7]);
				}
				break;
			}
			cli = cli->next;
		}
	}
	// close file
	fclose(fhandle);
	return 0;
}
#endif


///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

#ifdef TWIN

void twin_read_chninfo( struct config_data *cfg )
{
	int len,i;
	char str[255];
	FILE *fhandle;
	int nbline = 0;

	// Open Config file
	fhandle = fopen(cfg->twin.chninfo.fname,"rt");
	if (fhandle==0) {
		mlogf(LOGERROR,0," file not found '%s'\n",cfg->twin.chninfo.fname);
		return -1;
	} else mlogf(LOGINFO,0," config: parsing file '%s'\n",cfg->twin.chninfo.fname);

	// Init config data
	cfg->twin.chninfo.count = 0;

	while (!feof(fhandle))
	{
		if ( !fgets(currentline, 1023, fhandle) ) break;
		nbline++;
		iparser = &currentline[0];

		parse_spaces();
		if ( (*iparser=='#')||(*iparser==0)||(*iparser==13)||(*iparser==10) ) continue;

		if ( parse_hex(str)!=4 ) continue;

		cfg->twin.chninfo.data[cfg->twin.chninfo.count].caid = hex2int(str);

		parse_spaces();
		if (*iparser!=':') {
			mlogf(LOGERROR,0," config(%d,%d): ':' expected\n",nbline,iparser-currentline);
			continue;
		} else iparser++;
		parse_hex(&str[0]);
		cfg->twin.chninfo.data[cfg->twin.chninfo.count].prov = hex2int(str);

		parse_spaces();
		if (*iparser!=':') {
			mlogf(LOGERROR,0," config(%d,%d): ':' expected\n",nbline,iparser-currentline);
			continue;
		} else iparser++;
		parse_hex(str);
		cfg->twin.chninfo.data[cfg->twin.chninfo.count].sid = hex2int(str);

		parse_spaces();
		if (*iparser!=':') {
			mlogf(LOGERROR,0," config(%d,%d): ':' expected\n",nbline,iparser-currentline);
			continue;
		} else iparser++;
		parse_hex(str);
		cfg->twin.chninfo.data[cfg->twin.chninfo.count].deg = hex2int(str);

		parse_spaces();
		if (*iparser!=':') {
			mlogf(LOGERROR,0," config(%d,%d): ':' expected\n",nbline,iparser-currentline);
			continue;
		} else iparser++;
		parse_hex(str);
		cfg->twin.chninfo.data[cfg->twin.chninfo.count].freq = hex2int(str);

		parse_spaces();
		if (*iparser=='.') {
			iparser++;
			parse_hex(str);
			cfg->twin.chninfo.data[cfg->twin.chninfo.count].cw1cycle = hex2int(str);
		}

		parse_quotes( '"', str );
		str[63] = 0; // Overflow
		strcpy(cfg->twin.chninfo.data[cfg->twin.chninfo.count].name, str);

		//debug("%s -> %04x:%06x:%04x\n",chninfo[nbchninfo].name, chninfo[nbchninfo].caid,chninfo[nbchninfo].prov,chninfo[nbchninfo].sid);
		cfg->twin.chninfo.count++;
	}
	fclose(fhandle);
}

void twin_free_chinfo( struct config_data *cfg )
{
	cfg->twin.chninfo.count = 0;
}

#endif




///////////////////////////////////////////////////////////////////////////////

int read_chinfo( struct config_data *cfg )
{
	if (!cfg->channelinfo_file[0]) return 0;

	FILE *fhandle;
	char str[128];

	uint16_t caid,sid;
	uint32_t prov;
	uint8_t cw1cycle;
	int chncount = 0;

	int nbline = 0;
	// Open Config file
	fhandle = fopen(cfg->channelinfo_file,"rt");
	if (fhandle==0) {
		mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config: file not found '%s'\n",cfg->channelinfo_file);
		return -1;
	} else mlogf(LOGINFO,getdbgflag(DBG_CONFIG,0,0)," config: parsing file '%s'\n",cfg->channelinfo_file);

	while (!feof(fhandle))
	{
		if ( !fgets(currentline, 10239, fhandle) ) break;
		iparser = &currentline[0];
		nbline++;
		parse_spaces();

		if ( ((*iparser>='0')&&(*iparser<='9')) || ((*iparser>='a')&&(*iparser<='f')) || ((*iparser>='A')&&(*iparser<='F')) ) {
			parse_hex(str);
			caid = hex2int(str);
			parse_spaces();
			if (*iparser!=':') {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): caid ':' expected\n",nbline,iparser-currentline);
				continue;
			} else iparser++;
			parse_hex(str);
			prov = hex2int(str);
			parse_spaces();
			if (*iparser!=':') {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config(%d,%d): provid ':' expected\n",nbline,iparser-currentline);
				continue;
			} else iparser++;
			parse_hex(str);
			sid = hex2int(str);
			// ecmtag
			parse_spaces();
			cw1cycle = 0;
			if (*iparser=='.') {
				iparser++;
				if (parse_hex(str)==2) cw1cycle = hex2int(str);
			}
			//
			parse_spaces();
			if (*iparser=='"') {
				iparser++;
				char *end = iparser;
				while ( (*end!='"')&&(*end!='\n')&&(*end!='\r')&&(*end!=0) ) end++;
				if (end-iparser) {
					*end = 0;
					//strcpy(str,iparser);
					//mlogf(LOGDEBUG,getdbgflag(DBG_CONFIG,0,0),"%04x:%06x:%04x '%s'\n",caid,prov,sid,iparser);
					struct chninfo_data *chn = malloc( sizeof(struct chninfo_data) + strlen(iparser) + 1 );
					chn->sid = sid;
					chn->caid = caid;
					chn->prov = prov;
					chn->cw1cycle = cw1cycle;
					strcpy( chn->name, iparser );
					chn->next = cfg->chninfo;
					cfg->chninfo = chn;
					chncount++;
				}
			}
		}
	}
	fclose(fhandle);
	mlogf(LOGINFO,getdbgflag(DBG_CONFIG,0,0)," config: reading %d channels.\n", chncount);
	return 0;
}

void free_chinfo( struct config_data *cfg )
{
	if (cfg->chninfo) {
		struct chninfo_data *current = cfg->chninfo;
		cfg->chninfo = NULL;
		usleep(100000);
		while (current) {
			struct chninfo_data *next = current->next;
			free(current);
			current = next;
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

int isValidIp4 (char *str) {
    int segs = 0;   /* Segment count. */
    int chcnt = 0;  /* Character count within segment. */
    int accum = 0;  /* Accumulator for segment. */

    /* Catch NULL pointer. */

    if (str == NULL) return 0;

    /* Process every character in string. */

    while (*str != '\0') {
        /* Segment changeover. */

        if (*str == '.') {
            /* Must have some digits in segment. */

            if (chcnt == 0) return 0;

            /* Limit number of segments. */

            if (++segs == 4) return 0;

            /* Reset segment values and restart loop. */

            chcnt = accum = 0;
            str++;
            continue;
        }
        /* Check numeric. */

        if ((*str < '0') || (*str > '9')) return 0;

        /* Accumulate and check segment. */

        if ((accum = accum * 10 + *str - '0') > 255) return 0;

        /* Advance other segment specific stuff and continue loop. */
        chcnt++;
        str++;
    }

    /* Check enough segments and enough characters in last segment. */
    if (segs != 3) return 0;
    if (chcnt == 0) return 0;
    /* Address okay. */
    return 1;
}

///////////////////////////////////////////////////////////////////////////////
int isValidUInt(char *str)
{
   // Handle empty string or just "-".
   if (!*str) return 0;
   // Check for non-digit chars in the rest of the stirng.
   while (*str) {
      if ((*str < '0') || (*str > '9')) return 0;
      else str++;
   }
   return 1;
}

///////////////////////////////////////////////////////////////////////////////
int isValidInt(char *str)
{
   // Handle negative numbers.
   if (*str == '-') ++str;
   // Handle empty string or just "-".
   if (!*str) return 0;
   // Check for non-digit chars in the rest of the stirng.
   while (*str) {
      if ((*str < '0') || (*str > '9')) return 0;
      else str++;
   }
   return 1;
}

///////////////////////////////////////////////////////////////////////////////
int read_ip2country( struct config_data *cfg )
{
	if (!cfg->ip2country_file[0]) return 0;
	FILE *fhandle;
	int linecount = 0;


	int nbline = 0;
	// Open Config file
	fhandle = fopen(cfg->ip2country_file,"rt");
	if (fhandle==0) {
		mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config: file not found '%s'\n",cfg->ip2country_file);
		return -1;
	} else mlogf(LOGINFO,getdbgflag(DBG_CONFIG,0,0)," config: parsing file '%s'\n",cfg->ip2country_file);

	// indexes in csv
	int idcode = -1;
	int idfirstip = -1;
	int idlastip = -1;
	int decodeip = 0; // 0:numbers, 1:ip's

	char valuetype[20]; 
	char value[20][256];
	int nbvalues = 0;

	while (!feof(fhandle)) 	{
		if ( !fgets(currentline, 10239, fhandle) ) break;
		iparser = &currentline[0];
		nbline++;

		nbvalues = 0;

		parse_spaces();
		if (*iparser!='"') continue;

		while (*iparser=='"') {
			iparser++;
			// Copy IP address
			char *p = value[nbvalues];
			while ( (*iparser!='"')&&(*iparser!='\n')&&(*iparser!='\r')&&(*iparser!=0) ) {
				*p = *iparser;
				iparser++;
				p++;
			}
			*p = 0;
			if (*iparser!='"') break; // break;
			iparser++;
			if (strlen(value[nbvalues])==2) idcode = nbvalues;
//			printf("(%d) '%s'\n",nbvalues+1,value[nbvalues]);
			nbvalues++;
			// Comma
			parse_spaces();
			if (*iparser!=',') break;
			iparser++;
			parse_spaces();
		}
		if ( (nbvalues<3)||(idcode==-1) ) {
			mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," Invalid IpToCountry file format\n");
			return 0;
		}

		// First Line test columns
		if (cfg->ip2country==NULL) {
			// valuetype: 'U' -> unknown, 'I' --> ip, 'N' --> Number, 'S' --> sting
			int i;
			for (i=0; i<nbvalues; i++) {
				//printf(" Value %d '%s' ", i, value[i]);
				if ( isValidIp4(value[i]) ) { valuetype[i] = 'I';  }
				else if ( isValidUInt(value[i]) ) { valuetype[i] = 'N';  }
				else { valuetype[i] = 'U'; }
			}

			// Check for IP:
			for (i=0; i<(nbvalues-1); i++) {
				if ( (valuetype[i]=='I')&&(valuetype[i+1]=='I') ) {
					//printf(" We HAVE IP'S --> (%d,%d)\n", i, i+1);
					idfirstip = i;
					idlastip = i+1;
					decodeip = 1;
					break;
				}
			}
			if (i>=(nbvalues-1)) {
				// Check for NUMBERS
				for (i=0; i<(nbvalues-1); i++) {
					if ( (valuetype[i]=='N')&&(valuetype[i+1]=='N') ) {
						//printf(" We HAVE NUMBERS --> (%d,%d)\n", i, i+1);
						idfirstip = i;
						idlastip = i+1;
						decodeip = 0;
						break;
					}
				}
			}
			if ( (idfirstip==-1)||(idlastip==-1) ) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," Invalid IpToCountry file format\n");
				return 0;
			}
		}


		// ADD TO DB
		if (decodeip) {
			struct ip2country_data *data = malloc( sizeof(struct ip2country_data) );
			memset( data, 0, sizeof(struct ip2country_data) );
			unsigned int ip4[4];
			if (sscanf(value[idfirstip],"%d.%d.%d.%d", &ip4[0], &ip4[1], &ip4[2], &ip4[3])==4) {
				data->ipstart = (ip4[0]<<24)|(ip4[1]<<16)|(ip4[2]<<8)|(ip4[3]);
				if (sscanf(value[idlastip],"%d.%d.%d.%d", &ip4[0], &ip4[1], &ip4[2], &ip4[3])==4) {
					data->ipend = (ip4[0]<<24)|(ip4[1]<<16)|(ip4[2]<<8)|(ip4[3]);
					strcpy(data->code, value[idcode]);
					data->next = cfg->ip2country;
					cfg->ip2country = data;
					linecount++;
					continue; // OK
				}
			}
			//ERROR
			free( data );
		}
		else {
			struct ip2country_data *data = malloc( sizeof(struct ip2country_data) );
			memset( data, 0, sizeof(struct ip2country_data) );
			if (sscanf(value[idfirstip], "%u", &data->ipstart)==1) {
				if (sscanf(value[idlastip],"%u", &data->ipend)==1) {
					strcpy(data->code, value[idcode]);
					data->next = cfg->ip2country;
					cfg->ip2country = data;
					linecount++;
					continue; // OK
				}
			}
			//ERROR
			free( data );
		}

	}
	fclose(fhandle);
	mlogf(LOGINFO,getdbgflag(DBG_CONFIG,0,0)," config: reading %d valid ip2country entries.\n", linecount);
	return 0;
}


void free_ip2country( struct config_data *cfg )
{
	if (cfg->ip2country) {
		struct ip2country_data *current = cfg->ip2country;
		cfg->ip2country = NULL;
		usleep(100000);
		while (current) {
			struct ip2country_data *next = current->next;
			free(current);
			current = next;
		}
	}
}


///////////////////////////////////////////////////////////////////////////////

int read_providers( struct config_data *cfg )
{
	if (!cfg->providers_file[0]) return 0;

	FILE *fhandle;
	char str[128];

	uint32_t caprovid;
	int provcount = 0;

	int nbline = 0;
	// Open Config file
	fhandle = fopen(cfg->providers_file,"rt");
	if (fhandle==0) {
		mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," config: file not found '%s'\n",cfg->providers_file);
		return -1;
	} else mlogf(LOGINFO,getdbgflag(DBG_CONFIG,0,0)," config: parsing file '%s'\n",cfg->providers_file);

	while (!feof(fhandle))
	{
		if ( !fgets(currentline, 10239, fhandle) ) break;
		iparser = &currentline[0];
		nbline++;
		parse_spaces();

		if ( parse_hex(str)==8 ) {
			caprovid = hex2int(str);
			parse_spaces();
			if (*iparser=='"') {
				iparser++;
				char *end = iparser;
				while ( (*end!='"')&&(*end!='\n')&&(*end!='\r')&&(*end!=0) ) end++;
				if (end-iparser) {
					*end = 0;
					//strcpy(str,iparser);
					//mlogf(LOGDEBUG,getdbgflag(DBG_CONFIG,0,0),"%04x:%06x:%04x '%s'\n",caid,prov,sid,iparser);
					struct providers_data *prov = malloc( sizeof(struct providers_data) + strlen(iparser) + 1 );
					prov->caprovid = caprovid;
					strcpy( prov->name, iparser );
					prov->next = cfg->providers;
					cfg->providers = prov;
					provcount++;
				}
			}
		}
	}
	fclose(fhandle);
	mlogf(LOGINFO,getdbgflag(DBG_CONFIG,0,0)," config: reading %d providers.\n", provcount);
	return 0;
}

void free_providers( struct config_data *cfg )
{
	if (cfg->providers) {
		struct providers_data *current = cfg->providers;
		cfg->providers = NULL;
		usleep(100000);
		while (current) {
			struct providers_data *next = current->next;
			free(current);
			current = next;
		}
	}
}


///////////////////////////////////////////////////////////////////////////////
// CAMD35 SERVER
///////////////////////////////////////////////////////////////////////////////

#ifdef CAMD35_SRV

// Clients
void remove_camd35_clients(struct camd35_server_data *srv)
{
	while (srv->client) {
		struct camd35_client_data *cli = srv->client;
		srv->client = cli->next;
		if (cli->handle>0) close(cli->handle);
		free( cli );
	}
}

void update_camd35_clients(struct camd35_server_data *srv, struct camd35_server_data *newsrv )
{
	// set remove flag to old deleted clients & update reused one
	struct camd35_client_data *cli = srv->client;
	while (cli) {
		struct camd35_client_data *newcli = newsrv->client;
		while (newcli) {
			if ( !(newcli->flags&FLAG_DELETE) )
			if ( !(cli->flags&FLAG_DELETE) )
			if ( !strcmp(cli->user, newcli->user) ) break;
			newcli = newcli->next;
		}
		if (newcli) {
			newcli->flags |= FLAG_DELETE;
			// Update camd35 Client Data
/*
			// PASS
			if ( strcmp(cli->pass, newcli->pass) ) {
				cli->connected = 0;
				strcpy(cli->pass, newcli->pass);
			}
*/
			//
#ifdef CACHEEX
			cli->cacheex_mode = newcli->cacheex_mode;
#endif
			// Share Limits
			if ( memcmp(cli->sharelimits, newcli->sharelimits, sizeof(cli->sharelimits)) ) {
				memcpy(cli->sharelimits, newcli->sharelimits, sizeof(cli->sharelimits));
			}
		}
		else cli->flags |= FLAG_DELETE;
		cli = cli->next;
	}
	// Move all newcli without FLAG_DELETE to cli
	struct camd35_client_data *prev = NULL;
	struct camd35_client_data *newcli = newsrv->client;
	while (newcli) {
		struct camd35_client_data *next = newcli->next;
		if (!(newcli->flags&FLAG_DELETE)) {
			if (prev) prev->next = newcli->next; else newsrv->client = newcli->next;
			cfg_addcamd35client(srv, newcli);
		} else prev = newcli;
		newcli = next;
	}
	// Move all cli with FLAG_DELETE to newcli
	prev = NULL;
	cli = srv->client;
	while (cli) {
		struct camd35_client_data *next = cli->next;
		if (cli->flags&FLAG_DELETE) {
			if (prev) prev->next = cli->next; else srv->client = cli->next;
			cfg_addcamd35client(newsrv, cli);
		} else prev = cli;
		cli = next;
	}
}

//CacheEX 
void remove_camd35_cacheexclients(struct camd35_server_data *srv)
{
	while (srv->cacheexclient) {
		struct camd35_client_data *cli = srv->cacheexclient;
		srv->cacheexclient = cli->next;
		if (cli->handle>0) close(cli->handle);
		free( cli );
	}
}

void update_camd35_cacheexclients(struct camd35_server_data *srv, struct camd35_server_data *newsrv )
{
	// set remove flag to old deleted clients & update reused one
	struct camd35_client_data *cli = srv->cacheexclient;
	while (cli) {
		struct camd35_client_data *newcli = newsrv->cacheexclient;
		while (newcli) {
			if ( !(newcli->flags&FLAG_DELETE) )
			if ( !(cli->flags&FLAG_DELETE) )
			if ( !strcmp(cli->user, newcli->user) ) break;
			newcli = newcli->next;
		}
		if (newcli) {
			newcli->flags |= FLAG_DELETE;
			// Update camd35 Client Data
/*
			// PASS
			if ( strcmp(cli->pass, newcli->pass) ) {
				cli->connected = 0;
				strcpy(cli->pass, newcli->pass);
			}
*/
			//
#ifdef CACHEEX
			cli->cacheex_mode = newcli->cacheex_mode;
#endif
			// Share Limits
			if ( memcmp(cli->sharelimits, newcli->sharelimits, sizeof(cli->sharelimits)) ) {
				memcpy(cli->sharelimits, newcli->sharelimits, sizeof(cli->sharelimits));
			}
		}
		else cli->flags |= FLAG_DELETE;
		cli = cli->next;
	}
	// Move all newcli without FLAG_DELETE to cli
	struct camd35_client_data *prev = NULL;
	struct camd35_client_data *newcli = newsrv->cacheexclient;
	while (newcli) {
		struct camd35_client_data *next = newcli->next;
		if (!(newcli->flags&FLAG_DELETE)) {
			if (prev) prev->next = newcli->next; else newsrv->cacheexclient = newcli->next;
			cfg_addcamd35client(srv, newcli);
		} else prev = newcli;
		newcli = next;
	}
	// Move all cli with FLAG_DELETE to newcli
	prev = NULL;
	cli = srv->cacheexclient;
	while (cli) {
		struct camd35_client_data *next = cli->next;
		if (cli->flags&FLAG_DELETE) {
			if (prev) prev->next = cli->next; else srv->cacheexclient = cli->next;
			cfg_addcamd35client(newsrv, cli);
		} else prev = cli;
		cli = next;
	}
}

//

void update_camd35_servers(struct config_data *cfg, struct config_data *newcfg)
{
	struct camd35_server_data *srv = cfg->camd35.server;
	while (srv) {
		struct camd35_server_data *newsrv = newcfg->camd35.server;
		while (newsrv) {
			if (srv->port==newsrv->port) break;
			newsrv = newsrv->next;
		}
		if (newsrv) {
			newsrv->flags |= FLAG_DELETE;
			update_camd35_clients( srv, newsrv );
			update_camd35_cacheexclients( srv, newsrv );
		}
		else srv->flags |= FLAG_DELETE;
		srv = srv->next;
	}
	// Move all newsrv without FLAG_DELETE to srv
	struct camd35_server_data *prev = NULL;
	srv = newcfg->camd35.server;
	while (srv) {
		struct camd35_server_data *next = srv->next;
		if (!(srv->flags&FLAG_DELETE)) {
			if (prev) prev->next = srv->next; else newcfg->camd35.server = srv->next;
			cfg_addcamd35server(cfg, srv);
		} else prev = srv;
		srv = next;
	}
	// Move all srv with FLAG_DELETE to newsrv
	prev = NULL;
	srv = cfg->camd35.server;
	while (srv) {
		struct camd35_server_data *next = srv->next;
		if (srv->flags&FLAG_DELETE) {
			if (prev) prev->next = srv->next; else cfg->camd35.server = srv->next;
			cfg_addcamd35server(newcfg, srv);
		} else prev = srv;
		srv = next;
	}
}

#endif

///////////////////////////////////////////////////////////////////////////////
//  cs378x
///////////////////////////////////////////////////////////////////////////////

#ifdef CS378X_SRV

void remove_cs378x_clients(struct camd35_server_data *srv)
{
	while (srv->client) {
		struct camd35_client_data *cli = srv->client;
		srv->client = cli->next;
		if (cli->handle>0) close(cli->handle);
		free( cli );
	}
}

void update_cs378x_clients(struct camd35_server_data *srv, struct camd35_server_data *newsrv )
{
	// set remove flag to old deleted clients & update reused one
	struct camd35_client_data *cli = srv->client;
	while (cli) {
		struct camd35_client_data *newcli = newsrv->client;
		while (newcli) {
			if ( !(newcli->flags&FLAG_DELETE) )
			if ( !(cli->flags&FLAG_DELETE) )
			if ( !strcmp(cli->user, newcli->user) ) break;
			newcli = newcli->next;
		}
		if (newcli) {
			newcli->flags |= FLAG_DELETE;
			// Update camd35 Client Data
/*
			// PASS
			if ( strcmp(cli->pass, newcli->pass) ) {
				cli->connected = 0;
				strcpy(cli->pass, newcli->pass);
			}
*/
			//
#ifdef CACHEEX
			cli->cacheex_mode = newcli->cacheex_mode;
#endif
			// Share Limits
			if ( memcmp(cli->sharelimits, newcli->sharelimits, sizeof(cli->sharelimits)) ) {
				memcpy(cli->sharelimits, newcli->sharelimits, sizeof(cli->sharelimits));
			}
		}
		else cli->flags |= FLAG_DELETE;
		cli = cli->next;
	}
	// Move all newcli without FLAG_DELETE to cli
	struct camd35_client_data *prev = NULL;
	struct camd35_client_data *newcli = newsrv->client;
	while (newcli) {
		struct camd35_client_data *next = newcli->next;
		if (!(newcli->flags&FLAG_DELETE)) {
			if (prev) prev->next = newcli->next; else newsrv->client = newcli->next;
			cfg_addcamd35client(srv, newcli);
		} else prev = newcli;
		newcli = next;
	}
	// Move all cli with FLAG_DELETE to newcli
	prev = NULL;
	cli = srv->client;
	while (cli) {
		struct camd35_client_data *next = cli->next;
		if (cli->flags&FLAG_DELETE) {
			if (prev) prev->next = cli->next; else srv->client = cli->next;
			cfg_addcamd35client(newsrv, cli);
		} else prev = cli;
		cli = next;
	}
}

// CACHEEX


void remove_cs378x_cacheexclients(struct camd35_server_data *srv)
{
	while (srv->cacheexclient) {
		struct camd35_client_data *cli = srv->cacheexclient;
		srv->cacheexclient = cli->next;
		if (cli->handle>0) close(cli->handle);
		free( cli );
	}
}

void update_cs378x_cacheexclients(struct camd35_server_data *srv, struct camd35_server_data *newsrv )
{
	// set remove flag to old deleted clients & update reused one
	struct camd35_client_data *cli = srv->cacheexclient;
	while (cli) {
		struct camd35_client_data *newcli = newsrv->cacheexclient;
		while (newcli) {
			if ( !(newcli->flags&FLAG_DELETE) )
			if ( !(cli->flags&FLAG_DELETE) )
			if ( !strcmp(cli->user, newcli->user) ) break;
			newcli = newcli->next;
		}
		if (newcli) {
			newcli->flags |= FLAG_DELETE;
			// Update camd35 Client Data
/*
			// PASS
			if ( strcmp(cli->pass, newcli->pass) ) {
				cli->connected = 0;
				strcpy(cli->pass, newcli->pass);
			}
*/
			//
#ifdef CACHEEX
			cli->cacheex_mode = newcli->cacheex_mode;
#endif
			// Share Limits
			if ( memcmp(cli->sharelimits, newcli->sharelimits, sizeof(cli->sharelimits)) ) {
				memcpy(cli->sharelimits, newcli->sharelimits, sizeof(cli->sharelimits));
			}
		}
		else cli->flags |= FLAG_DELETE;
		cli = cli->next;
	}
	// Move all newcli without FLAG_DELETE to cli
	struct camd35_client_data *prev = NULL;
	struct camd35_client_data *newcli = newsrv->cacheexclient;
	while (newcli) {
		struct camd35_client_data *next = newcli->next;
		if (!(newcli->flags&FLAG_DELETE)) {
			if (prev) prev->next = newcli->next; else newsrv->cacheexclient = newcli->next;
			cfg_addcamd35client(srv, newcli);
		} else prev = newcli;
		newcli = next;
	}
	// Move all cli with FLAG_DELETE to newcli
	prev = NULL;
	cli = srv->cacheexclient;
	while (cli) {
		struct camd35_client_data *next = cli->next;
		if (cli->flags&FLAG_DELETE) {
			if (prev) prev->next = cli->next; else srv->cacheexclient = cli->next;
			cfg_addcamd35client(newsrv, cli);
		} else prev = cli;
		cli = next;
	}
}


void update_cs378x_servers(struct config_data *cfg, struct config_data *newcfg)
{
	struct camd35_server_data *srv = cfg->cs378x.server;
	while (srv) {
		struct camd35_server_data *newsrv = newcfg->cs378x.server;
		while (newsrv) {
			if (srv->port==newsrv->port) break;
			newsrv = newsrv->next;
		}
		if (newsrv) {
			newsrv->flags |= FLAG_DELETE;
			update_cs378x_clients( srv, newsrv );
			update_cs378x_cacheexclients( srv, newsrv );
		}
		else srv->flags |= FLAG_DELETE;
		srv = srv->next;
	}
	// Move all newsrv without FLAG_DELETE to srv
	struct camd35_server_data *prev = NULL;
	srv = newcfg->cs378x.server;
	while (srv) {
		struct camd35_server_data *next = srv->next;
		if (!(srv->flags&FLAG_DELETE)) {
			if (prev) prev->next = srv->next; else newcfg->cs378x.server = srv->next;
			cfg_addcs378xserver(cfg, srv);
		} else prev = srv;
		srv = next;
	}
	// Move all srv with FLAG_DELETE to newsrv
	prev = NULL;
	srv = cfg->cs378x.server;
	while (srv) {
		struct camd35_server_data *next = srv->next;
		if (srv->flags&FLAG_DELETE) {
			if (prev) prev->next = srv->next; else cfg->cs378x.server = srv->next;
			cfg_addcs378xserver(newcfg, srv);
		} else prev = srv;
		srv = next;
	}
}

#endif

///////////////////////////////////////////////////////////////////////////////
/// CCCAM SERVERS
///////////////////////////////////////////////////////////////////////////////

int cardcmp( struct cs_card_data *card1, struct cs_card_data *card2)
{
	if (card1->caid!=card2->caid) return 1;
	if (card1->nbprov!=card2->nbprov) return 1;
	int i;
	for(i=0; i<card1->nbprov; i++) if (card1->prov[i]!=card2->prov[i]) return 1;
	return 0;
}

//////////////////////////// CCCAM

void remove_cccam_clients(struct cccam_server_data *srv)
{
	while (srv->client) {
		struct cc_client_data *cli = srv->client;
		srv->client = cli->next;
		// FREE 
		if (cli->handle>0) close(cli->handle);
		while (cli->info) {
			struct client_info_data *info = cli->info;
			cli->info = info->next;
			free(info);
		}
		free( cli );
	}
}

void update_cccam_clients(struct cccam_server_data *srv, struct cccam_server_data *newsrv )
{
	// set remove flag to old deleted clients & update reused one
	struct cc_client_data *cli = srv->client;
	while (cli) {
		struct cc_client_data *newcli = newsrv->client;
		while (newcli) {
			if ( !(newcli->flags&FLAG_DELETE) )
			if ( !(cli->flags&FLAG_DELETE) )
			if ( !strcmp(cli->user, newcli->user) ) break;
			newcli = newcli->next;
		}
		if (newcli) {
			newcli->flags |= FLAG_DELETE;
			// Update CCcam Client Data
			// PASS
			if ( strcmp(cli->pass, newcli->pass) ) {
				cli->flags |= FLAG_DISCONNECT;
				strcpy(cli->pass, newcli->pass);
			}
			// dnhops
			if (cli->dnhops!=newcli->dnhops) {
				cli->flags |= FLAG_DISCONNECT;
				cli->dnhops = newcli->dnhops;
			}
			// csport
			if ( memcmp(cli->csport,newcli->csport,sizeof(cli->csport)) ) {
				cli->flags |= FLAG_DISCONNECT;
				memcpy( cli->csport, newcli->csport, sizeof(cli->csport) );
			}
			//
			cli->uphops = newcli->uphops;
			cli->shareemus = newcli->shareemus;
			cli->allowemm = newcli->allowemm;
#ifdef CACHEEX
			if (cli->cacheex_mode!=newcli->cacheex_mode) {
				cli->flags |= FLAG_DISCONNECT;
				cli->cacheex_mode = newcli->cacheex_mode;
			}
#endif
#ifdef CHECK_NEXTDCW
			cli->dcwcheck = newcli->dcwcheck;
#endif
			// NODEID
			if ( memcmp(cli->option.nodeid, newcli->option.nodeid, 8) ) {
				cli->flags |= FLAG_DISCONNECT;
				memcpy(cli->option.nodeid, newcli->option.nodeid, 8);
			}
#ifndef PUBLIC
			cli->option.checknodeid = newcli->option.checknodeid;
#endif

			// Share Limits
#ifdef CACHEEX
			if ( !cli->cacheex_mode ) 
#endif
			if ( memcmp(cli->sharelimits, newcli->sharelimits, sizeof(cli->sharelimits)) ) {
				cli->flags |= FLAG_DISCONNECT;
				memcpy(cli->sharelimits, newcli->sharelimits, sizeof(cli->sharelimits));
			}
			// info+data
			struct client_info_data *info = cli->info;
			cli->info = newcli->info;
			newcli->info = info;
			cli->realname = newcli->realname;
#ifdef EXPIREDATE
			memcpy( &cli->enddate, &newcli->enddate, sizeof(struct tm) );
#endif
			cli->host = newcli->host;
		}
		else cli->flags |= FLAG_DELETE;
		cli = cli->next;
	}
	// Move all newcli without FLAG_DELETE to cli
	struct cc_client_data *prev = NULL;
	struct cc_client_data *newcli = newsrv->client;
	while (newcli) {
		struct cc_client_data *next = newcli->next;
		if (!(newcli->flags&FLAG_DELETE)) {
			if (prev) prev->next = newcli->next; else newsrv->client = newcli->next;
			cfg_addcccamclient(srv, newcli);
		} else prev = newcli;
		newcli = next;
	}
	// Move all cli with FLAG_DELETE to newcli
	prev = NULL;
	cli = srv->client;
	while (cli) {
		struct cc_client_data *next = cli->next;
		if (cli->flags&FLAG_DELETE) {
			if (prev) prev->next = cli->next; else srv->client = cli->next;
			cfg_addcccamclient(newsrv, cli);
		} else prev = cli;
		cli = next;
	}
}

////////////////////////////////////////////////////////////////////////////////

void remove_cccam_cacheexclients(struct cccam_server_data *srv)
{
	while (srv->cacheexclient) {
		struct cc_client_data *cli = srv->cacheexclient;
		srv->cacheexclient = cli->next;
		// FREE 
		if (cli->handle>0) close(cli->handle);
		while (cli->info) {
			struct client_info_data *info = cli->info;
			cli->info = info->next;
			free(info);
		}
		free( cli );
	}
}

void update_cccam_cacheexclients(struct cccam_server_data *srv, struct cccam_server_data *newsrv )
{
	// set remove flag to old deleted clients & update reused one
	struct cc_client_data *cli = srv->cacheexclient;
	while (cli) {
		struct cc_client_data *newcli = newsrv->cacheexclient;
		while (newcli) {
			if ( !(newcli->flags&FLAG_DELETE) )
			if ( !(cli->flags&FLAG_DELETE) )
			if ( !strcmp(cli->user, newcli->user) ) break;
			newcli = newcli->next;
		}
		if (newcli) {
			newcli->flags |= FLAG_DELETE;
			// Update CCcam cacheexclient Data
			// PASS
			if ( strcmp(cli->pass, newcli->pass) ) {
				cli->flags |= FLAG_DISCONNECT;
				strcpy(cli->pass, newcli->pass);
			}
			// dnhops
			if (cli->dnhops!=newcli->dnhops) {
				cli->flags |= FLAG_DISCONNECT;
				cli->dnhops = newcli->dnhops;
			}
			// csport
			if ( memcmp(cli->csport,newcli->csport,sizeof(cli->csport)) ) {
				cli->flags |= FLAG_DISCONNECT;
				memcpy( cli->csport, newcli->csport, sizeof(cli->csport) );
			}
			//
			cli->uphops = newcli->uphops;
			cli->shareemus = newcli->shareemus;
			cli->allowemm = newcli->allowemm;
#ifdef CACHEEX
			if (cli->cacheex_mode!=newcli->cacheex_mode) {
				cli->flags |= FLAG_DISCONNECT;
				cli->cacheex_mode = newcli->cacheex_mode;
			}
#endif
#ifdef CHECK_NEXTDCW
			cli->dcwcheck = newcli->dcwcheck;
#endif
			// NODEID
			if ( memcmp(cli->option.nodeid, newcli->option.nodeid, 8) ) {
				cli->flags |= FLAG_DISCONNECT;
				memcpy(cli->option.nodeid, newcli->option.nodeid, 8);
			}
#ifndef PUBLIC
			cli->option.checknodeid = newcli->option.checknodeid;
#endif

			// Share Limits
#ifdef CACHEEX
			if ( !cli->cacheex_mode ) 
#endif
			if ( memcmp(cli->sharelimits, newcli->sharelimits, sizeof(cli->sharelimits)) ) {
				cli->flags |= FLAG_DISCONNECT;
				memcpy(cli->sharelimits, newcli->sharelimits, sizeof(cli->sharelimits));
			}
			// info+data
			struct client_info_data *info = cli->info;
			cli->info = newcli->info;
			newcli->info = info;
			cli->realname = newcli->realname;
#ifdef EXPIREDATE
			memcpy( &cli->enddate, &newcli->enddate, sizeof(struct tm) );
#endif
			cli->host = newcli->host;
		}
		else cli->flags |= FLAG_DELETE;
		cli = cli->next;
	}
	// Move all newcli without FLAG_DELETE to cli
	struct cc_client_data *prev = NULL;
	struct cc_client_data *newcli = newsrv->cacheexclient;
	while (newcli) {
		struct cc_client_data *next = newcli->next;
		if (!(newcli->flags&FLAG_DELETE)) {
			if (prev) prev->next = newcli->next; else newsrv->cacheexclient = newcli->next;
			cfg_addcccamclient(srv, newcli);
		} else prev = newcli;
		newcli = next;
	}
	// Move all cli with FLAG_DELETE to newcli
	prev = NULL;
	cli = srv->cacheexclient;
	while (cli) {
		struct cc_client_data *next = cli->next;
		if (cli->flags&FLAG_DELETE) {
			if (prev) prev->next = cli->next; else srv->cacheexclient = cli->next;
			cfg_addcccamclient(newsrv, cli);
		} else prev = cli;
		cli = next;
	}
}

////////////////////////////////////////////////////////////////////////////////

void update_cccam_servers(struct config_data *cfg, struct config_data *newcfg)
{
	struct cccam_server_data *srv = cfg->cccam.server;
	while (srv) {
		struct cccam_server_data *newsrv = newcfg->cccam.server;
		while (newsrv) {
			if (srv->port==newsrv->port) break;
			newsrv = newsrv->next;
		}
		if (newsrv) {
			newsrv->flags |= FLAG_DELETE;
			update_cccam_clients( srv, newsrv );
			update_cccam_cacheexclients( srv, newsrv );
		}
		else srv->flags |= FLAG_DELETE;
		srv = srv->next;
	}
	// Move all newsrv without FLAG_DELETE to srv
	struct cccam_server_data *prev = NULL;
	srv = newcfg->cccam.server;
	while (srv) {
		struct cccam_server_data *next = srv->next;
		if (!(srv->flags&FLAG_DELETE)) {
			if (prev) prev->next = srv->next; else newcfg->cccam.server = srv->next;
			cfg_addcccamserver(cfg, srv);
		} else prev = srv;
		srv = next;
	}
	// Move all srv with FLAG_DELETE to newsrv
	prev = NULL;
	srv = cfg->cccam.server;
	while (srv) {
		struct cccam_server_data *next = srv->next;
		if (srv->flags&FLAG_DELETE) {
			if (prev) prev->next = srv->next; else cfg->cccam.server = srv->next;
			cfg_addcccamserver(newcfg, srv);
		} else prev = srv;
		srv = next;
	}
}

#ifdef FREECCCAM_SRV
//////////////////////////// FREECCCAM
void update_freecccam_server(struct config_data *cfg, struct config_data *newcfg)
{
	// Check for port/user/pass/max

	if ( ( cfg->freecccam.maxusers!=newcfg->freecccam.maxusers )
		|| ( strcmp(cfg->freecccam.user ,newcfg->freecccam.user) )
		|| ( strcmp(cfg->freecccam.pass ,newcfg->freecccam.pass) )
		|| ( strcmp(cfg->freecccam.version ,newcfg->freecccam.version) )
		|| ( strcmp(cfg->freecccam.build ,newcfg->freecccam.build) )
		|| ( memcmp(cfg->freecccam.csport ,newcfg->freecccam.csport, sizeof(cfg->freecccam.csport)) )
		|| ( cfg->freecccam.server.port != newcfg->freecccam.server.port )
	) {
		// Remove OLD
		cfg->freecccam.maxusers = newcfg->freecccam.maxusers;
		strcpy(cfg->freecccam.user ,newcfg->freecccam.user);
		strcpy(cfg->freecccam.pass ,newcfg->freecccam.pass);
		strcpy(cfg->freecccam.version ,newcfg->freecccam.version);
		strcpy(cfg->freecccam.build ,newcfg->freecccam.build);
		memcpy(cfg->freecccam.csport ,newcfg->freecccam.csport, sizeof(cfg->freecccam.csport));

		void *temp = cfg->freecccam.server.client;
		cfg->freecccam.server.client = newcfg->freecccam.server.client;
		newcfg->freecccam.server.client = temp;

		if ( cfg->freecccam.server.port != newcfg->freecccam.server.port ) {
			newcfg->freecccam.server.handle = cfg->freecccam.server.handle;
			cfg->freecccam.server.handle = -1;
			cfg->freecccam.server.port = newcfg->freecccam.server.port;
		}
	}
}
#endif

////////////////////////////////////////////////////////////////////////////////
// MGCAMD SERVER
////////////////////////////////////////////////////////////////////////////////

void remove_mgcamd_clients(struct mgcamdserver_data *srv)
{
	while (srv->client) {
		struct mg_client_data *cli = srv->client;
		srv->client = cli->next;
		// FREE 
		if (cli->handle>0) close(cli->handle);
		while (cli->info) {
			struct client_info_data *info = cli->info;
			cli->info = info->next;
			free(info);
		}
		free( cli );
	}
}

void update_mgcamd_clients(struct mgcamdserver_data *srv, struct mgcamdserver_data *newsrv )
{
	// set remove flag to old deleted clients & update reused one
	struct mg_client_data *cli = srv->client;
	while (cli) {
		struct mg_client_data *newcli = newsrv->client;
		while (newcli) {
			if ( !(newcli->flags&FLAG_DELETE) )
			if ( !(cli->flags&FLAG_DELETE) )
			if ( !strcmp(cli->user, newcli->user) ) break;
			newcli = newcli->next;
		}
		if (newcli) {
			newcli->flags |= FLAG_DELETE;
			// Update MGcamd Client Data
			// PASS
			if ( strcmp(cli->pass, newcli->pass) ) {
				cli->flags |= FLAG_DISCONNECT;
				strcpy(cli->pass, newcli->pass);
			}
			// Share Limits
			if ( memcmp(cli->sharelimits, newcli->sharelimits, sizeof(cli->sharelimits)) ) {
				cli->flags |= FLAG_DISCONNECT;
				memcpy(cli->sharelimits, newcli->sharelimits, sizeof(cli->sharelimits));
			}
			// csport
			if ( memcmp(cli->csport,newcli->csport,sizeof(cli->csport)) ) {
				cli->flags |= FLAG_DISCONNECT;
				memcpy( cli->csport, newcli->csport, sizeof(cli->csport) );
			}
			// info+data
			struct client_info_data *info = cli->info;
			cli->info = newcli->info;
			newcli->info = info;
			cli->realname = newcli->realname;
#ifdef CHECK_NEXTDCW
			cli->dcwcheck = newcli->dcwcheck;
#endif
#ifdef EXPIREDATE
			memcpy( &cli->enddate, &newcli->enddate, sizeof(struct tm) );
#endif
			cli->host = newcli->host;
		}
		else cli->flags |= FLAG_DELETE;
		cli = cli->next;
	}
	// Move all newcli without FLAG_DELETE to cli
	struct mg_client_data *prev = NULL;
	struct mg_client_data *newcli = newsrv->client;
	while (newcli) {
		struct mg_client_data *next = newcli->next;
		if (!(newcli->flags&FLAG_DELETE)) {
			if (prev) prev->next = newcli->next; else newsrv->client = newcli->next;
			cfg_addmgcamdclient(srv, newcli);
		} else prev = newcli;
		newcli = next;
	}
	// Move all cli with FLAG_DELETE to newcli
	prev = NULL;
	cli = srv->client;
	while (cli) {
		struct mg_client_data *next = cli->next;
		if (cli->flags&FLAG_DELETE) {
			if (prev) prev->next = cli->next; else srv->client = cli->next;
			cfg_addmgcamdclient(newsrv, cli);
		} else prev = cli;
		cli = next;
	}
}

void update_mgcamd_servers(struct config_data *cfg, struct config_data *newcfg)
{
	struct mgcamdserver_data *srv = cfg->mgcamd.server;
	while (srv) {
		struct mgcamdserver_data *newsrv = newcfg->mgcamd.server;
		while (newsrv) {
			if (srv->port==newsrv->port) break;
			newsrv = newsrv->next;
		}
		if (newsrv) {
			newsrv->flags |= FLAG_DELETE;
			update_mgcamd_clients( srv, newsrv );
		}
		else srv->flags |= FLAG_DELETE;
		srv = srv->next;
	}
	// Move all newsrv without FLAG_DELETE to srv
	struct mgcamdserver_data *prev = NULL;
	srv = newcfg->mgcamd.server;
	while (srv) {
		struct mgcamdserver_data *next = srv->next;
		if (!(srv->flags&FLAG_DELETE)) {
			if (prev) prev->next = srv->next; else newcfg->mgcamd.server = srv->next;
			cfg_addmgcamdserver(cfg, srv);
		} else prev = srv;
		srv = next;
	}
	// Move all srv with FLAG_DELETE to newsrv
	prev = NULL;
	srv = cfg->mgcamd.server;
	while (srv) {
		struct mgcamdserver_data *next = srv->next;
		if (srv->flags&FLAG_DELETE) {
			if (prev) prev->next = srv->next; else cfg->mgcamd.server = srv->next;
			cfg_addmgcamdserver(newcfg, srv);
		} else prev = srv;
		srv = next;
	}
}


////////////////////////////////////////////////////////////////////////////////
// CACHE SERVER
////////////////////////////////////////////////////////////////////////////////

#ifdef PEERLIST
void fpeer_update(struct cacheserver_data *cache);
void ipeer_update(struct cacheserver_data *cache);
#endif

void remove_cache_peers(struct cacheserver_data *srv)
{
	while (srv->peer) {
		struct cachepeer_data *peer = srv->peer;
		srv->peer = peer->next;
		//if (peer->outsock>0) close(peer->outsock);
		free( peer );
	}
}


void update_cache_peers(struct cacheserver_data *srv, struct cacheserver_data *newsrv)
{
	// set remove flag to old deleted clients & update reused one
	struct cachepeer_data *peer = srv->peer;
	while (peer) {
		struct cachepeer_data *newpeer = newsrv->peer;
		while (newpeer) {
			if ( !(newpeer->flags&FLAG_DELETE) )
			if ( !(peer->flags&FLAG_DELETE) )
			if ( peer->host==newpeer->host )
			if ( peer->port==newpeer->port ) break;
			newpeer = newpeer->next;
		}
		if (newpeer) {
			newpeer->flags |= FLAG_DELETE;
			// Update
			peer->flags &= (FLAG_DEFCONFIG|FLAG_DISABLE|FLAG_EXPIRED|FLAG_DELETE|FLAG_DISCONNECT);
			peer->flags |= newpeer->flags & (FLAG_CACHE_SENDREQ|FLAG_CACHE_SENDREP);
			peer->fblock0onid = newpeer->fblock0onid;
			peer->csp = newpeer->csp;
			peer->runtime = 0;
#ifndef PUBLIC
			peer->fwd = newpeer->fwd;
			// csport
			if ( memcmp(peer->sharelimits,newpeer->sharelimits,sizeof(peer->sharelimits)) ) {
				peer->flags |= FLAG_DISCONNECT;
				memcpy( peer->sharelimits, newpeer->sharelimits, sizeof(peer->sharelimits) );
			}
#endif
		}
		else if (!peer->runtime) peer->flags |= FLAG_DELETE; // if it is not created at runtime so delete
		peer = peer->next;
	}
	// Move all new without FLAG_DELETE to old
	struct cachepeer_data *prev = NULL;
	struct cachepeer_data *newpeer = newsrv->peer;
	while (newpeer) {
		struct cachepeer_data *next = newpeer->next;
		if (!(newpeer->flags&FLAG_DELETE)) {
			if (prev) prev->next = newpeer->next; else newsrv->peer = newpeer->next;
			cfg_addcachepeer(srv, newpeer);
		} else prev = newpeer;
		newpeer = next;
	}
	// Move all old with FLAG_DELETE to new
	prev = NULL;
	peer = srv->peer;
	while (peer) {
		struct cachepeer_data *next = peer->next;
		if (peer->flags&FLAG_DELETE) {
			if (prev) prev->next = peer->next; else srv->peer = peer->next;
			cfg_addcachepeer(newsrv, peer);
		} else prev = peer;
		peer = next;
	}
}

void update_cache_servers(struct config_data *cfg, struct config_data *newcfg)
{
	struct cacheserver_data *srv = cfg->cache.server;
	while (srv) {
		struct cacheserver_data *newsrv = newcfg->cache.server;
		while (newsrv) {
			if (srv->port==newsrv->port) break;
			newsrv = newsrv->next;
		}
		if (newsrv) {
			newsrv->flags |= FLAG_DELETE;
			update_cache_peers( srv, newsrv );
		}
		else srv->flags |= FLAG_DELETE;
		srv = srv->next;
	}
	// Move all newsrv without FLAG_DELETE to srv
	struct cacheserver_data *prev = NULL;
	srv = newcfg->cache.server;
	while (srv) {
		struct cacheserver_data *next = srv->next;
		if (!(srv->flags&FLAG_DELETE)) {
			if (prev) prev->next = srv->next; else newcfg->cache.server = srv->next;
			cfg_addcacheserver(cfg, srv);
		} else prev = srv;
		srv = next;
	}
	// Move all srv with FLAG_DELETE to newsrv
	prev = NULL;
	srv = cfg->cache.server;
	while (srv) {
		struct cacheserver_data *next = srv->next;
		if (srv->flags&FLAG_DELETE) {
			if (prev) prev->next = srv->next; else cfg->cache.server = srv->next;
			cfg_addcacheserver(newcfg, srv);
		} 
		else 
		{
			prev = srv;
#ifdef PEERLIST
	                fpeer_update(srv);
        	        ipeer_update(srv);
#endif
		}
		srv = next;
	}
}




////////////////////////////////////////////////////////////////////////////////
// PROFILE
////////////////////////////////////////////////////////////////////////////////

void remove_newcamd_clients(struct cardserver_data *cs)
{
	while (cs->newcamd.client) {
		struct cs_client_data *cli = cs->newcamd.client;
		cs->newcamd.client = cli->next;
		// FREE 
		if (cli->handle>0) close(cli->handle);
		while (cli->info) {
			struct client_info_data *info = cli->info;
			cli->info = info->next;
			free(info);
		}
		free( cli );
	}
}


void update_cardserver_newcamd_clients(struct cardserver_data *cs, struct cardserver_data *newcs )
{
	// set remove flag to old deleted clients & update reused one
	struct cs_client_data *cli = cs->newcamd.client;
	while (cli) {
		struct cs_client_data *newcli = newcs->newcamd.client;
		while (newcli) {
			if ( !(newcli->flags&FLAG_DELETE) )
			if ( !(cli->flags&FLAG_DELETE) )
			if ( !strcmp(cli->user, newcli->user) ) break;
			newcli = newcli->next;
		}
		if (newcli) {
			newcli->flags |= FLAG_DELETE;
#ifdef CHECK_NEXTDCW
			cli->dcwcheck = newcli->dcwcheck;
#endif
			// Update Newcamd Client Data
			// PASS
			if ( strcmp(cli->pass, newcli->pass) ) {
				cli->flags |= FLAG_DISCONNECT;
				strcpy(cli->pass, newcli->pass);
			}
			// info+data
			struct client_info_data *info = cli->info;
			cli->info = newcli->info;
			newcli->info = info;
			cli->realname = newcli->realname;
		}
		else cli->flags |= FLAG_DELETE;
		cli = cli->next;
	}
	// Move all newcli without FLAG_DELETE to cli
	struct cs_client_data *prev = NULL;
	struct cs_client_data *newcli = newcs->newcamd.client;
	while (newcli) {
		struct cs_client_data *next = newcli->next;
		if (!(newcli->flags&FLAG_DELETE)) {
			if (prev) prev->next = newcli->next; else newcs->newcamd.client = newcli->next;
			cs_addnewcamdclient(cs, newcli);
		} else prev = newcli;
		newcli = next;
	}
	// Move all cli with FLAG_DELETE to newcli
	prev = NULL;
	cli = cs->newcamd.client;
	while (cli) {
		struct cs_client_data *next = cli->next;
		if (cli->flags&FLAG_DELETE) {
			if (prev) prev->next = cli->next; else cs->newcamd.client = cli->next;
			cs_addnewcamdclient(newcs, cli);
		} else prev = cli;
		cli = next;
	}
}

#include "pipe.h"


int cs_same_card( struct cardserver_data *cs1, struct cardserver_data *cs2)
{
	int i,j,found;
	int nbsame = 0;
	int nbdiff = 0;

	if (cs1->card.caid!=cs2->card.caid) return 0;

	for(i=0; i<cs1->card.nbprov;i++) {
		found = 0;
		for(j=0; j<cs2->card.nbprov;j++)
			if (cs1->card.prov[i].id==cs2->card.prov[j].id) {
				found = 1;
				break;
			}
		if (found) nbsame++; else nbdiff++;
	}

	if ( (nbsame==cs1->card.nbprov)&&(nbsame==cs2->card.nbprov) ) return 2;
	if ( (nbsame==cs1->card.nbprov)||(nbsame==cs2->card.nbprov) ) return 1;

	return 0;
}

void update_cardserver(struct config_data *cfg, struct config_data *newcfg)
{
	struct cardserver_data *cs = cfg->cardserver;
	while (cs) {
		struct cardserver_data *newcs = newcfg->cardserver;
		while (newcs) {
			if (cs->newcamd.port==newcs->newcamd.port)
			if ( cs_same_card( cs, newcs ) ) break;
			newcs = newcs->next;
		}
		if (newcs) {
			newcs->flags |= FLAG_DELETE;
			// Name
			strcpy( cs->name, newcs->name);
			// Key
			if (memcmp( cs->newcamd.key, newcs->newcamd.key, sizeof(cs->newcamd.key)) ) {
				cs->newcamd.flags |= FLAG_DISCONNECT;
				memcpy( cs->newcamd.key, newcs->newcamd.key, sizeof(cs->newcamd.key) );
			}
			// card
			if ( cs_same_card(cs,newcs)==1 ) cs->flags |= FLAG_DISCONNECT;
			uint8_t buf[sizeof(cs->card)];
			memcpy( buf, &cs->card, sizeof(cs->card));
			memcpy( &cs->card, &newcs->card, sizeof(cs->card));
			memcpy( &newcs->card, buf, sizeof(cs->card));

			// ecm length
			memcpy( cs->ecmlen, newcs->ecmlen, sizeof(cs->ecmlen) );
			// options
			memcpy( &cs->option, &newcs->option, sizeof(cs->option) );
			update_cardserver_newcamd_clients( cs, newcs );
			// SIDS
			cs->sidlist.deny = newcs->sidlist.deny;
			cs->sidlist.total = newcs->sidlist.total;
			void *tmp = cs->sidlist.data;
			cs->sidlist.data = newcs->sidlist.data;
			newcs->sidlist.data = tmp;
		}
		else cs->flags |= FLAG_DELETE;
		cs = cs->next;
	}
	// Move all new without FLAG_DELETE to current
	struct cardserver_data *prev = NULL;
	cs = newcfg->cardserver;
	while (cs) {
		struct cardserver_data *next = cs->next;
		if (!(cs->flags&FLAG_DELETE)) {
			if (prev) prev->next = cs->next; else newcfg->cardserver = cs->next;
			cfg_addprofile(cfg, cs);
			cs->id = cfg->cardserverid;
			cfg->cardserverid++;
		} else prev = cs;
		cs = next;
	}
	// Move all current with FLAG_DELETE to new
	prev = NULL;
	cs = cfg->cardserver;
	while (cs) {
		struct cardserver_data *next = cs->next;
		if (cs->flags&FLAG_DELETE) {
#ifdef MULTITHREADED
			// SEND DEL SHARE TO CCCAM/MGCAMD CLIENTS
			mlogf(LOGINFO,0, " DEL share [%s] id:%d  caid:%04x\n", cs->name, cs->id, cs->card.caid);
			uint8_t buf[16];
			buf[0] = PIPE_CARD_DEL;
			memcpy( buf+1, &cs, sizeof(void*) );
			pipe_send( prg.pipe.cccam[1], buf, 1+sizeof(void*) );
			pipe_send( prg.pipe.mgcamd[1], buf, 1+sizeof(void*) );
#endif
			if (prev) prev->next = cs->next; else cfg->cardserver = cs->next;
			cfg_addprofile(newcfg, cs);
		} else prev = cs;
		cs = next;
	}
#ifdef MULTITHREADED
	//check for card update
	cs = newcfg->cardserver;
	while (cs) {
		if (cs->flags&FLAG_DISCONNECT) {
			uint8_t buf[16];
			// SEND DEL SHARE TO CCCAM/MGCAMD CLIENTS
			mlogf(LOGINFO,0, " DEL share [%s] id:%d  caid:%04x\n", cs->name, cs->id, cs->card.caid);
			buf[0] = PIPE_CARD_DEL;
			memcpy( buf+1, &cs, sizeof(void*) );
			if (cs->option.fsharecccam) pipe_send( prg.pipe.cccam[1], buf, 1+sizeof(void*) );
			if (cs->option.fsharemgcamd) pipe_send( prg.pipe.mgcamd[1], buf, 1+sizeof(void*) );
			// SEND ADD SHARE TO CCCAM/MGCAMD CLIENTS
			mlogf(LOGINFO,0, " ADD share [%s] id:%d  caid:%04x\n", cs->name, cs->id, cs->card.caid);
			buf[0] = PIPE_CARD_ADD;
			memcpy( buf+1, &cs, sizeof(void*) );
			if (cs->option.fsharecccam) pipe_send( prg.pipe.cccam[1], buf, 1+sizeof(void*) );
			if (cs->option.fsharemgcamd) pipe_send( prg.pipe.mgcamd[1], buf, 1+sizeof(void*) );
		} 
		cs = cs->next;
	}
#endif


}

void server2string(struct server_data *srv, char *line)
{
	int i;
	char tmp[255];
	if (!srv) return;
	if (srv->type==TYPE_CCCAM)
		sprintf(line, "C: %s %d %s %s", srv->host->name, srv->port, srv->user, srv->pass);
	else if (srv->type==TYPE_NEWCAMD) {
		sprintf(line, "N: %s %d %s %s ", srv->host->name, srv->port, srv->user, srv->pass);
		array2hex( srv->key, line+strlen(line), 14);
	}

	strcat(line," { ");

	// Option: Profiles
	if (srv->priority) {
		sprintf(tmp, "priority=%d; ", srv->priority);
		strcat(line,tmp);
	}

	// Option: Profiles
	if (srv->csport[0]) {
		sprintf(tmp, "profiles= %d", srv->csport[0]); strcat(line,tmp);
		for(i=1; i<MAX_CSPORTS; i++) {
			if (!srv->csport[i]) break;
			sprintf(tmp,", %d",srv->csport[i]); strcat(line,tmp);
		}
		strcat(line,"; ");
	}

	// Option: share
	if (srv->sharelimits[0].caid!=0xFFFF) {
		sprintf(tmp, "shares= %x:%x:%x", srv->sharelimits[0].caid,srv->sharelimits[0].provid,srv->sharelimits[0].uphops);
		strcat(line,tmp);
		for(i=1; i<100; i++) {
			if (srv->sharelimits[i].caid==0xFFFF) break;
			sprintf(tmp, ", %x:%x:%x", srv->sharelimits[i].caid,srv->sharelimits[i].provid,srv->sharelimits[i].uphops);
			strcat(line,tmp);
		}
		strcat(line,"; ");
	}

	// Option: sids
	if (srv->sids) {
		struct sid_chid_data *sid = srv->sids;
		if (sid->chid) sprintf(tmp, "sids= %04x:%04x", sid->sid, sid->chid); else sprintf(tmp, "sids= %04x", sid->sid);
		strcat(line,tmp);
		sid++;
		while (sid->sid) {
			if (sid->chid) sprintf(tmp, ", %04x:%04x", sid->sid, sid->chid); else sprintf(tmp, ", %04x", sid->sid);
			strcat(line,tmp);
			sid++;
		}
		strcat(line,"; ");
	}

	strcat(line," }");
}


////////////////////////////////////////////////////////////////////////////////
// SERVERS
////////////////////////////////////////////////////////////////////////////////

void free_card(struct cs_card_data* card)
{
	int s;
	for(s=0; s<256; s++) {
		struct sid_data *sid1 = card->sids[s];
		while (sid1) {
			struct sid_data *sid = sid1;
			sid1 = sid1->next;
			free(sid);
		}
	}
	free(card);
}

void free_cardlist(struct cs_card_data* card)
{
	while (card) {
		struct cs_card_data *tmp = card;
		card = card->next;
		free_card( tmp );
	}
}



void remove_servers(struct config_data *cfg)
{
	while (cfg->server) {
		struct server_data *srv = cfg->server;
		cfg->server = srv->next;
		pthread_mutex_destroy( &srv->lock );
		if (srv->connection.status>0) disconnect_srv(srv);
		// Sids
		if (srv->sids) free(srv->sids);
		// Cards
		free_cardlist(srv->card);
		//
		free( srv );
	}

	while (cfg->cacheexserver) {
		struct server_data *srv = cfg->cacheexserver;
		cfg->cacheexserver = srv->next;
		pthread_mutex_destroy( &srv->lock );
		if (srv->connection.status>0) disconnect_srv(srv);
		// Sids
		if (srv->sids) free(srv->sids);
		// Cards
		free_cardlist(srv->card);
		//
		free( srv );
	}

}


void update_servers(struct config_data *cfg, struct config_data *newcfg )
{
	// set remove flag to old deleted clients & update reused one
	struct server_data *srv = cfg->server;
	while (srv) {
		struct server_data *newsrv = newcfg->server;
		while (newsrv) {
			if ( !(newsrv->flags&FLAG_DELETE) )
			if ( !(srv->flags&FLAG_DELETE) )
			if ( srv->host==newsrv->host )
			if ( srv->port==newsrv->port )
			if ( !strcmp(srv->user, newsrv->user) ) break;
			newsrv = newsrv->next;
		}
		if (newsrv) {
			newsrv->flags |= FLAG_DELETE;
			// PASS
			if ( strcmp(srv->pass, newsrv->pass) ) {
				srv->flags |= FLAG_DISCONNECT;
				strcpy(srv->pass, newsrv->pass);
			}
			// TYPE
			if (srv->type!=newsrv->type) { // ???
				srv->flags |= FLAG_DISCONNECT;
				srv->type = newsrv->type;
			}
			// NEWCAMD KEY
			if ( (srv->type==TYPE_NEWCAMD) && memcmp(srv->key,newsrv->key, sizeof(srv->key)) ) {
				srv->flags |= FLAG_DISCONNECT;
				memcpy(srv->key,newsrv->key, sizeof(srv->key));
			}
			// csport
			if ( memcmp(srv->csport,newsrv->csport,sizeof(srv->csport)) ) {
				srv->flags |= FLAG_DISCONNECT;
				memcpy( srv->csport, newsrv->csport, sizeof(srv->csport) );
			}
			// priority
			srv->priority = newsrv->priority;
#ifdef CACHEEX
			srv->cacheex_mode = newsrv->cacheex_mode;
			srv->cacheex_maxhop = newsrv->cacheex_maxhop;
#ifndef PUBLIC
			srv->cacheex_forward = newsrv->cacheex_forward;
#endif
#endif
			// Share Limits
			if ( memcmp(srv->sharelimits, newsrv->sharelimits, sizeof(srv->sharelimits)) ) {
				srv->flags |= FLAG_DISCONNECT;
				memcpy(srv->sharelimits, newsrv->sharelimits, sizeof(srv->sharelimits));
			}
			// ACCEPTED SIDs
			void *tmp = srv->sids;
			srv->sids = newsrv->sids;
			newsrv->sids = tmp;
		}
		else srv->flags |= FLAG_DELETE;
		srv = srv->next;
	}
	// Move all newsrv without FLAG_DELETE to srv
	struct server_data *prev = NULL;
	struct server_data *newsrv = newcfg->server;
	while (newsrv) {
		struct server_data *next = newsrv->next;
		if (!(newsrv->flags&FLAG_DELETE)) {
			if (prev) prev->next = newsrv->next; else newcfg->server = newsrv->next;
			cfg_addserver(cfg, newsrv);
		} else prev = newsrv;
		newsrv = next;
	}
	// Move all srv with FLAG_DELETE to newsrv
	prev = NULL;
	srv = cfg->server;
	while (srv) {
		struct server_data *next = srv->next;
		if (srv->flags&FLAG_DELETE) {
			if (prev) prev->next = srv->next; else cfg->server = srv->next;
			cfg_addserver(newcfg, srv);
		} else prev = srv;
		srv = next;
	}
}


void update_cacheexservers(struct config_data *cfg, struct config_data *newcfg )
{
	// set remove flag to old deleted clients & update reused one
	struct server_data *srv = cfg->cacheexserver;
	while (srv) {
		struct server_data *newsrv = newcfg->cacheexserver;
		while (newsrv) {
			if ( !(newsrv->flags&FLAG_DELETE) )
			if ( !(srv->flags&FLAG_DELETE) )
			if ( srv->host==newsrv->host )
			if ( srv->port==newsrv->port )
			if ( !strcmp(srv->user, newsrv->user) ) break;
			newsrv = newsrv->next;
		}
		if (newsrv) {
			newsrv->flags |= FLAG_DELETE;
			// PASS
			if ( strcmp(srv->pass, newsrv->pass) ) {
				srv->flags |= FLAG_DISCONNECT;
				strcpy(srv->pass, newsrv->pass);
			}
			// TYPE
			if (srv->type!=newsrv->type) { // ???
				srv->flags |= FLAG_DISCONNECT;
				srv->type = newsrv->type;
			}
			// NEWCAMD KEY
			if ( (srv->type==TYPE_NEWCAMD) && memcmp(srv->key,newsrv->key, sizeof(srv->key)) ) {
				srv->flags |= FLAG_DISCONNECT;
				memcpy(srv->key,newsrv->key, sizeof(srv->key));
			}
			// csport
			if ( memcmp(srv->csport,newsrv->csport,sizeof(srv->csport)) ) {
				srv->flags |= FLAG_DISCONNECT;
				memcpy( srv->csport, newsrv->csport, sizeof(srv->csport) );
			}
			// priority
			srv->priority = newsrv->priority;
#ifdef CACHEEX
			srv->cacheex_mode = newsrv->cacheex_mode;
			srv->cacheex_maxhop = newsrv->cacheex_maxhop;
#ifndef PUBLIC
			srv->cacheex_forward = newsrv->cacheex_forward;
#endif
#endif
			// Share Limits
			if ( memcmp(srv->sharelimits, newsrv->sharelimits, sizeof(srv->sharelimits)) ) {
				srv->flags |= FLAG_DISCONNECT;
				memcpy(srv->sharelimits, newsrv->sharelimits, sizeof(srv->sharelimits));
			}
			// ACCEPTED SIDs
			void *tmp = srv->sids;
			srv->sids = newsrv->sids;
			newsrv->sids = tmp;
		}
		else srv->flags |= FLAG_DELETE;
		srv = srv->next;
	}
	// Move all newsrv without FLAG_DELETE to srv
	struct server_data *prev = NULL;
	struct server_data *newsrv = newcfg->cacheexserver;
	while (newsrv) {
		struct server_data *next = newsrv->next;
		if (!(newsrv->flags&FLAG_DELETE)) {
			if (prev) prev->next = newsrv->next; else newcfg->cacheexserver = newsrv->next;
			cfg_addserver(cfg, newsrv);
		} else prev = newsrv;
		newsrv = next;
	}
	// Move all srv with FLAG_DELETE to newsrv
	prev = NULL;
	srv = cfg->cacheexserver;
	while (srv) {
		struct server_data *next = srv->next;
		if (srv->flags&FLAG_DELETE) {
			if (prev) prev->next = srv->next; else cfg->cacheexserver = srv->next;
			cfg_addserver(newcfg, srv);
		} else prev = srv;
		srv = next;
	}
}


void get_cache_caids( struct config_data *cfg )
{
	struct cardserver_data *cs = cfg->cardserver;
	cfg->cache.caids[0] = cs->card.caid;
	cfg->cache.caids[1] = 0;
	//memset( &cfg->cache.caids[1], 0, sizeof(cfg->cache.caids) );
	while (cs) {
		uint16_t caid = cs->card.caid;
		// look for caid if isthere in list
		int count;
		for (count=0; count<31; count++) {
			if (cfg->cache.caids[count]==caid) break;
			if (!cfg->cache.caids[count]) {
				cfg->cache.caids[count] = caid;
				cfg->cache.caids[count+1] = 0;
				//printf(" cfg->cache.caids[] = %04X\n", caid);
				break;
			}
		}
		cs = cs->next;
	}
}

///////////////////////////////////////////////////////////////////////////////
void reread_config( struct config_data *cfg )
{
	void *pointer; // temp use
	struct config_data newcfg;

	// Remove files data from current config
	free_chinfo(cfg);
	free_ip2country(cfg);
	free_providers(cfg);

	init_config(&newcfg);
	newcfg.host = cfg->host;
	//usleep( 100000 );

	read_config( &newcfg );

	cfg->host = newcfg.host;
	cfg->files = newcfg.files;
	// Files+Data
	strcpy(cfg->stylesheet_file,newcfg.stylesheet_file);
    strcpy(cfg->javascript_file,newcfg.javascript_file);
	strcpy(cfg->channelinfo_file,newcfg.channelinfo_file);
	strcpy(cfg->providers_file,newcfg.providers_file);
	strcpy(cfg->ip2country_file,newcfg.ip2country_file);
	cfg->ip2country = newcfg.ip2country;
	cfg->chninfo = newcfg.chninfo;
	cfg->providers = newcfg.providers;

	memcpy( cfg->blockcountry, newcfg.blockcountry, sizeof(cfg->blockcountry) );
	memcpy( &cfg->delay, &newcfg.delay, sizeof(cfg->delay) );
	memcpy( cfg->nodeid, newcfg.nodeid, 8 );

	// HTTP SERVER
	strcpy(cfg->http.user, newcfg.http.user);
	strcpy(cfg->http.pass, newcfg.http.pass);
	strcpy(cfg->http.title, newcfg.http.title);
	memcpy( &cfg->http.show, &newcfg.http.show, sizeof(cfg->http.show) );
	cfg->http.autorefresh = newcfg.http.autorefresh;
	if (cfg->http.port!=newcfg.http.port) {
		//cfg->http.flags |= FLAG_DISCONNECT;
		cfg->http.port = newcfg.http.port;
		newcfg.http.handle = cfg->http.handle;
		cfg->http.handle = -1;
	}
	// update http file data
	pointer = cfg->http.files;
	cfg->http.files = newcfg.http.files;
	newcfg.http.files = pointer;
#ifdef TELNET
	// Telnet Server
	strcpy(cfg->telnet.user, newcfg.telnet.user);
	strcpy(cfg->telnet.pass, newcfg.telnet.pass);
	if (cfg->telnet.port!=newcfg.telnet.port) {
		//cfg->http.flags |= FLAG_DISCONNECT;
		cfg->telnet.port = newcfg.telnet.port;
		newcfg.telnet.handle = cfg->telnet.handle;
		cfg->telnet.handle = -1;
	}
#endif

#ifdef TESTCHANNEL
	cfg->testchn.caid = newcfg.testchn.caid;
	cfg->testchn.provid = newcfg.testchn.provid;
	cfg->testchn.sid = newcfg.testchn.sid;
#endif

	// DAB-DCW: remove old one and get new one
	void *tmp = cfg->bad_dcw;
	cfg->bad_dcw = newcfg.bad_dcw;
	newcfg.bad_dcw = tmp;

	// Servers

#ifdef FREECCCAM_SRV
	update_freecccam_server( cfg, &newcfg );
#endif

	update_cccam_servers( cfg, &newcfg );

#ifdef CAMD35_SRV
	update_camd35_servers( cfg, &newcfg );
#endif
#ifdef CS378X_SRV
	update_cs378x_servers( cfg, &newcfg );
#endif

	update_mgcamd_servers( cfg, &newcfg );


	cfg->cache.autoadd = newcfg.cache.autoadd;
	cfg->cache.autoenable = newcfg.cache.autoenable;
	cfg->cache.alivetime = newcfg.cache.alivetime;
	cfg->cache.threshold = newcfg.cache.threshold;
	cfg->cache.filter = newcfg.cache.filter;
	cfg->cache.filtertime = newcfg.cache.filtertime;
#ifndef PUBLIC
	cfg->cache.dcwcheck2 = newcfg.cache.dcwcheck2;
	cfg->cache.dcwcheck3 = newcfg.cache.dcwcheck3;
#endif
	cfg->cache.forward = newcfg.cache.forward;
	cfg->cache.faccept0onid = newcfg.cache.faccept0onid;
	memcpy( cfg->cache.caids, newcfg.cache.caids, sizeof(newcfg.cache.caids) );
	update_cache_servers( cfg, &newcfg );

	update_cardserver( cfg, &newcfg );

	cfg->newcamd.clientid = newcfg.newcamd.clientid;
	cfg->newcamd.dcwcheck = newcfg.newcamd.dcwcheck;
	cfg->newcamd.keepalive = newcfg.newcamd.keepalive;

	cfg->mgcamd.dcwcheck = newcfg.mgcamd.dcwcheck;
	cfg->mgcamd.keepalive = newcfg.mgcamd.keepalive;
	cfg->cccam.dcwcheck = newcfg.cccam.dcwcheck;
	cfg->cccam.keepalive = newcfg.cccam.keepalive;
	cfg->cs378x.keepalive = newcfg.cs378x.keepalive;

	update_servers( cfg, &newcfg );
	update_cacheexservers( cfg, &newcfg );


	///////////////////////////////////////////////////////////////////////////


	///////////////////////////////////////////////////////////////////////////
	// FREE NEWCFG
	///////////////////////////////////////////////////////////////////////////

	sleep( 1 );

	// http Server
	if (newcfg.http.handle>0) close(newcfg.http.handle);
	// Free http file data
	while (newcfg.http.files) {
		struct http_file_data *tmp = newcfg.http.files;
		newcfg.http.files = tmp->next;
		free( tmp );
	}

	// Server
	remove_servers(&newcfg);

#ifdef FREECCCAM_SRV
	// FreeCCcam Server
	remove_cccam_clients(&newcfg.freecccam.server);
	if (newcfg.freecccam.server.handle>0) close(newcfg.freecccam.server.handle);
#endif

	// CCcam Servers
	while (newcfg.cccam.server) {
		struct cccam_server_data *newsrv = newcfg.cccam.server;
		newcfg.cccam.server = newsrv->next;
		remove_cccam_clients( newsrv );
		remove_cccam_cacheexclients( newsrv );
		if (newsrv->handle>0) close(newsrv->handle);
		free( newsrv );
	}

#ifdef CAMD35_SRV
	// Camd35 Servers
	while (newcfg.camd35.server) {
		struct camd35_server_data *newsrv = newcfg.camd35.server;
		newcfg.camd35.server = newsrv->next;
		remove_camd35_clients( newsrv );
		remove_camd35_cacheexclients( newsrv );
		if (newsrv->handle>0) close(newsrv->handle);
		free( newsrv );
	}
#endif

#ifdef CS378X_SRV
	//cs378x
	while (newcfg.cs378x.server) {
		struct camd35_server_data *newsrv = newcfg.cs378x.server;
		newcfg.cs378x.server = newsrv->next;
		remove_camd35_clients( newsrv );
		remove_camd35_cacheexclients( newsrv );
		if (newsrv->handle>0) close(newsrv->handle);
		free( newsrv );
	}
#endif

	// Mgcamd Servers
	while (newcfg.mgcamd.server) {
		struct mgcamdserver_data *newsrv = newcfg.mgcamd.server;
		newcfg.mgcamd.server = newsrv->next;
		remove_mgcamd_clients( newsrv );
		if (newsrv->handle>0) close(newsrv->handle);
		free( newsrv );
	}

	// Cache Servers
	while (newcfg.cache.server) {
		struct cacheserver_data *newsrv = newcfg.cache.server;
		newcfg.cache.server = newsrv->next;
#ifdef PEERLIST
		fpeer_update(newsrv);
		ipeer_update(newsrv);
#endif
		remove_cache_peers( newsrv );
		if (newsrv->handle>0) close(newsrv->handle);
		free( newsrv );
	}

	// Cardservers
	while (newcfg.cardserver) {
		struct cardserver_data *newcs = newcfg.cardserver;
		newcfg.cardserver = newcs->next;
		remove_newcamd_clients( newcs );
		if (newcs->newcamd.handle>0) close(newcs->newcamd.handle);
		free( newcs );
	}

	// DAB-DCW
	while(newcfg.bad_dcw) {
		struct dcw_data *dcw = newcfg.bad_dcw;
		newcfg.bad_dcw = dcw->next;
		free( dcw );
	}

	///////////////////////////////////////////////////////////////////////////
	// DISCONNECT CFG
	///////////////////////////////////////////////////////////////////////////

	// Cardservers
	struct cardserver_data *cs = cfg->cardserver;
	while (cs) {
		struct cs_client_data *cli = cs->newcamd.client;
		while (cli) {
			if ( (cs->flags&FLAG_DISCONNECT)||(cs->newcamd.flags&FLAG_DISCONNECT)||(cli->flags&FLAG_DISCONNECT) ) if (cli->connection.status>0) cs_disconnect_cli( cli );
			cli->flags &= ~FLAG_DISCONNECT;
			cli = cli->next;
		}
		cs->newcamd.flags &= ~FLAG_DISCONNECT;
		cs->flags &= ~FLAG_DISCONNECT;
		cs = cs->next;
	}
/*
	// CCcam Server
	struct cccam_server_data *cccam = cfg->cccam.server;
	while (cccam) {
		struct cc_client_data *cli = cccam->client;
		while (cli) {
			if ( (cccam->flags&FLAG_DISCONNECT)||(cli->flags&FLAG_DISCONNECT) ) cc_disconnect_cli( cli );
			cli->flags &= ~FLAG_DISCONNECT;
			cli = cli->next;
		}
		cccam->flags &= ~FLAG_DISCONNECT;
		cccam = cccam->next;
	}
*/
	// Mgcamd Server
	struct mgcamdserver_data *mgcamd = cfg->mgcamd.server;
	while (mgcamd) {
		struct mg_client_data *cli = mgcamd->client;
		while (cli) {
			if ( (mgcamd->flags&FLAG_DISCONNECT)||(cli->flags&FLAG_DISCONNECT) ) if (cli->connection.status>0) mg_disconnect_cli( cli );
			cli->flags &= ~FLAG_DISCONNECT;
			cli = cli->next;
		}
		mgcamd->flags &= ~FLAG_DISCONNECT;
		mgcamd = mgcamd->next;
	}

	// Servers
	struct server_data *srv = cfg->server;
	while (srv) {
		if (srv->flags&FLAG_DISCONNECT) if (srv->connection.status>0) disconnect_srv( srv );
		srv->flags &= ~FLAG_DISCONNECT;
		srv = srv->next;
	}

	// Cache Peers
	struct cacheserver_data *cache = cfg->cache.server;
	while (cache) {
		struct cachepeer_data *peer = cache->peer;
		while (peer) {
			if (peer->flags&FLAG_DISCONNECT) {
				peer->ping = 0;
				peer->lastpingsent = 0;
			}
			peer->flags &= ~FLAG_DISCONNECT;
			peer = peer->next;
		}
		cache->flags &= ~FLAG_DISCONNECT;
		cache = cache->next;
	}

}




// Open ports
int check_config(struct config_data *cfg)
{

	get_cache_caids( cfg );

	// Open ports for new profiles
	struct cardserver_data *cs = cfg->cardserver;
	while (cs) {

		if (!cs->option.fsharenewcamd) {
			if (cs->newcamd.handle>0) {
				close(cs->newcamd.handle);
				cs->newcamd.handle = -1;
			}
		}
		else if (cs->newcamd.handle<=0) {
			if ( (cs->newcamd.port<1024)||(cs->newcamd.port>0xffff) ) {
				mlogf(LOGWARNING,getdbgflag(DBG_CONFIG,0,0)," [%s] Newcamd Server: invalid port value (%d)\n", cs->name, cs->newcamd.port);
				cs->newcamd.handle = -1;
			}
			else if ( (cs->newcamd.handle=CreateServerSockTcp_nonb(cs->newcamd.port, IP_ADRESS)) == -1) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," [%s] Newcamd Server: bind port failed (%d)\n", cs->name, cs->newcamd.port);
				cs->newcamd.handle = -1;
			}
			else {
				mlogf(LOGINFO,getdbgflag(DBG_CONFIG,0,0)," [%s] Newcamd Server started on port %d\n",cs->name,cs->newcamd.port);
				CHECK_IP_ADRESS(cs->newcamd.handle);
			}
		}

#ifdef RADEGAST_SRV
		if (cs->radegast.handle<=0) {
			if ( (cs->radegast.port<1024)||(cs->radegast.port>0xffff) ) {
				//mlogf(LOGWARNING,getdbgflag(DBG_CONFIG,0,0)," CardServer '%s': invalid port value (%d)\n", cs->name, cs->newcamd.port);
				cs->radegast.handle = -1;
			}
			else if ( (cs->radegast.handle=CreateServerSockTcp_nonb(cs->radegast.port, IP_ADRESS)) == -1) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," [%s] Radegast Server: bind port failed (%d)\n", cs->name, cs->radegast.port);
				cs->radegast.handle = -1;
			}
			else {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," [%s] Radegast Server started on port %d\n",cs->name,cs->radegast.port);
				CHECK_IP_ADRESS(cs->radegast.handle);
			}
		}
#endif
		cs = cs->next;
	}

	// HTTP Port
#ifdef HTTP_SRV
	if (cfg->http.handle<=0) {
		if ( (cfg->http.port<1024)||(cfg->http.port>0xffff) ) {
			mlogf(LOGWARNING,getdbgflag(DBG_CONFIG,0,0)," HTTP Server: invalid port value (%d)\n", cfg->http.port);
			cfg->http.handle = -1;
		}
		else if ( (cfg->http.handle=CreateServerSockTcp(cfg->http.port, IP_ADRESS)) == -1) {
			mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," HTTP Server: bind port failed (%d)\n", cfg->http.port);
			cfg->http.handle = -1;
		}
		else {
			mlogf(LOGINFO,getdbgflag(DBG_CONFIG,0,0)," HTTP server started on port %d\n",cfg->http.port);
			CHECK_IP_ADRESS(cfg->http.handle);
		}
	}
#endif

#ifdef TELNET
	// telnet Port
	if (cfg->telnet.handle<=0) {
		if ( (cfg->telnet.port<1024)||(cfg->telnet.port>0xffff) ) {
			mlogf(LOGWARNING,getdbgflag(DBG_CONFIG,0,0)," Telnet Server: invalid port value (%d)\n", cfg->telnet.port);
			cfg->telnet.handle = -1;
		}
		else if ( (cfg->telnet.handle=CreateServerSockTcp(cfg->telnet.port, IP_ADRESS)) == -1) {
			mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," Telnet Server: bind port failed (%d)\n", cfg->telnet.port);
			cfg->telnet.handle = -1;
		}
		else {
			mlogf(LOGINFO,getdbgflag(DBG_CONFIG,0,0)," Telnet server started on port %d\n",cfg->telnet.port);
			CHECK_IP_ADRESS(cfg->telnet.handle);
		}
	}
#endif

#ifdef CCCAM_SRV
	// Open port for CCcam server
	struct cccam_server_data *cccam = cfg->cccam.server;
	while (cccam) {
		if (cccam->handle<=0) {
			if ( (cccam->port<1024)||(cccam->port>0xffff) ) {
				mlogf(LOGWARNING,getdbgflag(DBG_CONFIG,0,0)," CCcam Server: invalid port value (%d)\n", cccam->port);
				cccam->handle = -1;
			}
			else if ( (cccam->handle=CreateServerSockTcp_nonb(cccam->port, IP_ADRESS)) == -1) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," CCcam Server: bind port failed (%d)\n", cccam->port);
				cccam->handle = -1;
			}
			else {
				mlogf(LOGINFO,getdbgflag(DBG_CONFIG,0,0)," CCcam server %d started on port %d (version: %s)\n",cccam->id, cccam->port,cfg->cccam.version);
				CHECK_IP_ADRESS(cccam->handle);
			}
		}
		cccam = cccam->next;
	}
#endif

#ifdef FREECCCAM_SRV
	// Open port
	if (cfg->freecccam.server.handle<=0) {
		if ( (cfg->freecccam.server.port<1024)||(cfg->freecccam.server.port>0xffff) ) {
			mlogf(LOGWARNING,getdbgflag(DBG_CONFIG,0,0)," FreeCCcam Server: invalid port value (%d)\n", cfg->freecccam.server.port);
			cfg->freecccam.server.handle = -1;
		}
		else if ( (cfg->freecccam.server.handle=CreateServerSockTcp_nonb(cfg->freecccam.server.port, IP_ADRESS)) == -1) {
			mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," FreeCCcam Server: bind port failed (%d)\n", cfg->freecccam.server.port);
			cfg->freecccam.server.handle = -1;
		}
		else {
			mlogf(LOGINFO,getdbgflag(DBG_CONFIG,0,0)," FreeCCcam server started on port %d\n",cfg->freecccam.server.port);
			CHECK_IP_ADRESS(cfg->freecccam.server.handle);
		}
	}
#endif

#ifdef MGCAMD_SRV
	// Open port for MGcamd servers
	struct mgcamdserver_data *mgcamd = cfg->mgcamd.server;
	while (mgcamd) {
		if (mgcamd->handle<=0) {
			if ( (mgcamd->port<1024)||(mgcamd->port>0xffff) ) {
				mlogf(LOGWARNING,getdbgflag(DBG_CONFIG,0,0)," MGcamd Server: invalid port value (%d)\n", mgcamd->port);
				mgcamd->handle = -1;
			}
			else if ( (mgcamd->handle=CreateServerSockTcp_nonb(mgcamd->port, IP_ADRESS)) == -1) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," MGcamd Server: bind port failed (%d)\n", mgcamd->port);
				mgcamd->handle = -1;
			}
			else {
				mlogf(LOGINFO,getdbgflag(DBG_CONFIG,0,0)," MGcamd server %d started on port %d\n", mgcamd->id, mgcamd->port);
				CHECK_IP_ADRESS(mgcamd->handle);
			}
		}
		mgcamd = mgcamd->next;
	}
#endif


#ifdef CAMD35_SRV
	// Open port for MGcamd servers
	struct camd35_server_data *camd35 = cfg->camd35.server;
	while (camd35) {
		if (camd35->handle<=0) {
			if ( (camd35->port<1024)||(camd35->port>0xffff) ) {
				mlogf(LOGWARNING,getdbgflag(DBG_CONFIG,0,0)," camd35 Server: invalid port value (%d)\n", camd35->port);
				camd35->handle = -1;
			}
			else if ( (camd35->handle=CreateServerSockUdp(camd35->port, IP_ADRESS)) == -1) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," camd35 Server: bind port failed (%d)\n", camd35->port);
				camd35->handle = -1;
			}
			else {
				mlogf(LOGINFO,getdbgflag(DBG_CONFIG,0,0)," camd35 Server started on port %d\n",camd35->port);
				CHECK_IP_ADRESS(camd35->handle);
			}
		}
		camd35 = camd35->next;
	}
#endif
#ifdef CS378X_SRV
	struct camd35_server_data *cs378x = cfg->cs378x.server;
	while (cs378x) {
		if (cs378x->handle<=0) {
			if ( (cs378x->port<1024)||(cs378x->port>0xffff) ) {
				mlogf(LOGWARNING,getdbgflag(DBG_CONFIG,0,0)," cs378x Server: invalid port value (%d)\n", cs378x->port);
				cs378x->handle = -1;
			}
			else if ( (cs378x->handle=CreateServerSockTcp_nonb(cs378x->port, IP_ADRESS)) == -1) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," cs378x Server: bind port failed (%d)\n", cs378x->port);
				cs378x->handle = -1;
			}
			else {
				mlogf(LOGINFO,getdbgflag(DBG_CONFIG,0,0)," cs378x Server started on port %d\n",cs378x->port);
				CHECK_IP_ADRESS(cs378x->handle);
			}
		}
		cs378x = cs378x->next;
	}
#endif


	// ADD TO EPOLL
	// Open port for Cache servers
	struct cacheserver_data *cache = cfg->cache.server;
	while (cache) {
		if (cache->handle<=0) {
			if ( (cache->port<1024)||(cache->port>0xffff) ) {
				mlogf(LOGWARNING,getdbgflag(DBG_CONFIG,0,0)," Cache Server: invalid port value (%d)\n", cache->port);
				cache->handle = -1;
			}
			else if ( (cache->handle=CreateServerSockUdp(cache->port, IP_ADRESS)) == -1) {
				mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," Cache Server: bind port failed (%d)\n", cache->port);
				cache->handle = -1;
			}
			else {
#ifdef EPOLL_CACHE
//				epoll_add( prg.epoll.cache, cache->handle, cache );
#endif
#ifndef PUBLIC
				int n = 1024 * 1024;
				if (setsockopt(cache->handle, SOL_SOCKET, SO_RCVBUF, &n, sizeof(n)) == -1) {
					mlogf(LOGERROR,getdbgflag(DBG_CONFIG,0,0)," setsockopt failure\n");
				}
#endif
				mlogf(LOGINFO,getdbgflag(DBG_CONFIG,0,0)," Cache server started on port %d\n",cache->port);
				CHECK_IP_ADRESS(cache->handle);
			}
		}

		// create cachepeer socket
		struct cachepeer_data *peer = cache->peer;
		while (peer) {
			peer->outsock = cache->handle; //if (peer->outsock<=0) peer->outsock = CreateClientSockUdp(0,0);
			peer = peer->next;
		}

		cache = cache->next;
	}



	return 0;
}


void cfg_set_id_counters(struct config_data *cfg)
{

	// Servers
	cfg->totalservers = 0;
	struct server_data *srv = cfg->server;
	while (srv) {
		if (!srv->id) {
			srv->id = cfg->serverid;
			cfg->serverid++;
		}
		cfg->totalservers++;
		srv = srv->next;
	}
	srv = cfg->cacheexserver;
	while (srv) {
		if (!srv->id) {
			srv->id = cfg->serverid;
			cfg->serverid++;
		}
		cfg->totalservers++;
		srv = srv->next;
	}

	// Profiles
	cfg->totalprofiles = 0;
	struct cardserver_data *cs = cfg->cardserver;
	while (cs) {
		if (!cs->id) {
			cs->id = cfg->cardserverid;
			cfg->cardserverid++;
		}
		cs->newcamd.totalclients = 0;
		struct cs_client_data *cli = cs->newcamd.client;
		while (cli) {
			cli->pid = cs->id;
			cli->cs = cs;

			if (!cli->id) {
				cli->id = cfg->clientid;
				cfg->clientid++;
			}
			cs->newcamd.totalclients++;
			cli = cli->next;
		}

		cfg->totalprofiles++;
		cs = cs->next;
	}

	// CCcam Servers/Clients
#ifdef CCCAM_SRV
	cfg->cccam.totalservers = 0;
	struct cccam_server_data *ccc = cfg->cccam.server;
	while (ccc) {
		ccc->totalclients = 0;
		if (!ccc->id) {
			ccc->id = cfg->cccam.serverid;
			cfg->cccam.serverid++;
		}
		// Normal Clients
		struct cc_client_data *cccli = ccc->client;
		while (cccli) {
			cccli->parent = ccc;
			if (!cccli->id) {
				cccli->id = cfg->cccam.clientid;
				cfg->cccam.clientid++;
			}
			ccc->totalclients++;
			cccli = cccli->next;
		}
		// CacheEX Clients
		cccli = ccc->cacheexclient;
		while (cccli) {
			cccli->parent = ccc;
			if (!cccli->id) {
				cccli->id = cfg->cccam.clientid;
				cfg->cccam.clientid++;
			}
			ccc->totalclients++;
			cccli = cccli->next;
		}
		//
		cfg->cccam.totalservers++;
		ccc = ccc->next;
	}
#endif

	// camd35 Servers/Clients
#ifdef CAMD35_SRV
	cfg->camd35.totalservers = 0;
	struct camd35_server_data *camd35 = cfg->camd35.server;
	while (camd35) {
		//
		if (!camd35->id) {
			camd35->id = cfg->camd35.serverid;
			cfg->camd35.serverid++;
		}
		// Normal Clients
		camd35->totalclients = 0;
		struct camd35_client_data *cli = camd35->client;
		while (cli) {
			//cli->srvid = camd35->id;
			if (!cli->id) {
				cli->id = cfg->camd35.clientid;
				cfg->camd35.clientid++;
			}
			camd35->totalclients++;
			cli = cli->next;
		}
		// CacheEX Clients
		cli = camd35->cacheexclient;
		while (cli) {
			//cli->srvid = camd35->id;
			if (!cli->id) {
				cli->id = cfg->camd35.clientid;
				cfg->camd35.clientid++;
			}
			camd35->totalclients++;
			cli = cli->next;
		}
		//
		cfg->camd35.totalservers++;
		camd35 = camd35->next;
	}
#endif

	// cs378x Servers/Clients
#ifdef CS378X_SRV
	cfg->cs378x.totalservers = 0;
	struct camd35_server_data *cs378x = cfg->cs378x.server;
	while (cs378x) {
		cs378x->totalclients = 0;
		if (!cs378x->id) {
			cs378x->id = cfg->cs378x.serverid;
			cfg->cs378x.serverid++;
		}
		// Normal Clients
		struct camd35_client_data *cli = cs378x->client;
		while (cli) {
			//cli->srvid = cs378x->id;
			if (!cli->id) {
				cli->id = cfg->cs378x.clientid;
				cfg->cs378x.clientid++;
			}
			cs378x->totalclients++;
			cli = cli->next;
		}
		// CacheEX Clients
		cli = cs378x->cacheexclient;
		while (cli) {
			//cli->srvid = cs378x->id;
			if (!cli->id) {
				cli->id = cfg->cs378x.clientid;
				cfg->cs378x.clientid++;
			}
			cs378x->totalclients++;
			cli = cli->next;
		}
		//
		cfg->cs378x.totalservers++;
		cs378x = cs378x->next;
	}
#endif

	// MGCAMD Clients
#ifdef MGCAMD_SRV
	cfg->mgcamd.totalservers = 0;
	struct mgcamdserver_data *mgcamd = cfg->mgcamd.server;
	while (mgcamd) {
		mgcamd->totalclients = 0;
		if (!mgcamd->id) {
			mgcamd->id = cfg->mgcamd.serverid;
			cfg->mgcamd.serverid++;
		}
		struct mg_client_data *cli = mgcamd->client;
		while (cli) {
			cli->parent = mgcamd;
			if (!cli->id) {
				cli->id = cfg->mgcamd.clientid;
				cfg->mgcamd.clientid++;
			}
			mgcamd->totalclients++;
			cli = cli->next;
		}
		cfg->mgcamd.totalservers++;
		mgcamd = mgcamd->next;
	}
#endif


	cfg->cache.totalservers = 0;
	struct cacheserver_data *cache = cfg->cache.server;
	while (cache) {
		cache->totalpeers = 0;
		if (!cache->id) {
			cache->id = cfg->cache.serverid;
			cfg->cache.serverid++;
		}
		struct cachepeer_data *peer = cache->peer;
		while (peer) {
			peer->srvid = cache->id;
			if (!peer->id) {
				peer->id = cfg->cache.peerid;
				cfg->cache.peerid++;
			}
			cache->totalpeers++;
			peer = peer->next;
		}
		cfg->cache.totalservers++;
		cache = cache->next;
	}

}



// Close ports
int done_config(struct config_data *cfg)
{
	// Close Newcamd/Radegast Clients Connections & profiles ports
	struct cardserver_data *cs = cfg->cardserver;
	while (cs) {
		if (cs->newcamd.handle>0) {
			close(cs->newcamd.handle);
			struct cs_client_data *cscli = cs->newcamd.client;
			while (cscli) {
				if (cscli->handle>0) close(cscli->handle);
				cscli = cscli->next;
			}
		}
#ifdef RADEGAST_SRV
		if (cs->radegast.handle>0) {
			close(cs->radegast.handle);
			struct rdgd_client_data *rdgdcli = cs->radegast.client;
			while (rdgdcli) {
				if (rdgdcli->handle>0) close(rdgdcli->handle);
				rdgdcli = rdgdcli->next;
			}
		}
#endif
		cs = cs->next;
	}

#ifdef HTTP_SRV
	// HTTP Port
	if (cfg->http.handle>0) close(cfg->http.handle);
#endif

#ifdef TELNET
	if (cfg->telnet.handle>0) close(cfg->telnet.handle);
#endif

#ifdef CCCAM_SRV
	struct cccam_server_data *cccam = cfg->cccam.server;
	while (cccam) {
		if (cccam->handle>0) close(cccam->handle);
		struct cc_client_data *cli = cccam->client;
		while (cli) {
			if (cli->handle>0) close(cli->handle);
			cli = cli->next;
		}
		cli = cccam->cacheexclient;
		while (cli) {
			if (cli->handle>0) close(cli->handle);
			cli = cli->next;
		}
		cccam = cccam->next;
	}
#endif


#ifdef FREECCCAM_SRV
	if (cfg->freecccam.server.handle>0) {
		close(cfg->freecccam.server.handle);
		struct cc_client_data *fcccli = cfg->freecccam.server.client;
		while (fcccli) {
			if (fcccli->handle>0) close(fcccli->handle);
			fcccli = fcccli->next;
		}
	}
#endif


#ifdef MGCAMD_SRV
	struct mgcamdserver_data *mgcamd = cfg->mgcamd.server;
	while (mgcamd) {
		if (mgcamd->handle>0) close(mgcamd->handle);
		struct mg_client_data *cli = mgcamd->client;
		while (cli) {
			if (cli->handle>0) close(cli->handle);
			cli = cli->next;
		}
		mgcamd = mgcamd->next;
	}
#endif


#ifdef CAMD35_SRV
	struct camd35_server_data *camd35 = cfg->camd35.server;
	while (camd35) {
		if (camd35->handle>0) close(camd35->handle);
/* no sockets for camd35 clients
		struct camd35_client_data *cli = camd35->client;
		while (cli) {
			if (cli->handle>0) close(cli->handle);
			cli = cli->next;
		}
*/
		camd35 = camd35->next;
	}
#endif

#ifdef CS378X_SRV
	struct camd35_server_data *cs378x = cfg->cs378x.server;
	while (cs378x) {
		if (cs378x->handle>0) close(cs378x->handle);
		struct camd35_client_data *cli = cs378x->client;
		while (cli) {
			if (cli->handle>0) close(cli->handle);
			cli = cli->next;
		}
		cli = cs378x->cacheexclient;
		while (cli) {
			if (cli->handle>0) close(cli->handle);
			cli = cli->next;
		}
		cs378x = cs378x->next;
	}
#endif

	// Close Cache Servers
	struct cacheserver_data *cache = cfg->cache.server;
	while (cache) {
		if (cache->handle>0) close(cache->handle);
		struct cachepeer_data *peer = cache->peer;
		while (peer) {
			//if (peer->outsock>0) close(peer->outsock);
			peer = peer->next;
		}
		cache = cache->next;
	}

	// Close Servers Connections
	struct server_data *srv = cfg->server;
	while (srv) {
		if (srv->handle>0) close(srv->handle);
		srv = srv->next;
	}

	// Close Cacheex Servers Connections
	srv = cfg->cacheexserver;
	while (srv) {
		if (srv->handle>0) close(srv->handle);
		srv = srv->next;
	}

	return 0;
}


// check if any profile updated for caid:provider
