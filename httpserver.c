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

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <sys/prctl.h>
#include <poll.h>

#endif

#include "debug.h"
#include "convert.h"
#include "tools.h"
#include "threads.h"
#include "ecmdata.h"

#ifdef CCCAM
#include "msg-cccam.h"
#endif

#include "config.h"
#include "sockets.h"

#include "httpserver.h"
#include "httpbuffer.c"
#include "dyn_buffer.c"

#include "main.h"

#include "images.c"
#include "country.c"
#include "httpstyle.c"



#define HTTP_GET  0
#define HTTP_POST 1
#define MAXHEADERS 20

struct cs_client_data *getnewcamdclientbyid(uint32_t id);
struct cccam_server_data *getcccamserverbyid(uint32_t id);
struct cc_client_data *getcccamclientbyid(uint32_t id);
struct cc_client_data *getcccamclientbyname(struct cccam_server_data *cccam, char *name);
#ifdef MGCAMD_SRV
struct mgcamdserver_data *getmgcamdserverbyid(uint32_t id);
struct mg_client_data *getmgcamdclientbyid(uint32_t id);
struct mg_client_data *getmgcamdclientbyname(struct mgcamdserver_data *mgcamd, char *name);
void mg_disconnect_cli(struct mg_client_data *cli);
#endif

#ifdef CS378X_SRV
struct camd35_client_data *getcs378xclientbyid(uint32_t id);
#endif

#ifdef CAMD35_SRV
struct camd35_client_data *getcamd35clientbyid(uint32_t id);
#endif


#define LIST_ACTIVE       0
#define LIST_CONNECTED    1
#define LIST_DISCONNECTED 2
#define LIST_ALL          3


#define ACTION_PAGE     0
#define ACTION_DIV      1
#define ACTION_ROW      2
#define ACTION_XML      3
#define ACTION_DISABLE  4
#define ACTION_ENABLE   5
#define ACTION_STATUS   6
#define ACTION_DEBUG    7
#define ACTION_UPDATE   8
#define ACTION_JSON     31



char HTTP_UPDATE_DIV[] = "\nvar autorefresh=%d;\nvar tautorefresh;\nfunction setautorefresh(t)\n{\n	clearTimeout(tautorefresh);\n	autorefresh = t;\n	if (t>0) tautorefresh = setTimeout('updateDiv()',autorefresh);\n}\nfunction updateDiv()\n{\n	var httpRequest;\n	try {\n		httpRequest = new XMLHttpRequest();  // Mozilla, Safari, etc\n	}\n	catch(trymicrosoft) {\n		try {\n			httpRequest = new ActiveXObject('Msxml2.XMLHTTP');\n		}\n		catch(oldermicrosoft) {\n			try {\n				httpRequest = new ActiveXObject('Microsoft.XMLHTTP');\n			}\n			catch(failed) {\n				httpRequest = false;\n			}\n		}\n	}\n	if (!httpRequest) {\n		alert('Your browser does not support Ajax.');\n		return false;\n	}\n	// Action http_request\n	httpRequest.onreadystatechange = function()\n	{\n		if (httpRequest.readyState == 4) {\n			if(httpRequest.status == 200) {\n				requestError=0;\n				document.getElementById('mainDiv').innerHTML = httpRequest.responseText;\n			}\n			tautorefresh = setTimeout('updateDiv()',autorefresh);\n		}\n	}\n	httpRequest.open('GET', '%s',true);\n	httpRequest.send(null);\n}\n";
char HTTP_UPDATE_ROW[] = "\nvar idx = 0;\nvar tupdateRow;\n\nfunction setupdateRow(id)\n{\n	clearTimeout(tupdateRow);\n	idx = id;\n	if (id>0) tupdateRow = setTimeout('updateRow()',1000);\n}\n\nvar lastidx = 0;\nvar requestError = 0;\nfunction updateRow()\n{\n	if (lastidx!=idx) {\n		requestError = 0;\n		lastidx = idx;\n	}\n	if ( !requestError && (idx>0) ) {\n		var httpRequest;\n		try {\n			httpRequest = new XMLHttpRequest();  // Mozilla, Safari, etc\n		}\n		catch(trymicrosoft) {\n			try {\n				httpRequest = new ActiveXObject('Msxml2.XMLHTTP');\n			}\n			catch(oldermicrosoft) {\n				try {\n					httpRequest = new ActiveXObject('Microsoft.XMLHTTP');\n				}\n				catch(failed) {\n					httpRequest = false;\n				}\n			}\n		}\n		if (!httpRequest) {\n			alert('Your browser does not support Ajax.');\n			return false;\n		}\n		var savedidx = idx;\n		// Action http_request\n		httpRequest.onreadystatechange = function()\n		{\n			if (httpRequest.readyState == 4) {\n				if (httpRequest.status == 200) {\n					requestError=0;\n					xmlupdateRow( httpRequest.responseXML, 'Row'+savedidx );\n				}\n				else {\n					requestError++;\n				}\n				tupdateRow = setTimeout('updateRow()',1000);\n			}\n		}\n		httpRequest.open('GET', %s, true);\n		httpRequest.send(null);\n		requestError++;\n	}\n}\n";


int getcountryimage( char *code )
{
	int i;
	for(i=0; i<MAX_COUNTRY_IMAGES; i++) {
		if ( !strcmp(country_images[i].code, code) ) return i;
	}
	return -1;
}

void getcountryhtml( char *code, char *html )
{
	int i;
	for(i=0; i<MAX_COUNTRY_IMAGES; i++) {
		if ( !strcmp(country_images[i].code, code) ) {
			sprintf(html,"<img src='/flag%s.gif'>", code);
			return;
		}
	}
	sprintf(html, "[%s]", code);
}


char *getcountrycodebyip(uint32_t ip)
{
	struct ip2country_data *data= cfg.ip2country;
	ip = (ip>>24&0xFF)|(ip>>8&0xFF00)|(ip<<8&0xFF0000)|(ip<<24&0xFF000000);  // from little endian -> big endian
	while (data) {
		if ( (ip>=data->ipstart)&&(ip<=data->ipend) ) return data->code;
		data = data->next;
	}
	return NULL;
}

int isblockedip(uint32_t ip)
{
	if (!cfg.blockcountry[0][0]) return 0; // accept
	char *p = getcountrycodebyip(ip);
	if (p) {
		int i;
		for(i=0; i<512; i++) {
			if (!cfg.blockcountry[i][0]) break;
			if ( !strcmp(cfg.blockcountry[i], p) ) return 1; // block
		}
	}
	return 0; // accept
}

char *getcountryname(char *code)
{
	int i;
	for(i=0; i<MAX_COUNTRY_IMAGES; i++) {
		if ( !strcmp(country_images[i].code, code) ) return country_images[i].name;
	}
	return NULL;
}

struct cachepeer_data *getpeerbyid(int id);
struct server_data *getsrvbyid(uint32_t id);
void cc_disconnect_cli(struct cc_client_data *cli);
char *src2string(int srctype, int srcid, char *ret);

typedef struct
{
	char name[256];
	char value[512];
} http_get;

typedef struct 
{
	int sock;
	uint32_t ip;
	struct dyn_buffer dbf;
	int type;//= (HTTP_GET/HTTP_POST)
	char path[512];
	char file[512];
	int http_version;//(0:1.0,1:1.1)
	char Host[100];//(localhost:9999)
	int Connection;//(1:keep-alive, 0:close);
	http_get getlist[MAXHEADERS];
	int getcount;
	http_get postlist[MAXHEADERS];
	int postcount;
	http_get headers[MAXHEADERS];
	int hdrcount;

} http_request;

void buf2str( char *dest, char *start, char *end)
{
  while (*start==' ') start++;
  while (start<=end)
  {
	*dest=*start;
	start++;
	dest++;
  }
  *dest='\0';
}

///////////////////////////////////////////////////////////////////////////////
char *isset_get(http_request *req, char *name)
{
  int i;
  char *n,*v;
  for(i=0; i<req->getcount; i++) {
    n = req->getlist[i].name;
    v = req->getlist[i].value;
    if (!strcmp(name, n)) {
		//printf("[$_GET] Name: '%s'    Value :'%s'\n", n,v);
		return v;
	}
  }
  return NULL;
}


///////////////////////////////////////////////////////////////////////////////
char *isset_header(http_request *req, char *name)
{
  int i;
  char *n,*v;
  //printf("Searching '%s'\n", name);
  for(i=0; i<req->hdrcount; i++) {
	//printf("[HEADER] Name: '%s'    Value :'%s'\n", req->headers[i].name, req->headers[i].value);
    n = req->headers[i].name;
    v = req->headers[i].value;
    if (!strcmp(name, n)) return v;
  }
  return NULL;
}

///////////////////////////////////////////////////////////////////////////////
void explode_get(http_request *req, char *get) // Get Variables
{
  char *end,*a;
  int i;
  i=0;
  //mlogf(LOGDEBUG,getdbgflag(DBG_HTTP,0,0),"explode_get()\n");
  while ( (end=strchr(get, '&')) ) 
  {
	*end = '\0';
        if (i>8) break; //@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
	if ( (a=strchr(get, '=')) ) {
	  *a='\0';
	  strncpy(req->getlist[i].name,get,255); 
	  strncpy(req->getlist[i].value,a+1,255);
	  //printf("$_GET['%s'] = '%s'\n",req->getlist[i].name,req->getlist[i].value);
	  i++;
	}
	get=end+1;
  }
  if ( (a=strchr(get, '=')) ) {
    *a='\0';
    strncpy(req->getlist[i].name,get,255);
    strncpy(req->getlist[i].value,a+1,255);
    //printf("$_GET['%s'] = '%s'\n",req->getlist[i].name,req->getlist[i].value);
    i++;
  }
  req->getcount=i;
}

///////////////////////////////////////////////////////////////////////////////
void explode_post(http_request *req, char *post)
{
  char *end,*a;
  int i;
  i=0;
  while ( (end=strchr(post, '&')) && i<MAXHEADERS ) 
  {
	*end = '\0';
	if ( (a=strchr(post, '=')) ) {
	  *a='\0';
	  strncpy(req->postlist[i].name,post,255); 
	  strncpy(req->postlist[i].value,a+1,255);
	  //printf("$_POST['%s'] = '%s'\n",req->postlist[i].name,req->postlist[i].value);
	  i++;
	}
	post=end+1;
  }
  if ( (a=strchr(post, '=')) && i<MAXHEADERS ) {
    *a='\0';
    strncpy(req->postlist[i].name,post,255);
    strncpy(req->postlist[i].value,a+1,255);
    i++;
  }
  req->postcount=i;
}

///////////////////////////////////////////////////////////////////////////////


int extractreq(http_request *req, char *buffer, int len )
{
	char *path_start, *path_end;
	char *rnrn, *slash;

	//printf("buffer size %d\n",len);
	//#Check Header
	if (!(rnrn=strstr( buffer, "\r\n\r\n"))) return -1;
	int reqsize = (rnrn-buffer)+4;
	//#Get Path
	path_start = buffer+4;
	while (*path_start==' ') path_start++;
	path_end=path_start;
	while (*path_end!=' ') path_end++;
	buf2str( req->path, path_start, path_end-1);
	//mlogf(LOGDEBUG,0, " HTTP PATH = '%s'\n", req->path);
	//#extract filename, and path
	slash = path_start = (char*)&req->path;
	while (*path_start) {
		if (*path_start=='/') slash=path_start;
		else if (*path_start=='?') {
			explode_get(req,path_start+1);
			*path_start='\0';
			break;
		}
		path_start++;
	}
	slash++;
	strncpy( req->file, slash, 100);
	//#Extract headers
	path_start = buffer+4;
	while ( (*path_start!='\r')&&(*path_start!='\n') ) path_start++;
	if (*path_start=='\r') path_start++;
	if (*path_start=='\n') path_start++;
	while ( path_start<rnrn && req->hdrcount<MAXHEADERS ) {
		// start = path_start
		//get end of line
		path_end = path_start;
		slash = NULL;
		while ( (*path_end!='\r')&&(*path_end!='\n')&&(*path_end!=0) ) {
			if (*path_end==':') if (!slash) slash = path_end;
			path_end++;
		}
		if (path_end==path_start) break; // end
		char tmp = *path_end;
		*path_end = 0;
		if (slash) {
			// Extract header name: value
			buf2str( req->headers[req->hdrcount].name , path_start, slash-1);
			buf2str( req->headers[req->hdrcount].value, slash+1, path_end-1);
			//printf(">> %s\n", path_start);
			//printf("[HEADER] Name: '%s'    Value :'%s'\n", req->headers[req->hdrcount].name, req->headers[req->hdrcount].value);
			//if ( !strcmp(req->headers[req->hdrcount].name,"Authorization") ) 
			req->hdrcount++;
		}
		*path_end = tmp;
		path_start = path_end;
		while ( (*path_start=='\r')||(*path_start=='\n') ) path_start++;
	}

	if ( !memcmp(buffer,"GET ",4) ) {
		//printf("requesttype = GET\n");
		req->type = HTTP_GET;
	}
	else if ( !memcmp(buffer,"POST",4) ) {
		//printf("requesttype = POST\n");
		req->type = HTTP_POST;
		int i;
		for(i=0; i<req->hdrcount; i++) {
			if ( !strcmp(req->headers[i].name,"Content-Length") ) {
				reqsize += atoi(req->headers[i].value);
				//printf("req size %d\n", reqsize);
				return reqsize;
			}
		}
	}
	return 0;
}




int parse_http_request(int sock, http_request *req )
{
	unsigned char buffer[2048]; // HTTP Header cant be greater than 1k
	int size;
	int totalsize = 0;
	memset(buffer,0,sizeof(buffer));
	memset(req,0, sizeof(http_request));
	size = recv( sock, buffer, sizeof(buffer), MSG_NOSIGNAL);
	if (size<10) return 0;
	totalsize += size;
	//printf("** Receiving %d bytes\n%s\n",size,buffer );
	if ( !memcmp(buffer,"GET ",4) || !memcmp(buffer,"POST",4) ) {
		buffer[size] = '\0';

		// Get Header
		while ( !strstr((char*)buffer, "\r\n\r\n") ) {
			struct pollfd pfd;
			pfd.fd = sock;
			pfd.events = POLLIN | POLLPRI;
			int retval = poll(&pfd, 1, 5000);
			if ( retval>0 )	{
				if ( pfd.revents & (POLLHUP|POLLNVAL) ) return 0; // Disconnect
				else if ( pfd.revents & (POLLIN|POLLPRI) ) {
					int len = recv(sock, (buffer+size), sizeof(buffer)-size, MSG_NOSIGNAL);
					//printf("** Receiving %d bytes\n",len );
					if (len<=0) return 0;
					size+=len;
					buffer[size]=0;
					totalsize += len;
				}
			}
			else if (retval==0) break;
			else return 0;
		}
		// Received Header
		//mlogf(LOGDEBUG,getdbgflag(DBG_HTTP,0,0)," Received Header >>>\n%s\n<<<\n", buffer);
		int ret = extractreq(req,(char*)buffer,size);
		if (ret==-1) return 0;
		//Get Data
		if (req->type==HTTP_POST) {
			while (ret>totalsize) {
				//printf("Waiting....\n");
				struct pollfd pfd;
				pfd.fd = sock;
				pfd.events = POLLIN | POLLPRI;
				int retval = poll(&pfd, 1, 5000);
				if ( retval>0 )	{
					if ( pfd.revents & (POLLHUP|POLLNVAL) ) return 0; // Disconnect
					else if ( pfd.revents & (POLLIN|POLLPRI) ) {
						if (size>=sizeof(buffer)) {
							dynbuf_write( &req->dbf, buffer, size);
							size = 0;
						}
						int len = recv(sock, (buffer+size), sizeof(buffer)-size, MSG_NOSIGNAL);
						//printf("** Receiving %d bytes\n",len );
						if (len<=0) return 0;
						size+=len;
						totalsize += len;
					}
				}
				else return 0;
			}
			if (size) dynbuf_write( &req->dbf, buffer, size);
		}
	}
	else return 0;
	return 1;
}



/// XXX: not thread safe
char channelname[256];
char *getchname(uint16_t caid, uint32_t prov, uint16_t sid )
{
	struct chninfo_data *chn= cfg.chninfo;
	while (chn) {
		if ( (chn->caid==caid)&&(chn->prov==prov)&&(chn->sid==sid) ) return chn->name;
		chn = chn->next;
	}
	sprintf(channelname, "%04X:%06X:%04X", caid, prov, sid );
	return channelname;
}

struct chninfo_data *getchninfo(uint16_t caid, uint32_t prov, uint16_t sid )
{
	struct chninfo_data *chn= cfg.chninfo;
	while (chn) {
		if ( (chn->caid==caid)&&(chn->prov==prov)&&(chn->sid==sid) ) return chn;
		chn = chn->next;
	}
	return NULL;;
}

int total_profiles()
{
	int count=0;
	struct cardserver_data *cs = cfg.cardserver;
	while(cs) {
		count++;
		cs = cs->next;
	}
	return count;
}	



int total_servers()
{
	int nb=0;
	struct server_data *srv=cfg.server;
	while (srv) {
		nb++;
		srv=srv->next;
	}
	return nb;
}

int connected_servers()
{
	int nb=0;
	struct server_data *srv=cfg.server;
	while (srv) {
		if ( !IS_DISABLED(srv->flags)&&(srv->handle>0) ) nb++;
		srv=srv->next;
	}
	return nb;
}

/*
int totalcachepeers()
{
	struct cachepeer_data *peer;
	int count=0;

	peer = cfg.cache.peer;
	while (peer) {
		count++;
		peer = peer->next;
	}
	return count;
}
*/

void cache_peers( struct cacheserver_data *cache, int *total, int *active )
{
	*total = 0;
	*active = 0;
	struct cachepeer_data *peer = cache->peer;
	while (peer) {
		(*total)++;
		if ( peer->ping>0 ) (*active)++;
		peer=peer->next;
	}
}

void total_cache_peers( int *total, int *active )
{
	*total = 0;
	*active = 0;
	struct cacheserver_data *cache = cfg.cache.server;
	while (cache) {
		struct cachepeer_data *peer = cache->peer;
		while (peer) {
			(*total)++;
			if ( peer->ping>0 ) (*active)++;
			peer=peer->next;
		}
		cache = cache->next;
	}
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

//color: #000000; background-color: #FFFFFF;
char http_replyok[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n";

char http_html[] = "<HTML>\n";
char http_html_[] = "</HTML>\n";

char http_head[] = "<HEAD>\n";
char http_head_[] = "</HEAD>\n";

char http_body[] = "<BODY>\n";
char http_body_[] = "</BODY>\n";

char html_title[] = "<title>%s - %s</title>\n";

char http_link[] = "<meta http-equiv=\"Content-type\" content=\"text/html; charset=utf-8\"/>\n";

char http_style[] = "<link rel=\"stylesheet\" href=\"style.css\" type=\"text/css\" />\n";

char http_javascript[] = "<script src=\"/customjs.js\"></script>\n";

#define PAGE_HOME      1
#define PAGE_SERVERS   2
#define PAGE_CACHE     3
#define PAGE_PROFILES  4
#define PAGE_NEWCAMD   5
#define PAGE_CCCAM     6
#define PAGE_FREECCCAM 7
#define PAGE_MGCAMD    8
#define PAGE_EDITOR    9
#define PAGE_RESTART   10
#define PAGE_CACHEEX   11

#define PAGE_CAMD35    12
#define PAGE_CS378X    13
#define PAGE_DEBUG     14


char *yesno( int a )
{
	static char yes[] ="YES";
	static char no[] ="NO";
	if (a) return yes; else return no;
}

char *onoff( int a )
{
	static char yes[] ="ON";
	static char no[] ="OFF";
	if (a) return yes; else return no;
}

int unreadsms()
{
	int nb = 0;
	struct cacheserver_data *cache = cfg.cache.server;
	while (cache) {
		struct cachepeer_data *peer = cache->peer;
		while (peer) {
			if ( (peer->sms)&&(peer->sms->status==0) ) nb++;
			peer = peer->next;
		}
		cache = cache->next;
	}
	return nb;
}		

void tcp_write_menu(struct tcp_buffer_data *tcpbuf, int sock, int selected)
{
	char *cNormal = "<li><a href='%s'>%s</a></li>";
	char *cSelected = "<li><a class=selected href='%s'>%s</a></li>";
	char *cDisabled = "<li><a class=disabled href='%s'>%s</a></li>";
	char *class;
	char buf[512];

	tcp_writestr(tcpbuf, sock, "<div class=menu><ul>" );
	// Home
	if (selected==PAGE_HOME) class = cSelected; else class = cNormal;
	sprintf( buf, class, "/", "Home"); tcp_writestr(tcpbuf, sock, buf);

	// Servers
	if ( !cfg.http.show.nodebug ) {
		if (selected==PAGE_DEBUG) class = cSelected; else class = cNormal;
		sprintf( buf, class, "/debug", "Debug"); tcp_writestr(tcpbuf, sock, buf);
	}

	// Threads
	//sprintf( buf, cNormal, "/threads", "Threads"); tcp_writestr(tcpbuf, sock, buf);

	// Servers
	if ( !cfg.http.show.noservers ) {
		if (cfg.server!=NULL) { 
			if (selected==PAGE_SERVERS) class = cSelected; else class = cNormal;
		} else class = cDisabled;
		sprintf( buf, class, "/servers", "Servers"); tcp_writestr(tcpbuf, sock, buf);
	}
	// Cache
	if ( !cfg.http.show.nocache ) {
		if (cfg.cache.server) {
			if (selected==PAGE_CACHE) class = cSelected; else class = cNormal;
		} else class = cDisabled;
		int unread = unreadsms();
		char cache[32] = "Cache";
		if (unread) sprintf( cache, "Cache (%d)", unread);
		sprintf( buf, class, "/cache", cache); tcp_writestr(tcpbuf, sock, buf);
	}
	// Profiles
	if (!cfg.http.show.noprofiles) {
		if (cfg.cardserver!=NULL) {
			if (selected==PAGE_PROFILES) class = cSelected; else class = cNormal;
		} else class = cDisabled;
		sprintf( buf, class, "/profiles", "Profiles"); tcp_writestr(tcpbuf, sock, buf);
	}
	// Newcamd
	if ( !cfg.http.show.nonewcamd ) {
		if (cfg.cardserver!=NULL) {
			if (selected==PAGE_NEWCAMD) class = cSelected; else class = cNormal;
		} else class = cDisabled;
		sprintf( buf, class, "/newcamd", "Newcamd"); tcp_writestr(tcpbuf, sock, buf);
	}
#ifdef MGCAMD_SRV
	if ( !cfg.http.show.noservers && (cfg.mgcamd.server!=NULL) ) {
		if (selected==PAGE_MGCAMD) class = cSelected; else class = cNormal;
		sprintf( buf, class, "/mgcamd", "Mgcamd"); tcp_writestr(tcpbuf, sock, buf);
	}
#endif

#ifdef CCCAM_SRV
	// CCcam
	if ( !cfg.http.show.nocccam && (cfg.cccam.server!=NULL) ) {
		if (selected==PAGE_CCCAM) class = cSelected; else class = cNormal;
		sprintf( buf, class, "/cccam", "CCcam"); tcp_writestr(tcpbuf, sock, buf);
	}
#endif

#ifdef CS378X_SRV
	// cs378x
	if (cfg.cs378x.server!=NULL) {
		if (selected==PAGE_CS378X) class = cSelected; else class = cNormal;
		sprintf( buf, class, "/cs378x", "Cs378x"); tcp_writestr(tcpbuf, sock, buf);
	}
#endif

#ifdef CAMD35_SRV
	// camd35
	if (cfg.camd35.server!=NULL) {
		if (selected==PAGE_CAMD35) class = cSelected; else class = cNormal;
		sprintf( buf, class, "/camd35", "Camd35"); tcp_writestr(tcpbuf, sock, buf);
	}
#endif

#ifdef CACHEEX
	// CacheEX
	if ( !cfg.http.show.nocacheex ) {
		if (selected==PAGE_CACHEEX) class = cSelected; else class = cNormal;
		sprintf( buf, class, "/cacheex", "CacheEX"); tcp_writestr(tcpbuf, sock, buf);
	}
#endif

#ifdef FREECCCAM_SRV
	// FreeCCcam
	if (cfg.freecccam.server.handle>0) {
		if (selected==PAGE_FREECCCAM) class = cSelected; else class = cNormal;
		sprintf( buf, class, "/freecccam", "FreeCCcam"); tcp_writestr(tcpbuf, sock, buf);
	}
#endif
	if (!cfg.http.show.noeditor) {
		if (selected==PAGE_EDITOR) class = cSelected; else class = cNormal;
		sprintf( buf, class, "/editor", "Editor"); tcp_writestr(tcpbuf, sock, buf);
	}
	if (!cfg.http.show.norestart) {
		if (selected==PAGE_RESTART) class = cSelected; else class = cNormal;
		sprintf( buf, class, "/restart", "Restart"); tcp_writestr(tcpbuf, sock, buf);
	}

	char tt[] = "</ul><span style='float:right;'>Multi Card Server r"REVISION_STR"</span></div>\n";
	tcp_writestr(tcpbuf, sock, tt);

	//
	if ( (selected!=PAGE_RESTART)&&(selected!=PAGE_EDITOR) ) {
		tcp_writestr(tcpbuf, sock, "<div align=right>Autorefresh <select onchange='setautorefresh(this.value);'>");
		if (cfg.http.autorefresh==0) tcp_writestr(tcpbuf, sock, "<option value=0 selected>OFF</option>");
		else tcp_writestr(tcpbuf, sock, "<option value=0>OFF</option>");
		int i;
		for (i=1; i<=10; i++) {
			if ( cfg.http.autorefresh==i ) sprintf( buf, "<option value=%d selected>%ds</option>", i*1000, i); else sprintf( buf, "<option value=%d>%ds</option>", i*1000, i);
			tcp_writestr(tcpbuf, sock, buf);
		}

		if ( cfg.http.autorefresh>10 ) {
			sprintf( buf, "<option value=%d selected>%ds</option>", cfg.http.autorefresh*1000, cfg.http.autorefresh); 
			tcp_writestr(tcpbuf, sock, buf);
		}
		tcp_writestr(tcpbuf, sock, "</select></div>\n");
	}
}




void tcp_writeecmdata(struct tcp_buffer_data *tcpbuf, int sock, int ecmok, int ecmnb)
{
	char http_buf[2048];
	if (ecmnb) {
		int n;
		if (ecmnb>9999999) n = (ecmok*10)/(ecmnb/10); else n = (ecmok*100)/ecmnb;
		sprintf( http_buf, "<td>%d<span style=\"float: right;\">%d%%</span></td>", ecmok, n );
	}
	else
		sprintf( http_buf, "<td><span style=\"float: right;\">0%%</span></td>" );
	tcp_write(tcpbuf, sock, http_buf, strlen(http_buf) );
}

void tcp_writeecmdata2(struct tcp_buffer_data *tcpbuf, int sock, int ecmok, int ecmnb)
{
	char http_buf[2048];
	if (ecmnb) {
		int n;
		if (ecmnb>9999999) n = (ecmok*10)/(ecmnb/10); else n = (ecmok*100)/ecmnb;
		sprintf( http_buf, "<td>%d / %d<span style=\"float: right;\">%d%%</span></td>", ecmok, ecmnb, n );
	}
	else
		sprintf( http_buf, "<td><span style=\"float: right;\">0%%</span></td>" );
	tcp_write(tcpbuf, sock, http_buf, strlen(http_buf) );
}

void getstatcell(int ecmok, int ecmnb, char *dest)
{
	if (ecmnb) {
		int n;
		if (ecmnb>9999999) n = (ecmok*10)/(ecmnb/10); else n = (ecmok*100)/ecmnb;
		sprintf( dest, "%d<span style=\"float: right;\">%d%%</span>", ecmok, n );
	}
	else sprintf( dest, "<span style=\"float: right;\">0%%</span>" );
}

void getstatcell2(int ecmok, int ecmnb, char *dest)
{
	if (ecmnb) {
		int n;
		if (ecmnb>9999999) n = (ecmok*10)/(ecmnb/10); else n = (ecmok*100)/ecmnb;
		sprintf( dest, "%d / %d<span style=\"float: right;\">%d%%</span>", ecmok, ecmnb, n );
	}
	else sprintf( dest, "<span style=\"float: right;\">0%%</span>" );
}

#include <sys/stat.h>

void http_send_file(int sock, http_request *req, char *type, char *fname)
{
	struct tcp_buffer_data tcpbuf;
	tcp_init(&tcpbuf);

	struct stat fstat;
	int fstatres=stat( fname, &fstat );	
	if ( fstatres<0 ) {
		mlogf(LOGERROR,DBG_HTTP," http: file %s not found\n",fname);
		// Not found
	}
	else {
		mlogf(LOGTRACE,DBG_HTTP," http: file %s size: %lld bytes\n",fname,(long long) fstat.st_size);
		FILE *fd = fopen( fname, "r");
		if (fd==NULL) {
			mlogf(LOGERROR,DBG_HTTP," http: could not open file %s for reading\n",fname);
			// ERROR
		}
		else {
			char buf[1024];
			sprintf( buf, "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", type, (int)fstat.st_size);
			mlogf(LOGTRACE,DBG_HTTP, " http: send headers: %s\n", buf);
			tcp_write(&tcpbuf, sock, buf, strlen(buf) );
			buf[0]=0;
			while (!feof(fd)) {
				int result = fread (buf,1, sizeof(buf),fd);
				if (result>0) {
					buf[result]=0;
					mlogf(LOGTRACE,DBG_HTTP," http: send %d bytes from file %s: %s \n",result,fname,buf);
					tcp_write(&tcpbuf, sock, (char*)buf, result );
				}
			}
			fclose(fd);
		}
	}
	tcp_flush(&tcpbuf, sock);
}


void http_send_answer(int sock, http_request *req, char *type, char *buf, int size)
{
	char http_buf[2048];
	struct tcp_buffer_data tcpbuf;
	tcp_init(&tcpbuf);
	sprintf( http_buf, "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", type, size);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	tcp_write(&tcpbuf, sock, (char*)buf, size );
	tcp_flush(&tcpbuf, sock);
}

void http_send_image(int sock, http_request *req, unsigned char *buf, int size, char *type)
{
	char http_buf[2048];
	struct tcp_buffer_data tcpbuf;
	tcp_init(&tcpbuf);
	sprintf( http_buf, "HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\nCache-Control: private, max-age=86400\r\nContent-Length: %d\r\nConnection: close\r\nContent-Type: image/%s\r\n\r\n", size, type);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	tcp_write(&tcpbuf, sock, (char*)buf, size );
	tcp_flush(&tcpbuf, sock);
}

void http_send_xml(int sock, http_request *req, char *buf, int size)
{
	char http_buf[2048];
	struct tcp_buffer_data tcpbuf;
	tcp_init(&tcpbuf);
	sprintf( http_buf, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nAccept-Ranges: bytes\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n", size);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	tcp_write(&tcpbuf, sock, (char*)buf, size );
	tcp_flush(&tcpbuf, sock);
}


void http_send_ok(int sock)
{
	char http_buf[100];
	struct tcp_buffer_data tcpbuf;
	tcp_init(&tcpbuf);
	sprintf( http_buf, "HTTP/1.1 200 OK\r\n\r\n");
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	tcp_flush(&tcpbuf, sock);
}


void http_send_text(int sock, char *buf)
{
	int size = strlen(buf);
	struct tcp_buffer_data tcpbuf;
	tcp_init(&tcpbuf);
	//char http_buf[100];
	//sprintf( http_buf, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n",size);
	//tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	tcp_write(&tcpbuf, sock, (char*)buf, size );
	tcp_flush(&tcpbuf, sock);
}




void http_send_ecmstatus(struct tcp_buffer_data *tcpbuf, int sock, ECM_DATA *ecm)
{
	char http_buf[2048];
	tcp_writestr(tcpbuf, sock, "<table class=\"infotable\"><tbody>\n" );
	sprintf( http_buf,"<tr><th>Current Ecm Request</th></tr>\n");
	tcp_write(tcpbuf, sock, http_buf, strlen(http_buf) );
	// Status Msg
	if (ecm->statusmsg) {
		sprintf( http_buf,"<tr><td>%s</td></tr>", ecm->statusmsg);
		tcp_write(tcpbuf, sock, http_buf, strlen(http_buf) );
	}
	// Channel name
	sprintf( http_buf,"<tr><td>Channel  %s</td></tr>\n", getchname(ecm->caid, ecm->provid, ecm->sid) );
	tcp_write(tcpbuf, sock, http_buf, strlen(http_buf) );
	// ECM
	sprintf( http_buf,"<tr><td>ECM(%d): ", ecm->ecmlen); tcp_write(tcpbuf, sock, http_buf, strlen(http_buf) );
	array2hex( ecm->ecm, http_buf, ecm->ecmlen );	tcp_write(tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"</td></tr>\n");
	// Last DCW
#ifdef CHECK_NEXTDCW
	if ( ecm->lastdecode.ecm && (ecm->lastdecode.counter>0) ) {
		sprintf( http_buf,"<tr><td>Previous CW: "); tcp_write(tcpbuf, sock, http_buf, strlen(http_buf) );
		array2hex( ecm->lastdecode.dcw, http_buf, 16 ); tcp_write(tcpbuf, sock, http_buf, strlen(http_buf) );
		tcp_writestr(tcpbuf, sock, "</td></tr>\n");
		if ((ecm->lastdecode.cwcycle&0xFE)=='0') sprintf( http_buf,"<tr><td>Next Cycle = CW%c</td></tr>\n", ecm->lastdecode.cwcycle);
		tcp_write(tcpbuf, sock, http_buf, strlen(http_buf) );
		if (ecm->lastdecode.error) {
			sprintf( http_buf,"<tr><td>Errors = %d</td></tr>\n", ecm->lastdecode.error);
			tcp_write(tcpbuf, sock, http_buf, strlen(http_buf) );
		}
		sprintf( http_buf,"<tr><td>Total Cycles = %d</td></tr>\n<tr><td>ECM Interval = %ds</td></tr>\n", ecm->lastdecode.counter, ecm->lastdecode.dcwchangetime/1000);
		tcp_write(tcpbuf, sock, http_buf, strlen(http_buf) );
	}
#endif
	// Servers
	if (ecm->server[0].srvid) {
		sprintf( http_buf, "<tr><td><table class='infotable'><tbody><tr><th width='30px'>ID</th><th width='250px'>Server</th><th width='50px'>Status</th><th width='70px'>Start time</th><th width='70px'>End time</th><th width='90px'>Elapsed time</th><th>CW</th></tr></tbody>");
		tcp_write(tcpbuf, sock, http_buf, strlen(http_buf) );
		int i;
		for(i=0; i<20; i++) {
			if (!ecm->server[i].srvid) break;
			char* str_srvstatus[] = { "WAIT", "OK", "NOK", "BUSY" };
			struct server_data *srv = getsrvbyid(ecm->server[i].srvid);
			if (srv) {
				sprintf( http_buf,"<tr><td>%d</td><td>%s:%d</td><td>%s</td><td>%dms</td>", i+1, srv->host->name, srv->port, str_srvstatus[ecm->server[i].flag], ecm->server[i].sendtime - ecm->recvtime );
				tcp_write(tcpbuf, sock, http_buf, strlen(http_buf) );
				// Recv Time
				if (ecm->server[i].statustime>ecm->server[i].sendtime)
					sprintf( http_buf,"<td>%dms</td><td>%dms</td>", ecm->server[i].statustime - ecm->recvtime, ecm->server[i].statustime-ecm->server[i].sendtime );
				else
					sprintf( http_buf,"<td>--</td><td>--</td>");
				tcp_write(tcpbuf, sock, http_buf, strlen(http_buf) );
				// DCW
				if (ecm->server[i].flag==ECM_SRV_REPLY_GOOD) {
					sprintf( http_buf,"<td>"); tcp_write(tcpbuf, sock, http_buf, strlen(http_buf) );
					array2hex( ecm->server[i].dcw, http_buf, 16 );	tcp_write(tcpbuf, sock, http_buf, strlen(http_buf) );
					sprintf( http_buf,"</td>"); tcp_write(tcpbuf, sock, http_buf, strlen(http_buf) );
				}
				else {
					sprintf( http_buf,"<td>--</td>");
					tcp_write(tcpbuf, sock, http_buf, strlen(http_buf) );
				}
				sprintf( http_buf,"</tr>");
				tcp_write(tcpbuf, sock, http_buf, strlen(http_buf) );
			}
		}
		tcp_writestr(tcpbuf, sock, "</tbody></table></td></tr>\n" );
	}
	// End of table
	tcp_writestr(tcpbuf, sock, "</tbody></table><br>\n");
}



void flagdebugvalue( char *str )
{
	uint32_t i,j,k;
	i = (flagdebug>>24);
	j = (flagdebug>>16)&0xff;
	k = flagdebug&0xffff;
	strcpy( str, "UNKNOWN");
	switch (i) {
		case DBG_ALL:
			strcpy( str, "ALL");
			break;
		case DBG_NEWCAMD:
			if (!j) strcpy( str, "PROFILES");
			else {
				struct cardserver_data *cs = getcsbyid(j);
				if (cs) {
					if (!k) sprintf( str, "[%s]", cs->name);
					else {
						struct cs_client_data *cli = getnewcamdclientbyid(k);
						if (cli) sprintf( str, "[%s] Newcamd Client '%s'", cs->name, cli->user);
						else sprintf( str, "[%s] Unknown Newcamd Client ID=%d", cs->name, k);
					}
				} else sprintf( str, "Unknown Profile ID=%d", j);
			}
			break;
		case DBG_CCCAM:
			if (!j) strcpy( str, "CCCAM");
			else {
				struct cccam_server_data *cc = getcccamserverbyid(j);
				if (cc) {
					if (!k) sprintf( str, "CCcam%d [%d]", cc->id, cc->port);
					else {
						struct cc_client_data *cli = getcccamclientbyid(k);
						if (cli) sprintf( str, "CCcam%d - Client '%s'", cc->id, cli->user);
						else sprintf( str, "CCcam%d - Unknown Client ID=%d", cc->id, k);
					}
				} else sprintf( str, "Unknown CCcam Server ID=%d", j);
			}
			break;
		case DBG_SERVER:
			if (!k) strcpy( str, "SERVERS");
			else {
				struct server_data *srv = getsrvbyid(k);
				if (srv) 
					sprintf( str, "Server (%s:%d)", srv->host->name, srv->port);
				else sprintf( str, "Unknown Server ID=%d", k);
			}
			break;
		case DBG_MGCAMD:
			if (!k) strcpy( str, "MGCAMD");
			else {
				struct mg_client_data *cli = getmgcamdclientbyid(k);
				if (cli)
					sprintf( str, "Mgcamd Client (%s)", cli->user);
				else sprintf( str, "Unknown Mgcamd Client ID=%d", k);
			}
			break;
		case DBG_CS378X:
			if (!k) strcpy( str, "CS378X");
			else {
				struct camd35_client_data *cli = getcs378xclientbyid(k);
				if (cli)
					sprintf( str, "Cs378x Client (%s)", cli->user);
				else sprintf( str, "Unknown Cs378x Client ID=%d", k);
			}
			break;
		case DBG_CAMD35:
			if (!k) strcpy( str, "CAMD35");
			else {
				struct camd35_client_data *cli = getcamd35clientbyid(k);
				if (cli)
					sprintf( str, "Camd35 Client (%s)", cli->user);
				else sprintf( str, "Unknown Camd35 Client ID=%d", k);
			}
			break;
		case DBG_ERROR:
			strcpy( str, "ERROR");
			break;

	}
}


void http_send_index(int sock, http_request *req)
{
	char http_buf[2048];
	struct tcp_buffer_data tcpbuf;

	// Action
	char *str_action = isset_get( req, "action");
	int get_action = 0;
	if (str_action) {
		if (!strcmp(str_action,"div")) get_action = 1;
		else if (!strcmp(str_action,"row")) get_action = 2;
		else str_action = NULL;
	}
	if (!str_action) str_action = "page";
	//
	tcp_init(&tcpbuf);
	if (get_action==0) {
		tcp_write(&tcpbuf, sock, http_replyok, strlen(http_replyok) );
		tcp_write(&tcpbuf, sock, http_html, strlen(http_html) );
		tcp_write(&tcpbuf, sock, http_head, strlen(http_head) );
		sprintf( http_buf, html_title, cfg.http.title, "Home"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		tcp_write(&tcpbuf, sock, http_link, strlen(http_link) );
		tcp_write(&tcpbuf, sock, http_style, strlen(http_style) );
		// JS
        tcp_write(&tcpbuf, sock, http_javascript, strlen(http_javascript) );
        tcp_writestr(&tcpbuf, sock, "\n<script type='text/javascript'>");
		// ACTIONS REQUEST
		tcp_writestr(&tcpbuf, sock, "\nfunction imgrequest( url, el )\n{\n	var httpRequest;\n	try { httpRequest = new XMLHttpRequest(); }\n	catch (trymicrosoft) { try { httpRequest = new ActiveXObject('Msxml2.XMLHTTP'); } catch (oldermicrosoft) { try { httpRequest = new ActiveXObject('Microsoft.XMLHTTP'); } catch(failed) { httpRequest = false; } } }\n	if (!httpRequest) { alert('Your browser does not support Ajax.'); return false; }\n	if ( typeof(el)!='undefined' ) {\n		el.onclick = null;\n		el.style.opacity = '0.7';\n		httpRequest.onreadystatechange = function()\n		{\n			if (httpRequest.readyState == 4) if (httpRequest.status == 200) el.style.opacity = '0.3';\n		}\n	}\n	httpRequest.open('GET', url, true);\n	httpRequest.send(null);\n}\n");
		// UPD DIV
		char url[256];
		sprintf( url, "/?action=div");
		sprintf( http_buf, HTTP_UPDATE_DIV, cfg.http.autorefresh*1000, url);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		//
		tcp_writestr(&tcpbuf, sock, "\nfunction start()\n{\n	 setautorefresh(autorefresh);\n}");
		tcp_writestr(&tcpbuf, sock, "\n</script>\n");
		tcp_write(&tcpbuf, sock, http_head_, strlen(http_head_) );
		tcp_writestr(&tcpbuf, sock, "<body onload=\"start();\">");
		tcp_write_menu(&tcpbuf, sock,PAGE_HOME);
		// DIV
		tcp_writestr(&tcpbuf, sock, "<div id='mainDiv'>");
	}

	tcp_writestr(&tcpbuf, sock, "<div style=\"margin-left:10px;\">");

	unsigned int d= GetTickCount()/1000;
	sprintf( http_buf,"Uptime: %02dd %02d:%02d:%02d", d/(3600*24), (d/3600)%24, (d/60)%60, d%60); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

	FILE *fp = fopen ("/proc/loadavg", "r");
	if (fp) {
		float avg1,avg2,avg3;
		char procs[20];
                int i = fscanf(fp, "%f %f %f %s", &avg1,&avg2,&avg3,procs);
		fclose(fp);
		sprintf( http_buf,"<br>Load Average: %01.2f %01.2f %01.2f %s", avg1,avg2,avg3,procs); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}

	fp = fopen ("/proc/meminfo", "r");
	if (fp) {
		int memfree;
		int i = fscanf (fp, "MemTotal: %*d kB MemFree: %d kB", &memfree);
		sprintf( http_buf,"<br>Free Memory: %d kB", memfree); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		fclose(fp);
	}
	sprintf( http_buf, "<br>Total Profiles: %d", cfg.totalprofiles ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf, "<br>Total Servers: %d", cfg.totalservers ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf, "<br>Total Cache Servers: %d", cfg.cache.totalservers ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf, "<br>Total CCcam Servers: %d", cfg.cccam.totalservers ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf, "<br>Total Mgcamd Servers: %d", cfg.mgcamd.totalservers ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf, "<br>Total Camd35 Servers: %d", cfg.camd35.totalservers ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf, "<br>Total cs378x Servers: %d", cfg.cs378x.totalservers ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"<br>NodeID = %02x%02x%02x%02x%02x%02x%02x%02x", cfg.nodeid[0], cfg.nodeid[1], cfg.nodeid[2], cfg.nodeid[3], cfg.nodeid[4], cfg.nodeid[5], cfg.nodeid[6], cfg.nodeid[7]); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"<br><br>Version: MultiCS r%s-%s\n</div>", REVISION_STR, GIT_COMMIT); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

	if (get_action==0) tcp_writestr(&tcpbuf, sock, "</body></html>");
	tcp_flush(&tcpbuf, sock);
}


void http_send_debug(int sock, http_request *req)
{
	char http_buf[MAX_DBGLINE_LEN];
	struct tcp_buffer_data tcpbuf;

	// Action
	char *str_action = isset_get( req, "action");
	int get_action = 0;
	if (str_action) {
		if (!strcmp(str_action,"div")) get_action = 1;
		else if (!strcmp(str_action,"row")) get_action = 2;
		else if (!strcmp(str_action,"debug")) {
			get_action = 3;
			char *str_value = isset_get( req, "value");
			if (str_value) {
				if (!strcmp(str_value,"ALL")) flagdebug = getdbgflag( DBG_ALL, 0, 0);
				//else if (!strcmp(str_value,"CONFIG")) flagdebug = getdbgflag( DBG_CONFIG, 0, 0);
				else if (!strcmp(str_value,"SERVER")) flagdebug = getdbgflag( DBG_SERVER, 0, 0);
				else if (!strcmp(str_value,"CACHE")) flagdebug = getdbgflag( DBG_CACHE, 0, 0);
				else if (!strcmp(str_value,"NEWCAMD")) flagdebug = getdbgflag( DBG_NEWCAMD, 0, 0);
				else if (!strcmp(str_value,"MGCAMD")) flagdebug = getdbgflag( DBG_MGCAMD, 0, 0);
				else if (!strcmp(str_value,"CCCAM")) flagdebug = getdbgflag( DBG_CCCAM, 0, 0);
#ifdef CS378X_SRV
				else if (!strcmp(str_value,"CS378X")) flagdebug = getdbgflag( DBG_CS378X, 0, 0);
#endif
#ifdef CACHEEX
				else if (!strcmp(str_value,"CACHEEX")) flagdebug = getdbgflag( DBG_CACHEEX, 0, 0);
#endif
				//else if (!strcmp(str_value,"HTTP")) flagdebug = getdbgflag( DBG_HTTP, 0, 0);
				else if (!strcmp(str_value,"ERROR")) flagdebug = getdbgflag( DBG_ERROR, 0, 0);
				//else return;
				http_send_ok(sock);
			}
			return;
		}
		else str_action = NULL;
	}
	if (!str_action) str_action = "page";
	//
	tcp_init(&tcpbuf);
	if (get_action==0) {
		tcp_write(&tcpbuf, sock, http_replyok, strlen(http_replyok) );
		tcp_write(&tcpbuf, sock, http_html, strlen(http_html) );
		tcp_write(&tcpbuf, sock, http_head, strlen(http_head) );
		sprintf( http_buf, html_title, cfg.http.title, "Debug"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		tcp_write(&tcpbuf, sock, http_link, strlen(http_link) );
		tcp_write(&tcpbuf, sock, http_style, strlen(http_style) );
		// JS
		tcp_write(&tcpbuf, sock, http_javascript, strlen(http_javascript) );
        tcp_writestr(&tcpbuf, sock, "\n<script type='text/javascript'>");
		// ACTIONS REQUEST
		tcp_writestr(&tcpbuf, sock, "\nfunction imgrequest( url, el )\n{\n	var httpRequest;\n	try { httpRequest = new XMLHttpRequest(); }\n	catch (trymicrosoft) { try { httpRequest = new ActiveXObject('Msxml2.XMLHTTP'); } catch (oldermicrosoft) { try { httpRequest = new ActiveXObject('Microsoft.XMLHTTP'); } catch(failed) { httpRequest = false; } } }\n	if (!httpRequest) { alert('Your browser does not support Ajax.'); return false; }\n	if ( typeof(el)!='undefined' ) {\n		el.onclick = null;\n		el.style.opacity = '0.7';\n		httpRequest.onreadystatechange = function()\n		{\n			if (httpRequest.readyState == 4) if (httpRequest.status == 200) el.style.opacity = '0.3';\n		}\n	}\n	httpRequest.open('GET', url, true);\n	httpRequest.send(null);\n}\n");
		// UPD DIV
		char url[256];
		sprintf( url, "/debug?action=div");
		sprintf( http_buf, HTTP_UPDATE_DIV, cfg.http.autorefresh*1000, url);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		//
		tcp_writestr(&tcpbuf, sock, "\nfunction start()\n{\n	 setautorefresh(autorefresh);\n}");
		tcp_writestr(&tcpbuf, sock, "\n</script>\n");
		tcp_write(&tcpbuf, sock, http_head_, strlen(http_head_) );
		tcp_writestr(&tcpbuf, sock, "<body onload=\"start();\">");
		tcp_write_menu(&tcpbuf, sock,PAGE_DEBUG);
		// DIV
		tcp_writestr(&tcpbuf, sock, "<div id='mainDiv'>");
	}

	if (!cfg.http.show.nodebug) {
		tcp_writestr(&tcpbuf, sock, "<br>\n<fieldset><legend> Debug: <select onchange=\"imgrequest('/debug?action=debug&amp;value='+this.value);\" style='width:250px;'>");
		int sel;
		if ( (flagdebug&0xffffff)!=0 ) {
			char str[255];
			flagdebugvalue( str );
			sprintf( http_buf, "<option>%s</option>",str);
			tcp_writestr(&tcpbuf, sock, http_buf);
			sel = 0x10;
		} else sel = (flagdebug>>24);
		if (sel==DBG_ALL) tcp_writestr(&tcpbuf, sock, "<option value='ALL' selected>ALL</option>"); else tcp_writestr(&tcpbuf, sock, "<option value='ALL'>ALL</option>");
		if (sel==DBG_SERVER) tcp_writestr(&tcpbuf, sock, "<option value='SERVER' selected>SERVERS</option>"); else tcp_writestr(&tcpbuf, sock, "<option value='SERVER'>SERVERS</option>");
		if (sel==DBG_CACHE) tcp_writestr(&tcpbuf, sock, "<option value='CACHE' selected>CACHE</option>"); else tcp_writestr(&tcpbuf, sock, "<option value='CACHE'>CACHE</option>"); 
		if (sel==DBG_NEWCAMD) tcp_writestr(&tcpbuf, sock, "<option value='NEWCAMD' selected>PROFILES</option>"); else tcp_writestr(&tcpbuf, sock, "<option value='NEWCAMD'>PROFILES</option>");
		if (sel==DBG_MGCAMD) tcp_writestr(&tcpbuf, sock, "<option value='MGCAMD' selected>MGCAMD</option>"); else tcp_writestr(&tcpbuf, sock, "<option value='MGCAMD'>MGCAMD</option>"); 
		if (sel==DBG_CCCAM) tcp_writestr(&tcpbuf, sock, "<option value='CCCAM' selected>CCCAM</option>"); else tcp_writestr(&tcpbuf, sock, "<option value='CCCAM'>CCCAM</option>");
#ifdef CS378X_SRV
		if (sel==DBG_CS378X) tcp_writestr(&tcpbuf, sock, "<option value='CS378X' selected>CS378X</option>"); else tcp_writestr(&tcpbuf, sock, "<option value='CS378X'>CS378X</option>"); 
#endif
#ifdef CACHEEX
		if (sel==DBG_CACHEEX) tcp_writestr(&tcpbuf, sock, "<option value='CACHEEX' selected>CACHEEX</option>"); else tcp_writestr(&tcpbuf, sock, "<option value='CACHEEX'>CACHEEX</option>"); 
#endif
#ifndef PUBLIC
		if (sel==DBG_ERROR) tcp_writestr(&tcpbuf, sock, "<option value='ERROR' selected>ERROR</option>"); else tcp_writestr(&tcpbuf, sock, "<option value='ERROR'>ERROR</option>");
#endif
		tcp_writestr(&tcpbuf, sock, "</select></legend>\n");
		sprintf( http_buf, "<pre style=\"font-size:10; color:#004455;\">"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		int current = idbgline;
		int i = current - 35;
		if (i<0) i += 70;
		do {
			sprintf( http_buf, "%s", dbgline[i] ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			i++;
			if (i>=MAX_DBGLINES) i=0;
		} while (i!=current);
		sprintf( http_buf, "</pre></fieldset>"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}

	if (get_action==0) {
		tcp_writestr(&tcpbuf, sock, "</div></body></html>");
	}
	tcp_flush(&tcpbuf, sock);
}

void http_send_restart(int sock, http_request *req)
{
	char http_buf[2048];
	struct tcp_buffer_data tcpbuf;
	tcp_init(&tcpbuf);
	tcp_write(&tcpbuf, sock, http_replyok, strlen(http_replyok) );
	tcp_write(&tcpbuf, sock, http_html, strlen(http_html) );
	tcp_write(&tcpbuf, sock, http_head, strlen(http_head) );
	sprintf( http_buf, html_title, cfg.http.title, "Restarting"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	//tcp_write(&tcpbuf, sock, http_link, strlen(http_link) );
	//tcp_write(&tcpbuf, sock, http_style, strlen(http_style) );
	tcp_write(&tcpbuf, sock, http_head_, strlen(http_head_) );
	tcp_write(&tcpbuf, sock, http_body, strlen(http_body) );
	//tcp_write_menu(&tcpbuf, sock,PAGE_RESTART);
	sprintf( http_buf, "<script type=\"text/JavaScript\"><!--\nsetTimeout(\"location.href = '/';\",5000);\n--></script>\n<h3>Restarting %s<br>Plesase Wait...</h3>", cfg.http.title);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	tcp_flush(&tcpbuf, sock);
	flag_debugfile = 1;
	mlogf(LOGINFO, 0 , " Restart: from http server\n");
	prg.restart = 1;
}


///////////////////////////////////////////////////////////////////////////////
// SERVERS
///////////////////////////////////////////////////////////////////////////////

char *srvtypename(struct server_data *srv)
{
	static char newcamd[] = "Newcamd";
	static char cccam[] = "CCcam";
	static char radegast[] = "Radegast";
#ifdef CACHEEX
	static char cacheex[] = "CacheEX";
	if (srv->cacheex_mode && (srv->type==TYPE_CCCAM)) return cacheex;
#endif
	if (srv->type==TYPE_NEWCAMD) return newcamd;
	if (srv->type==TYPE_CCCAM) return cccam;
	if (srv->type==TYPE_RADEGAST) return radegast;
	return NULL;
}
	

int srv_cardcount(struct server_data *srv, int uphops)
{
	int count=0;
	struct cs_card_data *card = srv->card;
	while (card) {
		if ( (uphops==-1) 
#ifdef CCCAM_CLI
			|| (card->uphops==uphops)
#endif
		) count++;
		card = card->next;
	}
	return count;
}


char *xmlescape( char *str )
{
// "   &quot;
// '   &apos;
// <   &lt;
// >   &gt;
// &   &amp;
	char exml[5000];
	char *src = str;
	char *dest = exml;
	while (*src) {
		switch (*src) {
			case '&':
				memcpy(dest,"&amp;", 5);
				dest +=5;
				break;				
			case '<':
				memcpy(dest,"&lt;", 4);
				dest +=4;
				break;				
			case '>':
				memcpy(dest,"&gt;", 4);
				dest +=4;
				break;				
			case '"':
				memcpy(dest,"&quot;", 6);
				dest +=6;
				break;				
			case '\'':
				memcpy(dest,"&apos;", 6);
				dest +=6;
				break;				
			default:
				*dest = *src;
				dest++;
		}
		src++;
	}
	*dest = 0;
	strcpy( str, exml);
	return str;
}

char *providerID( unsigned short caid, unsigned int provid )
{
	unsigned int caprovid = (caid<<16) | provid;
	struct providers_data *prov = cfg.providers;
	while (prov) {
		if (prov->caprovid==caprovid) return prov->name;
		prov = prov->next;
	}
	return NULL;
}

void getservercells(struct server_data *srv, char cell[8][2048] )
{
	char temp[2048];
	unsigned int ticks = GetTickCount();
	uint d;
	int i;
	memset(cell, 0, 8*2048);
	// CELL0
	uint32_t uptime;
	if (srv->connection.status>0) uptime = (ticks-srv->connection.time) + srv->connection.uptime; else uptime = srv->connection.uptime;
	d = uptime / (ticks/100);
	uptime /= 1000;
	sprintf( cell[0],"<span title='%02dd %02d:%02d:%02d'>%d%%</span>",uptime/(3600*24),(uptime/3600)%24,(uptime/60)%60,uptime%60 ,d);

	// CELL1
	sprintf( cell[1],"<a href=\"/server?id=%d\">%s:%d</a><br>", srv->id,srv->host->name,srv->port);
	if (!srv->host->ip && srv->host->clip)
		sprintf( temp,"0.0.0.0 (%s)",(char*)ip2string(srv->host->ip) );
	else {
		char *p = getcountrycodebyip(srv->host->ip);
		if (p) sprintf( temp,"<img src='/flag_%s.gif' title='%s'> %s", p, getcountryname(p), (char*)ip2string(srv->host->ip) ); else sprintf( temp,"%s",(char*)ip2string(srv->host->ip) );
	}
	strcat( cell[1], temp );
	// CELL2
	if (srv->type==TYPE_NEWCAMD) {
		if (srv->progname) {
			if (srv->version) sprintf( cell[2],"%s %s", srv->progname, srv->version);
			else strcpy( cell[2], srv->progname);
		}
		else sprintf( cell[2],"Newcamd");
	}
#ifdef CCCAM_CLI
	else if (srv->type==TYPE_CCCAM) {
		if (srv->handle>0)
			sprintf( cell[2],"%s %s<br>%02x%02x%02x%02x%02x%02x%02x%02x", srv->progname, srv->version, srv->nodeid[0],srv->nodeid[1],srv->nodeid[2],srv->nodeid[3],srv->nodeid[4],srv->nodeid[5],srv->nodeid[6],srv->nodeid[7]);
		else sprintf( cell[2],"CCcam");
#ifdef CACHEEX
		if (srv->cacheex_mode) strcat( cell[2], "<br>CacheEX");
#endif
		//if (srv->progname) sprintf( cell[2],"<td>CCcam(%s) %s", srv->progname, srv->version); else sprintf( cell[2],"<td>CCcam %s", srv->version);
	}
#endif
#ifdef RADEGAST_CLI
	else if (srv->type==TYPE_RADEGAST) sprintf( cell[2],"Radegast");
#endif
#ifdef CAMD35_CLI
	else if (srv->type==TYPE_CAMD35) sprintf( cell[2],"Camd35");
#endif
#ifdef CS378X_CLI
	else if (srv->type==TYPE_CS378X) sprintf( cell[2],"cs378x");
#endif
	else sprintf( cell[2],"Unknown");

	// CELL3
	if (srv->connection.status>0) {
		d = (ticks-srv->connection.time)/1000;
		sprintf( cell[3],"%02dd %02d:%02d:%02d", d/(3600*24),(d/3600)%24,(d/60)%60,d%60);
		if (srv->busy) sprintf( cell[7],"busy"); else sprintf( cell[7],"online");
	}
	else {
		sprintf( cell[7],"offline");
		if (srv->flags&FLAG_DELETE) sprintf( cell[3],"Removed");
		else if (srv->flags&FLAG_EXPIRED) sprintf( cell[3],"Expired");
		else if (srv->flags&FLAG_DISABLE) sprintf( cell[3],"Disabled");
		else sprintf( cell[3],"offline");
	}

#ifdef CCCAM_CLI
#ifdef CACHEEX
	if (srv->cacheex_mode) {
		sprintf( cell[4],"%d",srv->ecmnb);
		strcpy( cell[5], " "); // default
	}
	else
#endif
#endif
	{
		// CELL4
		if (srv->ecmnb)
			sprintf( cell[4],"%d / %d<span style=\"float: right;\">%d%%</span><br>Hits = %d",srv->ecmok ,srv->ecmnb, (srv->ecmok*100)/srv->ecmnb, srv->hits);
		else
			sprintf( cell[4],"<span style=\"float: right;\">0%%</span>");
		// CELL5
		if (srv->ecmok)
			sprintf( cell[5],"%d ms",(srv->ecmoktime/srv->ecmok) ); //, srv->hits );
		else
			sprintf( cell[5],"-- ms");
	}

	// CELL6
	strcpy( cell[6], " "); // default
	if (srv->connection.status>0) {
		if (srv->type==TYPE_CCCAM)
			sprintf( temp,"<b>Total Cards = %d</b> ( Hop1 = %d, Hop2 = %d )<font style=\"font-size: 9;\">", srv_cardcount(srv,-1), srv_cardcount(srv,1), srv_cardcount(srv,2) );
		else
			sprintf( temp,"<b>Total Cards = %d</b><font style=\"font-size: 9;\">", srv_cardcount(srv,-1) );
		strcpy( cell[6], temp );
		int icard = 0;
		struct cs_card_data *card = srv->card;
		while (card) {
			if (card->uphops<=1) {
				if (icard>3) {
					strcat( cell[6], "<br> ..." );
					break;
				}
				char *provname = providerID(card->caid,card->prov[0]);
				if (provname) sprintf( temp,"<br><b>%04x:</b> %x <font color=#CC3300>%s</font>",card->caid,card->prov[0], provname); else sprintf( temp,"<br><b>%04x:</b> %x",card->caid,card->prov[0]);
				strcat( cell[6], temp );
				for(i=1; i<card->nbprov; i++) {
					char *provname = providerID(card->caid,card->prov[i]);
					if (provname) sprintf( temp,", %x <font color=#CC3300>%s</font>", card->prov[i], provname); else sprintf( temp,", %x", card->prov[i]);
					if ( (strlen(cell[6])+strlen(temp))<sizeof(cell[6]) )  strcat( cell[6], temp );
				}
				icard++;
			}
			card = card->next;
		}
		strcat( cell[6],"</font>\0");
	}
	else {
		if (srv->statmsg) {
			if (srv->connection.lastseen) {
				d = (ticks-srv->connection.lastseen)/1000;
				sprintf( temp,"%s<br>Last Seen %02dd %02d:%02d:%02d", srv->statmsg, d/(3600*24),(d/3600)%24,(d/60)%60,d%60);
			}
			else sprintf( temp,"%s",srv->statmsg);
			strcpy( cell[6], temp );
		}
	}

	strcat( cell[6], "<span style='float:right;'>");
	if ( !(srv->flags&(FLAG_DELETE|FLAG_EXPIRED)) ) {
		if (srv->flags&FLAG_DISABLE) {
			sprintf( temp," <img title='Enable' src='enable.png' OnClick=\"imgrequest('/server?id=%d&action=enable',this);\">",srv->id);
			strcat( cell[6], temp );
		}
		else {
			sprintf( temp," <img title='disable' src='disable.png' OnClick=\"imgrequest('/server?id=%d&action=disable',this);\">",srv->id);
			strcat( cell[6], temp );
		}
	}
	sprintf( temp," <img title='Debug' src='debug.png' OnClick=\"imgrequest('/server?id=%d&action=debug',this);\">",srv->id);
	strcat( cell[6], temp );
	strcat( cell[6], "</span>");
}

void alltotal_servers( int *all, int *cccam, int *newcamd, int *radegast )
{
	*all = 0;
	*cccam = 0;
	*newcamd = 0;
	*radegast = 0;

	struct server_data *srv=cfg.server;
	while (srv) {
		(*all)++;
		if (srv->type==TYPE_CCCAM) (*cccam)++;
		else if (srv->type==TYPE_NEWCAMD) (*newcamd)++;
		else if (srv->type==TYPE_RADEGAST) (*radegast)++;
		srv=srv->next;
	}
}

void allconnected_servers( int *all, int *cccam, int *newcamd, int *radegast )
{
	*all = 0;
	*cccam = 0;
	*newcamd = 0;
	*radegast = 0;

	struct server_data *srv=cfg.server;
	while (srv) {
		if ( !IS_DISABLED(srv->flags)&&(srv->handle>0) ) {
			(*all)++;
			if (srv->type==TYPE_CCCAM) (*cccam)++;
			else if (srv->type==TYPE_NEWCAMD) (*newcamd)++;
			else if (srv->type==TYPE_RADEGAST) (*radegast)++;
		}
		srv=srv->next;
	}
}

void http_send_servers(int sock, http_request *req)
{
	char http_buf[5000];
	struct tcp_buffer_data tcpbuf;

	char cell[8][2048];
	struct server_data *srv;
	int i;

	// Action
	char *str_action = isset_get( req, "action");
	int get_action = 0;
	if (str_action) {
		if (!strcmp(str_action,"div")) get_action = 1;
		else if (!strcmp(str_action,"row")) get_action = 2;
		else str_action = NULL;
	}
	if (!str_action) str_action = "page";
	//
	char *str_type = isset_get( req, "type");
	int get_type = 0;
	if (str_type) {
		if (!strcmp(str_type,"cccam"))  get_type = 1;
		else if (!strcmp(str_type,"newcamd")) get_type = 2;
		else if (!strcmp(str_type,"radegast")) get_type = 3;
		else str_type = NULL;
	}
	if (!str_type) str_type = "all";
	//
	char *str_list = isset_get( req, "list");
	int get_list = LIST_ALL;
	if (str_list) {
		if (!strcmp(str_list,"connected")) get_list = LIST_CONNECTED;
		else if (!strcmp(str_list,"disconnected")) get_list = LIST_DISCONNECTED;
		else str_list = NULL;
	}
	if (!str_list) str_list = "all";

	//
	char *id = isset_get( req, "id");
	// Get Server ID
	if (id)	{
		i = atoi(id);
		//look for server
		srv = cfg.server;
		while (srv) {
			if (!(srv->flags&FLAG_DELETE)) {
				if (srv->id==(uint32_t)i) break;
			}
			srv = srv->next;
		}
		if (!srv) return;
		char *action = isset_get( req, "action");
		if (action) {
			if (!strcmp(action,"disable")) {
				srv->flags |= FLAG_DISABLE;
				if (srv->connection.status>0) disconnect_srv(srv);
			}
			else if (!strcmp(action,"enable")) {
				srv->flags &= ~FLAG_DISABLE;
				srv->host->checkiptime = 0;
			}
		}			
		// Send XML CELLS
		getservercells(srv,cell);
		for(i=0; i<8; i++) xmlescape( cell[i] );
		char buf[5000] = "";
		sprintf( buf, "<server>\n<c0>%s</c0>\n<c1>%s</c1>\n<c2>%s</c2>\n<c3_c>%s</c3_c>\n<c3>%s</c3>\n<c4>%s</c4>\n<c5>%s</c5>\n<c6>%s</c6>\n</server>\n",cell[0],cell[1],cell[2],cell[7],cell[3],cell[4],cell[5],cell[6] );
		http_send_xml( sock, req, buf, strlen(buf));
		return;
	}

	tcp_init(&tcpbuf);
	if (get_action==0) {
		tcp_write(&tcpbuf, sock, http_replyok, strlen(http_replyok) );
		tcp_write(&tcpbuf, sock, http_html, strlen(http_html) );
		tcp_write(&tcpbuf, sock, http_head, strlen(http_head) );
		sprintf( http_buf, html_title, cfg.http.title, "Servers"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		tcp_write(&tcpbuf, sock, http_link, strlen(http_link) );
		tcp_write(&tcpbuf, sock, http_style, strlen(http_style) );
		// JS
		tcp_write(&tcpbuf, sock, http_javascript, strlen(http_javascript) );
        tcp_writestr(&tcpbuf, sock, "\n<script type='text/javascript'>");
		// ACTIONS REQUEST
		tcp_writestr(&tcpbuf, sock, "\nfunction imgrequest( url, el )\n{\n	var httpRequest;\n	try { httpRequest = new XMLHttpRequest(); }\n	catch (trymicrosoft) { try { httpRequest = new ActiveXObject('Msxml2.XMLHTTP'); } catch (oldermicrosoft) { try { httpRequest = new ActiveXObject('Microsoft.XMLHTTP'); } catch(failed) { httpRequest = false; } } }\n	if (!httpRequest) { alert('Your browser does not support Ajax.'); return false; }\n	if ( typeof(el)!='undefined' ) {\n		el.onclick = null;\n		el.style.opacity = '0.7';\n		httpRequest.onreadystatechange = function()\n		{\n			if (httpRequest.readyState == 4) if (httpRequest.status == 200) el.style.opacity = '0.3';\n		}\n	}\n	httpRequest.open('GET', url, true);\n	httpRequest.send(null);\n}\n");
		// UPD ROW
		tcp_writestr(&tcpbuf, sock, "\nfunction xmlupdateRow( xmlDoc, id )\n{\n	var row = document.getElementById(id);\n	row.cells.item(0).innerHTML = xmlDoc.getElementsByTagName('c0')[0].childNodes[0].nodeValue;\n	row.cells.item(1).innerHTML = xmlDoc.getElementsByTagName('c1')[0].childNodes[0].nodeValue;\n	row.cells.item(2).innerHTML = xmlDoc.getElementsByTagName('c2')[0].childNodes[0].nodeValue;\n	row.cells.item(3).className = xmlDoc.getElementsByTagName('c3_c')[0].childNodes[0].nodeValue;\n	row.cells.item(3).innerHTML = xmlDoc.getElementsByTagName('c3')[0].childNodes[0].nodeValue;\n	row.cells.item(4).innerHTML = xmlDoc.getElementsByTagName('c4')[0].childNodes[0].nodeValue;\n	row.cells.item(5).innerHTML = xmlDoc.getElementsByTagName('c5')[0].childNodes[0].nodeValue;\n	row.cells.item(6).innerHTML = xmlDoc.getElementsByTagName('c6')[0].childNodes[0].nodeValue;\n}\n" );
		char url[256];
		sprintf( url, "'/servers?id='+idx");
		sprintf( http_buf, HTTP_UPDATE_ROW, url);
/////"\nvar idx = 0;\nvar lastidx = 0;\nvar requestError = 0;\nfunction updateRow()\n{\n	if (lastidx!=idx) {\n		requestError = 0;\n		lastidx = idx;\n	}\n	if ( !requestError && (idx>0) ) {\n		var httpRequest;\n		try {\n			httpRequest = new XMLHttpRequest();  // Mozilla, Safari, etc\n		}\n		catch(trymicrosoft) {\n			try {\n				httpRequest = new ActiveXObject('Msxml2.XMLHTTP');\n			}\n			catch(oldermicrosoft) {\n				try {\n					httpRequest = new ActiveXObject('Microsoft.XMLHTTP');\n				}\n				catch(failed) {\n					httpRequest = false;\n				}\n			}\n		}\n		if (!httpRequest) {\n			alert('Your browser does not support Ajax.');\n			return false;\n		}\n		var savedidx = idx;\n		// Action http_request\n		httpRequest.onreadystatechange = function()\n		{\n			if (httpRequest.readyState == 4) {\n				if (httpRequest.status == 200) {\n					requestError=0;\n					xmlupdateRow( httpRequest.responseXML, 'Row'+savedidx );\n				}\n				else {\n					requestError++;\n				}\n				t = setTimeout('updateRow()',1000);\n			}\n		}\n		httpRequest.open('GET', %s, true);\n		httpRequest.send(null);\n		requestError++;\n	} else t = setTimeout('updateRow()',1000);\n}\n"
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		// UPD DIV
		sprintf( url, "/servers?action=div&type=%s&list=%s", str_type, str_list);
		sprintf( http_buf, HTTP_UPDATE_DIV, cfg.http.autorefresh*1000, url);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		//
		tcp_writestr(&tcpbuf, sock, "\nfunction start()\n{\n	setautorefresh(autorefresh);\n}");
		tcp_writestr(&tcpbuf, sock, "\n</script>\n");
		tcp_write(&tcpbuf, sock, http_head_, strlen(http_head_) );
		tcp_writestr(&tcpbuf, sock, "<body onload=\"start();\">");
		tcp_write_menu(&tcpbuf, sock,PAGE_SERVERS);
		// DIV
		tcp_writestr(&tcpbuf, sock, "<div id='mainDiv'>");
	}
	//
	int iall, icccam, inewcamd, iradegast; // Total
	alltotal_servers( &iall, &icccam, &inewcamd, &iradegast );
	int jall, jcccam, jnewcamd, jradegast; // Connected
	allconnected_servers( &jall, &jcccam, &jnewcamd, &jradegast );
	//
	int connected = jall;
	int total = iall;
	if (get_type==1) { connected=jcccam; total=icccam; }
	else if (get_type==2) { connected=jnewcamd; total=inewcamd; }
	else if (get_type==3) { connected=jradegast; total=iradegast; }
	//
	tcp_writestr(&tcpbuf, sock, "<select style=\"width:200px;\" onchange=\"parent.location.href='/servers?type='+this.value\">");
	sprintf( http_buf, "<option value=all>All Servers (%d/%d)</option>",jall, iall );
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	if (inewcamd) {
		if (get_type==2) sprintf( http_buf, "<option value=newcamd selected>Newcamd Servers (%d/%d)</option>",jnewcamd,inewcamd );
		else sprintf( http_buf, "<option value=newcamd>Newcamd Servers (%d/%d)</option>",jnewcamd,inewcamd );
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}
	if (icccam) {
		if (get_type==1) sprintf( http_buf, "<option value=cccam selected>CCcam Servers (%d/%d)</option>",jcccam,icccam );
		else sprintf( http_buf, "<option value=cccam>CCcam Servers (%d/%d)</option>",jcccam,icccam );
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}
	if (iradegast) {
		if (get_type==3) sprintf( http_buf, "<option value=radegast>Radegast Servers (%d/%d)</option>",jradegast,iradegast );
		else sprintf( http_buf, "<option value=radegast selected>Radegast Servers (%d/%d)</option>",jradegast,iradegast );
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}
	tcp_writestr(&tcpbuf, sock, "</select>");
	//
	char *class1 = "button"; char *class2 = "sbutton";
	char *class;
	if (get_list==LIST_ALL) class = class2; else class = class1;
	sprintf( http_buf," <input type=button class=%s onclick=\"parent.location='/servers?type=%s&amp;list=all'\" value='All (%d)'>",class,str_type,total);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	if (get_list==LIST_CONNECTED) class = class2; else class = class1;
	sprintf( http_buf," <input type=button class=%s onclick=\"parent.location='/servers?type=%s&amp;list=connected'\" value='Connected (%d)'>",class,str_type,connected);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	if (get_list==LIST_DISCONNECTED) class = class2; else class = class1;
	sprintf( http_buf," <input type=button class=%s onclick=\"parent.location='/servers?type=%s&amp;list=disconnected'\" value='Disconnected (%d)'>",class,str_type,total-connected);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	// Table
	sprintf( http_buf, "<br><table class=maintable width=100%%>\n<tr><th width=20px>Uptime</th><th width=200px>Host</th><th width=100px>Server</th><th width=100px>Connected</th><th width=150px>Ecm OK</th><th width=50px>EcmTime</th><th>Cards</th></tr>\n");
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	srv = cfg.server;
	int alt = 0;

	if (get_type==0) {
		while (srv) {
			if (!(srv->flags&FLAG_DELETE))
			if ( ((get_list&LIST_CONNECTED)&&(srv->handle>0))||((get_list&LIST_DISCONNECTED)&&(srv->handle<=0)) ) {
				if (alt==1) alt=2; else alt=1;
				getservercells(srv,cell);
				sprintf( http_buf,"<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'><td align=\"center\">%s</td><td>%s</td><td>%s</td><td class=\"%s\">%s</td><td>%s</td><td align=\"center\">%s</td><td>%s</td></tr>\n",srv->id,alt,srv->id,cell[0],cell[1],cell[2],cell[7],cell[3],cell[4],cell[5],cell[6]);
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			}
			srv = srv->next;
		}
	}
	else if (get_type==1) {
		while (srv) {
			if (!(srv->flags&FLAG_DELETE))
			if (srv->type==TYPE_CCCAM)
			if ( ((get_list&LIST_CONNECTED)&&(srv->handle>0))||((get_list&LIST_DISCONNECTED)&&(srv->handle<=0)) ) {
				if (alt==1) alt=2; else alt=1;
				getservercells(srv,cell);
				sprintf( http_buf,"<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'><td align=\"center\">%s</td><td>%s</td><td>%s</td><td class=\"%s\">%s</td><td>%s</td><td align=\"center\">%s</td><td>%s</td></tr>\n",srv->id,alt,srv->id,cell[0],cell[1],cell[2],cell[7],cell[3],cell[4],cell[5],cell[6]);
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			}
			srv = srv->next;
		}
	}
	else if (get_type==2) {
		while (srv) {
			if (!(srv->flags&FLAG_DELETE))
			if (srv->type==TYPE_NEWCAMD)
			if ( ((get_list&LIST_CONNECTED)&&(srv->handle>0))||((get_list&LIST_DISCONNECTED)&&(srv->handle<=0)) ) {
				if (alt==1) alt=2; else alt=1;
				getservercells(srv,cell);
				sprintf( http_buf,"<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'><td align=\"center\">%s</td><td>%s</td><td>%s</td><td class=\"%s\">%s</td><td>%s</td><td align=\"center\">%s</td><td>%s</td></tr>\n",srv->id,alt,srv->id,cell[0],cell[1],cell[2],cell[7],cell[3],cell[4],cell[5],cell[6]);
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			}
			srv = srv->next;
		}
	}
	else if (get_type==3) {
		while (srv) {
			if (!(srv->flags&FLAG_DELETE))
			if (srv->type==TYPE_RADEGAST)
			if ( ((get_list&LIST_CONNECTED)&&(srv->handle>0))||((get_list&LIST_DISCONNECTED)&&(srv->handle<=0)) ) {
				if (alt==1) alt=2; else alt=1;
				getservercells(srv,cell);
				sprintf( http_buf,"<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'><td align=\"center\">%s</td><td>%s</td><td>%s</td><td class=\"%s\">%s</td><td>%s</td><td align=\"center\">%s</td><td>%s</td></tr>\n",srv->id,alt,srv->id,cell[0],cell[1],cell[2],cell[7],cell[3],cell[4],cell[5],cell[6]);
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			}
			srv = srv->next;
		}
	}
	tcp_writestr(&tcpbuf, sock, "</table>");

	if (get_action==0) {
		tcp_writestr(&tcpbuf, sock, "</div></body></html>");
	}
	tcp_flush(&tcpbuf, sock);
}



void http_send_server(int sock, http_request *req)
{
	char http_buf[2048];
	struct tcp_buffer_data tcpbuf;
	char *provname;

	//
	int get_id;
	char *str_id = isset_get( req, "id");
	if (str_id)	get_id = atoi(str_id); else return;

	//look for server
	struct server_data *srv = getsrvbyid( get_id );
	if (!srv) {
		tcp_init(&tcpbuf);
		tcp_write(&tcpbuf, sock, http_replyok, strlen(http_replyok) );
		sprintf( http_buf, "<br>Server not found (id=%d)<br>", get_id);
		tcp_flush(&tcpbuf, sock);
		return;
	}
	//
	// Action
	char *str_action = isset_get( req, "action");
	int get_action = 0;
	if (str_action) {
		if (!strcmp(str_action,"div")) get_action = 1;
		else if (!strcmp(str_action,"row")) get_action = 2;
		else if (!strcmp(str_action,"disable")) get_action = 3;
		else if (!strcmp(str_action,"enable")) get_action = 4;
		else if (!strcmp(str_action,"status")) get_action = 5;
		else if (!strcmp(str_action,"info")) get_action = 6; // XML info
		else if (!strcmp(str_action,"debug")) get_action = 7;
		else str_action = NULL;
	}
	if (!str_action) str_action = "page";
	//
	if (get_action==3) {
		srv->flags |= FLAG_DISABLE;
		if (srv->connection.status>0) disconnect_srv(srv);
		http_send_ok(sock);
		return;
	}
	else if (get_action==4) {
		srv->flags &= ~FLAG_DISABLE;
		srv->host->checkiptime = 0;
		http_send_ok(sock);
		return;
	}
	else if (get_action==5) {
		if (srv->handle>0) http_send_text(sock,"connected"); else http_send_text(sock,"disconnected");
		tcp_flush(&tcpbuf, sock);
		return;
	}
	else if (get_action==7) {
		flagdebug = getdbgflag( DBG_SERVER, 0, srv->id);
		http_send_ok(sock);
		return;
	}
	//

	// Send Server infoPage
	tcp_init(&tcpbuf);
	tcp_write(&tcpbuf, sock, http_replyok, strlen(http_replyok) );
	tcp_write(&tcpbuf, sock, http_html, strlen(http_html) );
	tcp_write(&tcpbuf, sock, http_head, strlen(http_head) );
	sprintf( http_buf, html_title, cfg.http.title, "Server"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	tcp_write(&tcpbuf, sock, http_link, strlen(http_link) );
	tcp_write(&tcpbuf, sock, http_style, strlen(http_style) );
	tcp_write(&tcpbuf, sock, http_head_, strlen(http_head_) );
	tcp_write(&tcpbuf, sock, http_body, strlen(http_body) );
	tcp_write_menu(&tcpbuf, sock,0);

	tcp_writestr(&tcpbuf, sock, "<table width=100%><tr><td style=\"vertical-align:top; width:40%\">");
	//
	tcp_writestr(&tcpbuf, sock, "<table class=infotable><tbody>\n<tr><th colspan=2>Server Informations</th></tr>\n" );
	// Host:Port
	sprintf( http_buf,"<tr><td class=left>Host</td><td class=right>%s : %d</td></tr>\n", srv->host->name, srv->port);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	// Server Type
	tcp_writestr(&tcpbuf, sock, "<tr><td class=left>Type</td><td class=right>");
	if (srv->type==TYPE_CCCAM) tcp_writestr(&tcpbuf, sock, "CCcam</td></tr>\n");
	else if (srv->type==TYPE_NEWCAMD) tcp_writestr(&tcpbuf, sock, "Newcamd</td></tr>\n");
	else if (srv->type==TYPE_RADEGAST) tcp_writestr(&tcpbuf, sock, "Radegast</td></tr>\n");
	// USER
	sprintf( http_buf,"<tr><td class=left>User</td><td class=right>%s</td></tr>\n",srv->user );
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	// Connection Time
	if (srv->connection.status>0) {
		tcp_writestr(&tcpbuf, sock, "<tr><td class=left>Status</td><td class=right>Connected</td></tr>\n");
		uint32_t d = (GetTickCount()-srv->connection.time)/1000;
		sprintf( http_buf,"<tr><td class=left>Connection time</td><td class=right>%02dd %02d:%02d:%02d</td></tr>\n", d/(3600*24), (d/3600)%24, (d/60)%60, d%60);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		// IP
		sprintf( http_buf,"<tr><td class=left>IP Address</td><td class=right>%s</td></tr>\n",(char*)ip2string(srv->host->ip) );
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		if (srv->type==TYPE_CCCAM) {
			// Version
			sprintf( http_buf,"<tr><td class=left>Version</td><td class=right>%s</td></tr>\n", srv->version);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			// Nodeid
			sprintf( http_buf,"<tr><td class=left>NodeID</td><td class=right>%02x%02x%02x%02x%02x%02x%02x%02x</td></tr>\n", srv->nodeid[0],srv->nodeid[1],srv->nodeid[2],srv->nodeid[3],srv->nodeid[4],srv->nodeid[5],srv->nodeid[6],srv->nodeid[7]);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		}
	}
	else {
		tcp_writestr(&tcpbuf, sock, "<tr><td class=left>Status</td><td class=right>Disconnected</td></tr>\n");
		if (srv->connection.lastseen) {
			uint32_t d = (GetTickCount()-srv->connection.lastseen)/1000;
			sprintf( http_buf,"<tr><td class=left>Last Seen</td><td class=right>%02dd %02d:%02d:%02d</td></tr>\n", d/(3600*24),(d/3600)%24,(d/60)%60,d%60);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		}
	}
	// UPTIME
	if ( srv->connection.uptime || (srv->connection.status>0) ) {
		uint32_t uptime;
		if (srv->connection.status>0) uptime = (GetTickCount()-srv->connection.time)+srv->connection.uptime; else uptime = srv->connection.uptime;
		uptime /= 1000;
		sprintf( http_buf,"<tr><td class=left>Uptime</td><td class=right>%02dd %02d:%02d:%02d</td></tr>",uptime/(3600*24),(uptime/3600)%24,(uptime/60)%60,uptime%60);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}
	// Priority
	sprintf( http_buf,"<tr><td class=left>Priority</td><td class=right>%d</td></tr>", srv->priority);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	// EOT
	tcp_writestr(&tcpbuf, sock, "</tbody></table><br>\n" );
	if (srv->ecmnb) {
		// Ecm Stat
		tcp_writestr(&tcpbuf, sock, "<table class=\"infotable\"><tbody>\n" );
		tcp_writestr(&tcpbuf, sock, "<tr><th colspan=2>ECM Statistics</th></tr>\n" );
		sprintf( http_buf, "<tr><td class=left>Total ECM requests</td><td class=right>%d</td></tr>\n", srv->ecmnb);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		sprintf( http_buf, "<tr><td class=left>Good ECM answer</td><td class=right>%d</td></tr>\n", srv->ecmok);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		//Ecm Time
		if (srv->ecmok) {
			sprintf( http_buf,"<tr><td class=left>Average Time</td><td class=right>%d ms</td></tr>\n",(srv->ecmoktime/srv->ecmok) );
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		}
		// EOT
		tcp_writestr(&tcpbuf, sock, "</tbody></table><br>\n" );
	}

	tcp_writestr(&tcpbuf, sock, "</td><td style=\"vertical-align:top;\">");

	if (srv->cstat[0].csid) { //Print used profiles
		sprintf( http_buf, "<br>Used Profiles<br><table class=option><tr><th width=200px>Profile name</th><th width=90px>Total ECM</th><th width=90px>Ecm OK</th><th width=90px>Ecm Time</th></tr>");
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		int alt=0;
		int i;
		for ( i=0; i<MAX_CSPORTS; i++ ) {
			if (!srv->cstat[i].csid) break;
			struct cardserver_data *cs = getcsbyid(srv->cstat[i].csid);
			if (!cs) continue;
			if (alt==1) alt=2; else alt=1;
			//Profile name
			sprintf( http_buf,"<tr><td class=alt%d><a href=\"/profile?id=%d\">%s</a></td>",alt, cs->id, cs->name); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			//TotalECM
			sprintf( http_buf, "<td class=alt%d align=center>%d</td>",alt, srv->cstat[i].ecmnb ); //,cs->ecmdenied);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			//ECM OK
			tcp_writeecmdata(&tcpbuf, sock, srv->cstat[i].ecmok, srv->cstat[i].ecmnb );
			//ECM TIME
			int temp;
			if (srv->cstat[i].ecmok) temp =  srv->cstat[i].ecmoktime/srv->cstat[i].ecmok; else temp=0;
			if (temp)
				sprintf( http_buf, "<td class=alt%d align=center>%dms</td>",alt, temp);
			else
				sprintf( http_buf, "<td class=alt%d align=center>-- ms</td>",alt);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			//Close Row
			sprintf( http_buf,"</tr>");
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		}
		sprintf( http_buf,"</table>");
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}
	// EOT
	tcp_writestr(&tcpbuf, sock, "</td></tr></table>");


		if (srv->handle>0) {
			// Print CardList
			if (srv->type==TYPE_CCCAM) {
				sprintf( http_buf, "<br>Total Cards = %d ( Hop1 = %d, Hop2 = %d )<br><table class=maintable width=100%%><tr><th width=120px>NodeID_CardID</th><th width=150px>EcmOK</th><th width=70px>EcmTime</th><th>Caid/Providers</th></tr>",srv_cardcount(srv,-1), srv_cardcount(srv,1), srv_cardcount(srv,2));
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				struct cs_card_data *card = srv->card;
				int alt=0;
				while(card) {
					if (alt==1) alt=2; else alt=1;
#ifdef CCCAM_CLI
					sprintf( http_buf,"<tr><td class=alt%d>%02x%02x%02x%02x%02x%02x%02x%02x_%x</td>",alt, card->nodeid[0], card->nodeid[1], card->nodeid[2], card->nodeid[3], card->nodeid[4], card->nodeid[5], card->nodeid[6], card->nodeid[7], card->shareid);
#else
					sprintf( http_buf,"<tr><td class=alt%d>%x</td>",alt, card->id);
#endif
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

#ifdef CCCAM_CLI
					sprintf( http_buf,"<td class=alt%d>%d / %d<span style=\"float:right\">",alt,card->ecmok,card->ecmnb);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

					if (card->ecmnb)					
						sprintf( http_buf,"%d%%</span></td>", card->ecmok*100/card->ecmnb);
					else
						sprintf( http_buf,"0%%</span></td>");
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

					if (card->ecmok)
						sprintf( http_buf,"<td class=alt%d align=center>%d ms</td>",alt, card->ecmoktime/card->ecmok );
					else
						sprintf( http_buf,"<td class=alt%d align=center>-- ms</td>",alt);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

					provname = providerID(card->caid,card->prov[0]);
					if (provname) sprintf( http_buf,"<td class=alt%d>[%d] <b>%04x:</b> %x <font color=#CC3300>%s</font>",alt,card->uphops,card->caid,card->prov[0], provname);
					else sprintf( http_buf,"<td class=alt%d>[%d] <b>%04x:</b> %x",alt,card->uphops,card->caid,card->prov[0]);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
#else
					provname = providerID(card->caid,card->prov[0]);
					if (provname) sprintf( http_buf,"<td class=alt%d><b>%04x:</b> %x <font color=#CC3300>%s</font>",alt,card->caid,card->prov[0], provname);
					else sprintf( http_buf,"<td class=alt%d><b>%04x:</b> %x",alt,card->caid,card->prov[0]);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
#endif
					int i;
					for(i=1; i<card->nbprov; i++) {
						provname = providerID(card->caid,card->prov[i]);
						if (provname) sprintf( http_buf,", %x <font color=#CC3300>%s</font>", card->prov[i], provname); else sprintf( http_buf,", %x", card->prov[i]);
						tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					}
					sprintf( http_buf,"</td></tr>");
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

					card = card->next;
				}
				sprintf( http_buf,"</table>");
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			}
			else {
				sprintf( http_buf, "<br>Cards:<br><table class=maintable width=100%%><tr><th>Caid/Providers</th></tr>");
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

				struct cs_card_data *card = srv->card;
				int alt=0;
				while(card) {
					if (alt==1) alt=2; else alt=1;
					provname = providerID(card->caid,card->prov[0]);
					if (provname) sprintf( http_buf,"<tr><td class=alt%d><b>%04x:</b> %x <font color=#CC3300>%s</font>",alt,card->caid,card->prov[0], provname);
					else sprintf( http_buf,"<tr><td class=alt%d><b>%04x:</b> %x",alt,card->caid,card->prov[0]);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					int i;
					for(i=1; i<card->nbprov; i++) {
						provname = providerID(card->caid,card->prov[i]);
						if (provname) sprintf( http_buf,", %x <font color=#CC3300>%s</font>", card->prov[i], provname);
						else sprintf( http_buf,", %x", card->prov[i]);
						tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					}
					sprintf( http_buf,"</td></tr>");
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

					card = card->next;
				}
				sprintf( http_buf,"</table>");
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			}
		}

	tcp_flush(&tcpbuf, sock);
}


///////////////////////////////////////////////////////////////////////////////
// [CACHE]
///////////////////////////////////////////////////////////////////////////////

inline int isactivepeer(struct cachepeer_data *peer)
{
	if ( peer->ping>0 ) return 1;
	return 0;
}

void getcachecells(struct cachepeer_data *peer, char cell[12][2048] )
{
	char temp[2048];

	memset(cell, 0, 12*2048);
	// CELL0#Host/port
#ifdef NEWCACHE
	if ( (peer->protocol)&&(peer->ping>0) ) {
		if (peer->sms) {
			if (peer->sms->status==0) sprintf( cell[0],"<span style='float:right'><img src=sms_new.gif></span><a href='/cachepeer?id=%d'>%s:%d</a>", peer->id, peer->host->name,peer->port);
			else  sprintf( cell[0],"<span style='float:right'><img src=sms_old.gif></span><a href='/cachepeer?id=%d'>%s:%d</a>", peer->id, peer->host->name,peer->port);
		}
		else sprintf( cell[0],"<a href='/cachepeer?id=%d'>%s:%d</a>", peer->id, peer->host->name,peer->port);
	}
	else
#endif
	sprintf( cell[0],"%s:%d", peer->host->name,peer->port);
	// CELL1#IP
	char *p = getcountrycodebyip(peer->host->ip);
	if (p) sprintf( cell[1],"<img src='/flag_%s.gif' title='%s'> %s", p, getcountryname(p), (char*)ip2string(peer->host->ip) ); else sprintf( cell[1],"%s",(char*)ip2string(peer->host->ip) );
	// CELL2#Program
	sprintf( cell[2],"%s %s", peer->program, peer->version);
	// CELL3 # Ping
	if (IS_DISABLED(peer->flags)) {
		sprintf( cell[3],"offline");
		sprintf( cell[4],"Dis.");
	}
	else {
		if ( peer->ping>0 ) {
			sprintf( cell[3],"online");
			sprintf( cell[4],"%d", peer->ping);
		}
		else {
			sprintf( cell[3],"offline");
			sprintf( cell[4],"?");
		}
		if (peer->csporthit[0].csid) {
			strcat( cell[4], "<table class=\"connect_data\">" );
#ifndef PUBLIC
			if (peer->ismultics) sprintf( temp,"<tr><td>Protocol</td><td>*%d</td></tr>", peer->protocol);
			else sprintf( temp,"<tr><td>Protocol</td><td>%d</td></tr>", peer->protocol);
			strcat( cell[4], temp );
#endif
			strcat( cell[4], "<tr><td width=150px>Profile</td><td>Hits</td></tr>" );
			int i;
			for(i=0; i<10; i++) {
				if (!peer->csporthit[i].csid) break;
				struct cardserver_data *cs = getcsbyid(peer->csporthit[i].csid);
				if (!cs) continue;
				sprintf( temp,"<tr><td>%s</td><td>%d</td></tr>", cs->name,peer->csporthit[i].hits);
				strcat( cell[4], temp );
			}
			strcat( cell[4], "</table>");
		}
	}



	// CELL4 # Request
	sprintf( cell[5],"%d",peer->reqnb);
	// CELL5 #
	sprintf( cell[6],"%d",peer->repok);

	sprintf( cell[7],"%d",peer->sentreq);
	sprintf( cell[8],"%d",peer->sentrep);

	// CELL8 # Cache Hits/Total
	getstatcell( peer->hitnb, cfg.cache.hits, cell[9] );
	// CELL9 # Instant Cache
	getstatcell( peer->ihitnb, peer->hitnb, cell[10] );
	// CELL10 # Last Used Cache
	if (peer->lastcaid) {
		sprintf( cell[11],"ch %s (%dms)", getchname(peer->lastcaid, peer->lastprov, peer->lastsid) , peer->lastdecodetime );
	}
	else strcpy( cell[11], " ");

	strcat( cell[11], "<span style='float:right;'>");
	if ( !(peer->flags&(FLAG_DELETE|FLAG_EXPIRED)) ) {
		if (peer->flags&FLAG_DISABLE) {
			sprintf( temp," <img title='Enable' src='enable.png' OnClick=\"imgrequest('/cachepeer?id=%d&action=enable',this);\">",peer->id);
			strcat( cell[11], temp );
		}
		else {
			sprintf( temp," <img title='disable' src='disable.png' OnClick=\"imgrequest('/cachepeer?id=%d&action=disable',this);\">",peer->id);
			strcat( cell[11], temp );
		}
	}
	//sprintf( temp," <img title='Debug' src='debug.png' OnClick=\"imgrequest('/cachepeer?id=%d&action=debug',this);\">",peer->id); strcat( cell[9], temp );
	strcat( cell[11], "</span>");

}

struct cacheserver_data *getcacheserverbyid(uint32_t id)
{
	struct cacheserver_data *cache = cfg.cache.server;
	while (cache) {
		if (!(cache->flags&FLAG_DELETE))
			if (cache->id==id) return cache;
		cache = cache->next;
	}
	return NULL;
}


void http_send_cache(int sock, http_request *req)
{
	char http_buf[2048];
	struct tcp_buffer_data tcpbuf;
	struct cachepeer_data *peer;
	char cell[12][2048];

	char *peerid = isset_get( req, "peerid");
	// Get Peer ID
	if (peerid)	{
		int i = atoi(peerid);
		//look for server
		struct cacheserver_data *cache = cfg.cache.server;
		while (cache) {
			peer = cache->peer;
			while (peer) {
				if (peer->id==(uint32_t)i) break;
				peer = peer->next;
			}
			cache = cache->next;
		}
		if (!peer) return;
		// Send XML CELLS
		getcachecells(peer,cell);
		for(i=0; i<12; i++) xmlescape( cell[i] );
		char buf[5000] = "";
		sprintf( buf, "<peer>\n<c0>%s</c0>\n<c1>%s</c1>\n<c2>%s</c2>\n<c3_c>%s</c3_c>\n<c3>%s</c3>\n<c4>%s</c4>\n<c5>%s</c5>\n<c6>%s</c6><c7>%s</c7><c8>%s</c8><c9>%s</c9><c10>%s</c10>\n</peer>\n",cell[0],cell[1],cell[2],cell[3],cell[4],cell[5],cell[6],cell[7],cell[8],cell[9],cell[10],cell[11] );
		http_send_xml( sock, req, buf, strlen(buf));
		return;
	}

	// Param Action
	char *str_action = isset_get( req, "action");
	int get_action = 0;
	if (str_action) {
		if (!strcmp(str_action,"div")) get_action = 1;
		else if (!strcmp(str_action,"row")) get_action = 2;
		else if (!strcmp(str_action,"disable")) {
			str_action = NULL;
			char *str_z = isset_get( req, "z"); // server ID
			if (str_z) {
				int get_z = atoi(str_z);
				struct cacheserver_data *cache = cfg.cache.server;
				while (cache) {
					peer = cache->peer;
					while (peer) {
						if ( (peer->ping>0)&&(peer->hitnb<get_z) ) {
							peer->flags |= FLAG_DISABLE;
							peer->nbcards = 0;
							peer->ping = 0;
						}
						peer = peer->next;
					}
					cache = cache->next;
				}
			}
		}
		else if (!strcmp(str_action,"config")) {
			tcp_init(&tcpbuf);
			struct cacheserver_data *cache = cfg.cache.server;
			while (cache) {
				sprintf( http_buf, "\n\nCACHE PORT: %d\n", cache->port);
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				peer = cache->peer;
				while (peer) {
					if (peer->ping>0) {
						sprintf( http_buf, "CACHE PEER: %s %d\n", peer->host->name, peer->port);
						tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					}
					peer = peer->next;
				}
				cache = cache->next;
			}
			tcp_flush(&tcpbuf, sock);
			return;
		}
		else str_action = NULL;
	}
	if (!str_action) str_action = "page";
	//
	char *str_id = isset_get( req, "id"); // server ID
	int get_id = 0;
	if (str_id)	get_id = atoi(str_id);
	// Param List
	char *str_list = isset_get( req, "list");
	int get_list = LIST_CONNECTED;
	if (str_list) {
		if (!strcmp(str_list,"active")) get_list = LIST_CONNECTED;
		else if (!strcmp(str_list,"inactive")) get_list = LIST_DISCONNECTED;
		else if (!strcmp(str_list,"all")) get_list = LIST_ALL;
		else str_list=NULL;
	}
	if (!str_list) str_list = "active";
	//
	//
	struct cacheserver_data *cache = NULL;
	if (get_id) {
		cache = getcacheserverbyid(get_id);
		if (!cache) return;
	}

	tcp_init(&tcpbuf);
	if (get_action==0) {
		tcp_write(&tcpbuf, sock, http_replyok, strlen(http_replyok) );
		tcp_write(&tcpbuf, sock, http_html, strlen(http_html) );
		tcp_write(&tcpbuf, sock, http_head, strlen(http_head) );
		sprintf( http_buf, html_title, cfg.http.title, "Cache"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		tcp_write(&tcpbuf, sock, http_link, strlen(http_link) );
		tcp_write(&tcpbuf, sock, http_style, strlen(http_style) );
		// JS
		tcp_write(&tcpbuf, sock, http_javascript, strlen(http_javascript) );
        tcp_writestr(&tcpbuf, sock, "\n<script type='text/javascript'>");
		// ACTIONS REQUEST
		tcp_writestr(&tcpbuf, sock, "\nfunction imgrequest( url, el )\n{\n	var httpRequest;\n	try { httpRequest = new XMLHttpRequest(); }\n	catch (trymicrosoft) { try { httpRequest = new ActiveXObject('Msxml2.XMLHTTP'); } catch (oldermicrosoft) { try { httpRequest = new ActiveXObject('Microsoft.XMLHTTP'); } catch(failed) { httpRequest = false; } } }\n	if (!httpRequest) { alert('Your browser does not support Ajax.'); return false; }\n	if ( typeof(el)!='undefined' ) {\n		el.onclick = null;\n		el.style.opacity = '0.7';\n		httpRequest.onreadystatechange = function()\n		{\n			if (httpRequest.readyState == 4) if (httpRequest.status == 200) el.style.opacity = '0.3';\n		}\n	}\n	httpRequest.open('GET', url, true);\n	httpRequest.send(null);\n}\n");
		// UPD ROW
		tcp_writestr(&tcpbuf, sock, "\nfunction xmlupdateRow( xmlDoc, id )\n{\n	var row = document.getElementById(id);\n	row.cells.item(0).innerHTML = xmlDoc.getElementsByTagName('c0')[0].childNodes[0].nodeValue;\n	row.cells.item(1).innerHTML = xmlDoc.getElementsByTagName('c1')[0].childNodes[0].nodeValue;\n	row.cells.item(2).innerHTML = xmlDoc.getElementsByTagName('c2')[0].childNodes[0].nodeValue;\n	row.cells.item(3).className = xmlDoc.getElementsByTagName('c3_c')[0].childNodes[0].nodeValue;\n	row.cells.item(3).innerHTML = xmlDoc.getElementsByTagName('c3')[0].childNodes[0].nodeValue;\n	row.cells.item(4).innerHTML = xmlDoc.getElementsByTagName('c4')[0].childNodes[0].nodeValue;\n	row.cells.item(5).innerHTML = xmlDoc.getElementsByTagName('c5')[0].childNodes[0].nodeValue;\n	row.cells.item(6).innerHTML = xmlDoc.getElementsByTagName('c6')[0].childNodes[0].nodeValue;\n	row.cells.item(7).innerHTML = xmlDoc.getElementsByTagName('c7')[0].childNodes[0].nodeValue;\n	row.cells.item(8).innerHTML = xmlDoc.getElementsByTagName('c8')[0].childNodes[0].nodeValue;\n	row.cells.item(9).innerHTML = xmlDoc.getElementsByTagName('c9')[0].childNodes[0].nodeValue;\n	row.cells.item(10).innerHTML = xmlDoc.getElementsByTagName('c10')[0].childNodes[0].nodeValue;\n}\n");
		char url[256];
		sprintf( url, "'/cache?peerid='+idx");
		sprintf( http_buf, HTTP_UPDATE_ROW, url);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		// UPD DIV
		sprintf( url, "/cache?action=div&list=%s", str_list);
		sprintf( http_buf, HTTP_UPDATE_DIV, cfg.http.autorefresh*1000, url);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		//
		tcp_writestr(&tcpbuf, sock, "\nfunction start()\n{\n	setautorefresh(autorefresh);\n}");
		tcp_writestr(&tcpbuf, sock, "\n</script>\n");
		tcp_write(&tcpbuf, sock, http_head_, strlen(http_head_) );
		tcp_writestr(&tcpbuf, sock, "<body onload=\"start();\">");
		tcp_write_menu(&tcpbuf, sock,PAGE_CACHE);
		// DIV
		tcp_writestr(&tcpbuf, sock, "<div id='mainDiv'>");
	}

	tcp_writestr(&tcpbuf, sock, "<table border=1 width=100%><tr>");
	sprintf( http_buf,"<td align=center>AliveTime = %ds</td>", cfg.cache.alivetime/1000 ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"<td align=center>Auto-Add = %s</td>", yesno(cfg.cache.autoadd) ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	if (cfg.cache.autoadd) {
		sprintf( http_buf,"<td align=center>Auto-Enable = %s</td>", yesno(cfg.cache.autoenable) ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}
	sprintf( http_buf,"<td align=center>Filter = %s</td>", onoff( cfg.cache.filter) ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"<td align=center>Total Requests = %d</td>",cfg.cache.req); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	if (cfg.cache.req>0) {
		sprintf( http_buf,"<td align=center>Total Replies = %d (%d%%)</td>", cfg.cache.rep, (cfg.cache.rep*100)/cfg.cache.req );
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	} else tcp_writestr(&tcpbuf, sock, "<td align=center>Total Replies = 0</td>" );
	tcp_writestr(&tcpbuf, sock, "</tr></table>");


	//
	tcp_writestr(&tcpbuf, sock, "<table style=\"margin:0px; padding:0px; border-width:0px; border-spacing: 1px;\"><tr>");
	tcp_writestr(&tcpbuf, sock, "<td style=\"margin:0px; padding:0px;\"><a href='/cache'><table border=1 width=200px>");
	// Total Servers
	sprintf( http_buf, "<tr><td>Total Cache Servers: %d</td></tr>", cfg.cache.totalservers ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	int total, active;
	total_cache_peers( &total, &active );
	sprintf( http_buf, "<tr><td>Active Peers: %d / %d</td></tr>", active, total ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	tcp_writestr(&tcpbuf, sock, "</table></a></td>");
	// Servers
	if (cfg.cache.server) {
		int counter = 0;
		struct cacheserver_data *cache = cfg.cache.server;
		while ( cache && (counter<5) ) {
			sprintf( http_buf, "<td style=\"margin:0px; padding: 0px;\"><a href='/cache?id=%d'><table border=1 width=150px>", cache->id);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			if (cache->handle>0) sprintf( http_buf, "<tr><td>cache %d [<span class=success>%d</span>]</td></tr>", cache->id, cache->port);
			else sprintf( http_buf, "<tr><td>cache %d [<span class=failed>%d</span>]</td></tr>", cache->id, cache->port);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			int total, active;
			cache_peers( cache, &total, &active );
			sprintf( http_buf, "<tr><td>Active: %d / %d</td></tr>", active, total);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			tcp_writestr(&tcpbuf, sock, "</table></a></td>");
			counter++;
			cache = cache->next;
		}
	}
	// End of table
	tcp_writestr(&tcpbuf, sock, "</tr></table><br>");

	// Buttons
	tcp_writestr(&tcpbuf, sock, "<select style=\"width:200px;\" onchange=\"parent.location.href='/cache?id='+this.value\">");
	sprintf( http_buf, "<option value=0>ALL (%d)</option>", cfg.cache.totalservers);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	struct cacheserver_data *tmp = cfg.cache.server;
	while (tmp) {
		if (get_id==tmp->id) sprintf( http_buf, "<option value=%d selected>[%d] cache %d</option>",tmp->id,tmp->port, tmp->id );
		else sprintf( http_buf, "<option value=%d>[%d] cache %d</option>",tmp->id,tmp->port, tmp->id );
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		tmp = tmp->next;
	}
	tcp_writestr(&tcpbuf, sock, "</select> ");
	//
	if (cache) cache_peers( cache, &total, &active ); else total_cache_peers( &total, &active );
	char *class1 = "button"; char *class2 = "sbutton";
	char *class;
	if (get_list==LIST_CONNECTED) class = class2; else class = class1;
	sprintf( http_buf, "<input type=button class=%s onclick=\"parent.location='/cache?id=%d&amp;list=active'\" value='Active Peers (%d)'>", class, get_id, active);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	if (get_list==LIST_DISCONNECTED) class = class2; else class = class1;
	sprintf( http_buf, "<input type=button class=%s onclick=\"parent.location='/cache?id=%d&amp;list=inactive'\" value='Inactive Peers (%d)'>", class, get_id, total-active);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	if (get_list==LIST_ALL) class = class2; else class = class1;
	sprintf( http_buf, " <input type=button class=%s onclick=\"parent.location='/cache?id=%d&amp;list=all'\" value='All Peers (%d)'>", class, get_id, total);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

	// Peers MainTable
	tcp_writestr(&tcpbuf,sock, "\n<table class=maintable width=100%>");
	tcp_writestr(&tcpbuf,sock, "\n<tr><th width=200px>Host</th><th width=110px>IP Address</th><th width=80px>Program</th><th width=30px>Ping</th><th width=70px>Requests</th><th width=70px>Replies</th><th width=70px>Sent REQ</th><th width=70px>Sent REP</th><th width=90px>Cache Hits</th><th width=80px>Instant Hits</th><th>Last Cache Hit</th></tr>\n");
	int alt=0;
	if (cache) {
		int total, active;
		cache_peers( cache, &total, &active );
		sprintf( http_buf,"\n<tr><td class=alt3 colspan=12> cache %d (%d)</td></tr>", cache->id, active); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		peer = cache->peer;
		while (peer) {
			int isactive = isactivepeer(peer);
			if ( (isactive&&(get_list&LIST_CONNECTED)) || (!isactive&&(get_list&LIST_DISCONNECTED)) ) {
				if (alt==1) alt=2; else alt=1;
				getcachecells(peer, cell);
				if (peer->runtime) alt=3;
				sprintf( http_buf,"<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'><td>%s</td><td>%s</td><td>%s</td><td class=\"%s\">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",peer->id,alt,peer->id,cell[0],cell[1],cell[2],cell[3],cell[4],cell[5],cell[6],cell[7],cell[8],cell[9],cell[10],cell[11]);
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			}
			peer = peer->next;
		}
		// Total
		cache_peers( cache, &total, &active );
		sprintf( http_buf,"<tr class=alt3><td align=right>Total</td><td colspan=3>%d</td>",total);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		int totreq = 0;
		int totrepok = 0;
		int tothits = 0;
		int totihits = 0;

		peer = cache->peer;
		while (peer) {
			totreq += peer->reqnb;
			totrepok += peer->repok;
			tothits += peer->hitnb;
			totihits += peer->ihitnb;
			peer = peer->next;
		}
		sprintf( http_buf,"<td>%d</td>",totreq); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		sprintf( http_buf,"<td>%d</td>",totrepok); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		sprintf( http_buf,"<td colspan=2> </td>"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		tcp_writeecmdata(&tcpbuf, sock, tothits, cfg.cache.hits);
		tcp_writeecmdata(&tcpbuf, sock, totihits, tothits);
		sprintf( http_buf,"<td> </td></tr>"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}
	else {
		cache = cfg.cache.server;
		while (cache) {
			int total, active;
			cache_peers( cache, &total, &active );
			sprintf( http_buf,"\n<tr><td class=alt3 colspan=12> cache %d (%d)</td></tr>", cache->id, active); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			peer = cache->peer;
			while (peer) {
				int isactive = isactivepeer(peer);
				if ( (isactive&&(get_list&LIST_CONNECTED)) || (!isactive&&(get_list&LIST_DISCONNECTED)) ) {
					if (alt==1) alt=2; else alt=1;
					getcachecells(peer, cell);
					if (peer->runtime) alt=3;
					sprintf( http_buf,"<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'><td>%s</td><td>%s</td><td>%s</td><td class=\"%s\">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",peer->id,alt,peer->id,cell[0],cell[1],cell[2],cell[3],cell[4],cell[5],cell[6],cell[7],cell[8],cell[9],cell[10],cell[11]);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				}
				peer = peer->next;
			}
			cache = cache->next;
		}

		// Total
		total_cache_peers( &total, &active );
		sprintf( http_buf,"<tr class=alt3><td align=right>Total</td><td colspan=3>%d</td>",total);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		int totreq = 0;
		int totrepok = 0;
		int tothits = 0;
		int totihits = 0;

		cache = cfg.cache.server;
		while (cache) {
			peer = cache->peer;
			while (peer) {
				totreq += peer->reqnb;
				totrepok += peer->repok;
				tothits += peer->hitnb;
				totihits += peer->ihitnb;
				peer = peer->next;
			}
			cache = cache->next;
		}

		sprintf( http_buf,"<td>%d</td>",totreq); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		sprintf( http_buf,"<td>%d</td>",totrepok); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		sprintf( http_buf,"<td colspan=2> </td>"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		tcp_writeecmdata(&tcpbuf, sock, tothits, cfg.cache.hits);
		tcp_writeecmdata(&tcpbuf, sock, totihits, tothits);
		sprintf( http_buf,"<td> </td></tr>"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}


	tcp_writestr(&tcpbuf, sock, "</table>");

	if (get_action==0) {
		tcp_writestr(&tcpbuf, sock, "</div></body></html>");
	}
	tcp_flush(&tcpbuf, sock);
}

struct sms_data *cache_new_sms(char *msg);
void cache_send_sms(struct cachepeer_data *peer, struct sms_data *sms);

///////////////////////////////////////////////////////////////////////////////
void http_send_cache_peer(int sock, http_request *req)
{
	char *str_id = isset_get( req, "id");
	if (!str_id) return; //error
	int get_id = atoi(str_id);
	//
	struct cachepeer_data *peer = getpeerbyid( get_id );
	if (!peer) return;
	// Action
	char *str_action = isset_get( req, "action");
	int get_action = 0;
	if (str_action) {
		if (!strcmp(str_action,"div")) get_action = 1;
		else if (!strcmp(str_action,"row")) get_action = 2;
		else if (!strcmp(str_action,"disable")) get_action = 3;
		else if (!strcmp(str_action,"enable")) get_action = 4;
		else if (!strcmp(str_action,"status")) get_action = 5;
		else if (!strcmp(str_action,"sms")) get_action = 10;
		else str_action = NULL;
	}
	if (!str_action) str_action = "page";
	//
	if (get_action==3) {
		peer->flags |= FLAG_DISABLE;
		peer->ping = 0;
 		http_send_ok(sock);
		return;
	}
	else if (get_action==4) {
		peer->flags &= ~FLAG_DISABLE;
		peer->ping = 0;
		peer->lastpingsent = 0;
		peer->program[0] = 0;
		peer->version[0] = 0;
		http_send_ok(sock);
		return;
	}
	else if (get_action==5) {
		if ( peer->ping>0 ) http_send_text(sock,"active"); else http_send_text(sock,"inactive");
		return;
	}
	else if (get_action==10) {
		// Terminate the string
		req->dbf.data[req->dbf.datasize] = 0;
		char *msg = strstr( (char*)req->dbf.data, "\r\n\r\n" );
		if (msg) {
			// Check Length
			int len = strlen(msg);
			if (len<2) return;
			if (len>1000) msg[1000] = 0;
			// Create MSG
			struct sms_data *sms = cache_new_sms(msg+4);
			cache_send_sms( peer, sms);
			// Wait ACK
			sleep(1);
			if (sms->status&2) {
				http_send_ok(sock);
				return;
			}
		}
		return;
	}


	char http_buf[2048];
	struct tcp_buffer_data tcpbuf;

	tcp_init(&tcpbuf);
	if (!get_action) {
		tcp_write(&tcpbuf, sock, http_replyok, strlen(http_replyok) );
		tcp_write(&tcpbuf, sock, http_html, strlen(http_html) );
		tcp_write(&tcpbuf, sock, http_head, strlen(http_head) );
		sprintf( http_buf, html_title, cfg.http.title, " Cache Peer"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		tcp_write(&tcpbuf, sock, http_link, strlen(http_link) );
		tcp_write(&tcpbuf, sock, http_style, strlen(http_style) );

		// JS
		tcp_write(&tcpbuf, sock, http_javascript, strlen(http_javascript) );
        tcp_writestr(&tcpbuf, sock, "\n<script type='text/javascript'>");
		// ACTIONS REQUEST
		tcp_writestr(&tcpbuf, sock, "\nfunction smsrequest( peerid , button )\n{\n	msg = document.getElementById('message').value;\n	if (msg=='') return;\n	var httpRequest;\n	try { httpRequest = new XMLHttpRequest(); }\n	catch (trymicrosoft) { try { httpRequest = new ActiveXObject('Msxml2.XMLHTTP'); } catch (oldermicrosoft) { try { httpRequest = new ActiveXObject('Microsoft.XMLHTTP'); } catch(failed) { httpRequest = false; } } }\n	if (!httpRequest) { alert('Your browser does not support Ajax.'); return false; }\n	button.disabled = true;\n	mydiv = document.getElementById('smsdiv');\n	mydiv.innerHTML = 'Sending message to peer...';\n	clearTimeout(tautorefresh);\n	httpRequest.onreadystatechange = function()\n	{\n		if (httpRequest.readyState == 4) {\n			if (httpRequest.status == 200) {\n				mydiv.innerHTML = 'Message Sent Successfully';\n				document.getElementById('message').value = '';\n			}\n			else mydiv.innerHTML = 'Failed to send message';\n			button.disabled = false;\n			if (!autorefresh) autorefresh = 3000;\n			updateDiv();\n		}\n	}\n	httpRequest.open('POST', '/cachepeer?action=sms&id='+peerid, true);\n	httpRequest.send( msg );\n}\n");
		// UPD DIV
		char url[255];
		sprintf( url, "/cachepeer?id=%d&action=div", peer->id);
		sprintf( http_buf, HTTP_UPDATE_DIV, cfg.http.autorefresh*1000, url);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		//
		tcp_writestr(&tcpbuf, sock, "\n</script>\n");
		tcp_write(&tcpbuf, sock, http_head_, strlen(http_head_) );
		tcp_writestr(&tcpbuf, sock, "<body>");
		tcp_write_menu(&tcpbuf, sock,0);
		//
		tcp_writestr(&tcpbuf, sock, "<table style='padding:0px; margin:0px;' width='100%'><tbody>");
		tcp_writestr(&tcpbuf, sock, "<tr><td style='vertical-align:top; width:400px;'>");
		// Peer Infos
		tcp_writestr(&tcpbuf, sock, "<table class='infotable'><tbody><tr><th colspan=2>Cache Peer Informations</th></tr>");
		sprintf( http_buf,"<tr><td class=left>Host:Port</td><td class=right>%s:%d</td></tr>", peer->host->name, peer->port); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		if (peer->cards[0]) {
			tcp_writestr(&tcpbuf, sock, "<tr><td class=left>Card list</td><td class=right><select>");
			int i;
			for (i=0; i<1024; i++) {
				if (!peer->cards[i]) break;
				if ( (peer->cards[i]>>24)==5 )
					sprintf( http_buf,"<option>0500:%06x</option>", peer->cards[i]&0xffffff);
				else
					sprintf( http_buf,"<option>%04x:%06x</option>", peer->cards[i]>>16, peer->cards[i]&0xffff);
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			}
			tcp_writestr(&tcpbuf, sock, "</select></td></tr>");
		}
		tcp_writestr(&tcpbuf, sock, "</tbody></table>");

		// Stat
		tcp_writestr(&tcpbuf, sock, "<br><table class='infotable'><tbody><tr><th colspan=2>Peer Statistics</th></tr>");
		sprintf( http_buf,"<tr><td class=left>Total Sent Requests</td><td class=right>%d</td></tr>", peer->sentreq);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		sprintf( http_buf,"<tr><td class=left>Total Sent Replies</td><td class=right>%d</td></tr>", peer->sentrep);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		sprintf( http_buf,"<tr><td class=left>Total Received Requests</td><td class=right>%d</td></tr>", peer->reqnb);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		sprintf( http_buf,"<tr><td class=left>Total Received Replies</td><td class=right>%d</td></tr>", peer->repok);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		sprintf( http_buf,"<tr><td class=left>Total Cache Hits</td><td class=right>%d</td></tr>", peer->hitnb);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		tcp_writestr(&tcpbuf, sock, "</tbody></table>");

		// Profiles Hits
		tcp_writestr(&tcpbuf, sock, "<br><table class='infotable'><tbody><tr><th colspan=2>Profiles Hits</th></tr>");
		int i;
		for(i=0; i<MAX_CSPORTS; i++) {
			if (!peer->csporthit[i].csid) break;
			struct cardserver_data *cs = getcsbyid(peer->csporthit[i].csid);
			if (!cs) continue;
			sprintf( http_buf,"<tr><td class=left>%s</td><td class=right>%d</td></tr>", cs->name,peer->csporthit[i].hits);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		}
		tcp_writestr(&tcpbuf, sock, "</tbody></table>");
		tcp_writestr(&tcpbuf, sock, "</td><td style='vertical-align:top;'>");
		// Messages
		tcp_writestr(&tcpbuf, sock, "<table class='infotable' width=100%><tr><th colspan=2>Send Message</td></tr><tr>");
		tcp_writestr(&tcpbuf, sock, "<td><textarea id='message' name='message' style='width:100%; height:50px;'></textarea></td>");
		sprintf( http_buf,"<td width=150px align=center><input type=button style='width=120px' value='Send Message' onclick='smsrequest(%d, this)'><br><div id=smsdiv></div></td>", peer->id);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		tcp_writestr(&tcpbuf, sock, "</tr><tr><td colspan=2>");
		tcp_writestr(&tcpbuf, sock, "<div id=mainDiv>");
	}
	if (peer->sms) {
		struct sms_data *sms = peer->sms;
		while (sms) {
			// Get Time
			char timebuf [80];
			struct tm * timeinfo = localtime (&sms->rawtime);
			strftime (timebuf,80,"%x %X",timeinfo);
			//
			char *color;
			if (sms->status&1) {
				if (sms->status&2) color = "blue"; else color = "grey";
			}
			else {
				if (sms->status&2) color = "green"; else color = "red";
				sms->status = 2;
			}
			//
			sprintf( http_buf,"<font color=%s><pre>-----[%s]-------\n%s</pre></font>", color, timebuf, sms->msg);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			sms = sms->next;
		}
	}

	if (!get_action) {
		tcp_writestr(&tcpbuf, sock, "</div></td></tr></table> </td></tr></table></body></html>");
	}
	tcp_flush(&tcpbuf, sock);
}


///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
void getprofilecells(struct cardserver_data *cs, char cell[11][2048])
{
	char temp[2048];
	// CELL0 # Profile name
	sprintf( cell[0],"<a href=\"/profile?id=%d\">%s</a>", cs->id, cs->name);
	// CELL1 # Port
	sprintf( cell[1],"<a href=\"/newcamd?pid=%d\">%d</a>", cs->id, cs->newcamd.port); 
	if (cs->newcamd.handle>0) sprintf( cell[10],"online"); else sprintf( cell[10],"offline"); 
	// CELL2 # Ecm Time
	if (cs->ecmok) sprintf( cell[2],"%d ms",(cs->ecmoktime/cs->ecmok) ); else sprintf( cell[2],"-- ms");

	// CELL3 # TotalECM
	int ecmnb = cs->ecmaccepted+cs->ecmdenied;
	sprintf( cell[3], "%d", ecmnb );
	// CELL4 # AcceptedECM
	getstatcell( cs->ecmaccepted, ecmnb, cell[4] );
	// CELL5 # ECM OK
	getstatcell( cs->ecmok, cs->ecmaccepted, cell[5] );
	// CELL6 # CacheHits
	getstatcell( cs->hits.csp, cs->ecmok, cell[6] );
#ifdef CACHEEX
	if (cs->option.fallowcacheex) {
		getstatcell( cs->hits.cacheex, cs->ecmok, temp );
		strcat( cell[6], "<br>" );
		strcat( cell[6], temp );
	}
#endif 
	// CELL7 # Cache iHits
	getstatcell( cs->hits.instant.csp, cs->hits.csp, cell[7] );
#ifdef CACHEEX
	if (cs->option.fallowcacheex) {
		getstatcell( cs->hits.instant.cacheex, cs->hits.cacheex, temp );
		strcat( cell[7], "<br>" );
		strcat( cell[7], temp );
	}
#endif 
	// CELL8 # Clients
	int i=0;
	int j=0;
	struct cs_client_data *usr = cs->newcamd.client;
	while (usr) {
		i++;
		if (usr->handle>0) j++;
		usr = usr->next;
	}
	getstatcell2(j,i,cell[8]);
	// CELL9 # Caid:Providers
	sprintf( cell[9],"<b>%04X:</b> %x ",cs->card.caid,cs->card.prov[0].id);
	for(i=1; i<cs->card.nbprov; i++) {
		sprintf( temp,",%x ",cs->card.prov[i].id);
		strcat( cell[9], temp );
	}

	strcat( cell[9], "<span style='float:right;'>");
	sprintf( temp," <img title='Debug' src='debug.png' OnClick=\"imgrequest('/profile?id=%d&action=debug',this);\">",cs->id);
	strcat( cell[9], temp );
	strcat( cell[9], "</span>");
}


void http_send_profiles(int sock, http_request *req)
{
	char http_buf[2048];
	struct tcp_buffer_data tcpbuf;

	char cell[11][2048];

	//  Get Params
	char *str_action = isset_get( req, "action");
	int get_action = 0;
	if (str_action) {
		if (!strcmp(str_action,"div")) get_action = ACTION_DIV;
		else if (!strcmp(str_action,"row")) get_action = ACTION_ROW;
#ifndef PUBLIC
		else if (!strcmp(str_action,"xml")) get_action = ACTION_XML; // Get Clients info in xml
#endif
		else str_action = NULL;
	}
	if (!str_action) { str_action = "page"; get_action = ACTION_PAGE; }
	//
	if (get_action==ACTION_XML) {
		char *str_id = isset_get( req, "id"); // CCcam server ID
		int get_id = 0;
		if (str_id) get_id = atoi( str_id );
		struct cardserver_data *cs = getcsbyid( get_id );

		tcp_init(&tcpbuf);
		tcp_writestr(&tcpbuf, sock, "HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n");
		tcp_writestr(&tcpbuf, sock, "<multics>");
		struct cardserver_data *srv;
		if (cs) srv = cs; else srv = cfg.cardserver;
		while (srv) {
			tcp_writestr(&tcpbuf, sock, "\n<profile>");
			sprintf(http_buf, "<id>%d</id>", srv->id); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			sprintf(http_buf, "<name>%s</name>", srv->name); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			sprintf(http_buf, "<caid>%04x</caid>", srv->card.caid); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			int i;
			for (i=0; i<srv->card.nbprov; i++) {
				sprintf(http_buf, "<provider>%06x</provider>", srv->card.prov[i].id);
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			}
			sprintf(http_buf, "<totalecm>%d</totalecm>", srv->ecmaccepted+srv->ecmdenied); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			sprintf(http_buf, "<acceptedecm>%d</acceptedecm>", srv->ecmaccepted); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			sprintf(http_buf, "<ecmok>%d</ecmok>", srv->ecmok); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			tcp_writestr(&tcpbuf, sock, "\n</profile>");
			if (cs) break; else srv = srv->next;
		}
		tcp_writestr(&tcpbuf, sock, "\n</multics>");
		tcp_flush(&tcpbuf, sock);
		return;
	}
	//
	int i;
	char *id = isset_get( req, "id");
	// Get Peer ID
	if (id)	{
		i = atoi(id);
		//look for server
		struct cardserver_data *cs = cfg.cardserver;
		while (cs) {
			if (cs->id==(uint32_t)i) break;
			cs = cs->next;
		}
		if (!cs) return;
		// Send XML CELLS
		getprofilecells(cs,cell);
		for(i=0; i<11; i++) xmlescape( cell[i] );
		char buf[5000] = "";
		sprintf( buf, "<profile>\n<c0>%s</c0>\n<c1_c>%s</c1_c>\n<c1>%s</c1>\n<c2>%s</c2>\n<c3>%s</c3>\n<c4>%s</c4>\n<c5>%s</c5>\n<c6>%s</c6>\n<c7>%s</c7>\n<c8>%s</c8>\n<c9>%s</c9>\n</profile>\n",cell[0],cell[10],cell[1],cell[2],cell[3],cell[4],cell[5],cell[6],cell[7],cell[8],cell[9] );
		http_send_xml( sock, req, buf, strlen(buf));
		return;
	}


	tcp_init(&tcpbuf);

	if (get_action==ACTION_PAGE) {
		tcp_write(&tcpbuf, sock, http_replyok, strlen(http_replyok) );
		tcp_write(&tcpbuf, sock, http_html, strlen(http_html) );
		tcp_write(&tcpbuf, sock, http_head, strlen(http_head) );
		sprintf( http_buf, html_title, cfg.http.title, "Profiles"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		tcp_write(&tcpbuf, sock, http_link, strlen(http_link) );
		tcp_write(&tcpbuf, sock, http_style, strlen(http_style) );
		// JS
		tcp_write(&tcpbuf, sock, http_javascript, strlen(http_javascript) );
        tcp_writestr(&tcpbuf, sock, "\n<script type='text/javascript'>");
		// ACTIONS REQUEST
		tcp_writestr(&tcpbuf, sock, "\nfunction imgrequest( url, el )\n{\n	var httpRequest;\n	try { httpRequest = new XMLHttpRequest(); }\n	catch (trymicrosoft) { try { httpRequest = new ActiveXObject('Msxml2.XMLHTTP'); } catch (oldermicrosoft) { try { httpRequest = new ActiveXObject('Microsoft.XMLHTTP'); } catch(failed) { httpRequest = false; } } }\n	if (!httpRequest) { alert('Your browser does not support Ajax.'); return false; }\n	if ( typeof(el)!='undefined' ) {\n		el.onclick = null;\n		el.style.opacity = '0.7';\n		httpRequest.onreadystatechange = function()\n		{\n			if (httpRequest.readyState == 4) if (httpRequest.status == 200) el.style.opacity = '0.3';\n		}\n	}\n	httpRequest.open('GET', url, true);\n	httpRequest.send(null);\n}\n");
		// UPD ROW
		tcp_writestr(&tcpbuf, sock, "\nfunction xmlupdateRow( xmlDoc, id )\n{\n	var row = document.getElementById(id);\n	row.cells.item(0).innerHTML = xmlDoc.getElementsByTagName('c0')[0].childNodes[0].nodeValue;\n	row.cells.item(1).className = xmlDoc.getElementsByTagName('c1_c')[0].childNodes[0].nodeValue;\n	row.cells.item(1).innerHTML = xmlDoc.getElementsByTagName('c1')[0].childNodes[0].nodeValue;\n	row.cells.item(2).innerHTML = xmlDoc.getElementsByTagName('c2')[0].childNodes[0].nodeValue;\n	row.cells.item(3).innerHTML = xmlDoc.getElementsByTagName('c3')[0].childNodes[0].nodeValue;\n	row.cells.item(4).innerHTML = xmlDoc.getElementsByTagName('c4')[0].childNodes[0].nodeValue;\n	row.cells.item(5).innerHTML = xmlDoc.getElementsByTagName('c5')[0].childNodes[0].nodeValue;\n	row.cells.item(6).innerHTML = xmlDoc.getElementsByTagName('c6')[0].childNodes[0].nodeValue;\n	row.cells.item(7).innerHTML = xmlDoc.getElementsByTagName('c7')[0].childNodes[0].nodeValue;\n	row.cells.item(8).innerHTML = xmlDoc.getElementsByTagName('c8')[0].childNodes[0].nodeValue;\n	row.cells.item(9).innerHTML = xmlDoc.getElementsByTagName('c9')[0].childNodes[0].nodeValue;\n}\n");
		char url[256];
		sprintf( url, "'/profiles?id='+idx");
		sprintf( http_buf, HTTP_UPDATE_ROW, url);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		// UPD DIV
		sprintf( url, "/profiles?action=div");
		sprintf( http_buf, HTTP_UPDATE_DIV, cfg.http.autorefresh*1000, url);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		//
		tcp_writestr(&tcpbuf, sock, "\nfunction start()\n{\n	setautorefresh(autorefresh);\n}");
		tcp_writestr(&tcpbuf, sock, "\n</script>\n");
		//
		tcp_write(&tcpbuf, sock, http_head_, strlen(http_head_) );
		tcp_writestr(&tcpbuf, sock, "\n<body onload=\"start();\">");
		tcp_write_menu(&tcpbuf, sock,PAGE_PROFILES);
		// DIV
		tcp_writestr(&tcpbuf, sock, "<div id='mainDiv'>");
	}

	sprintf( http_buf, "Total Profiles: %d", total_profiles() ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	tcp_writestr(&tcpbuf, sock, "<br>\n<table class=maintable width=100%%><tr><th width=150px>Profile name</th><th width=50px>Port</th><th width=60px>EcmTime</th><th width=60px>TotalECM</th><th width=90px>AcceptedECM</th><th width=80px>Ecm OK</th><th width=85px>Cache/Ex Hits</th><th width=80px>Instant Hits</th><th width=80px>Clients</th><th>Caid:Providers</th></tr>");

	struct cardserver_data *cs = cfg.cardserver;
	int alt=0;
	while(cs) {
		if (alt==1) alt=2; else alt=1;
		getprofilecells( cs, cell );
		sprintf( http_buf,"\n<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'><td>%s</td><td class=%s>%s</td><td align=center>%s</td><td align=center>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",cs->id,alt,cs->id,cell[0],cell[10],cell[1],cell[2],cell[3],cell[4],cell[5],cell[6],cell[7],cell[8],cell[9]);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		cs = cs->next;
	}
	// Total
	if (alt==1) alt=2; else alt=1;
	sprintf( http_buf,"\n<tr class=alt3><td align=right>Total</td><td align=center>%d</td><td align=center>--</td>",total_profiles()); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	int totecm = 0;
	int totecmaccepted = 0;
	int totecmok = 0;
	int totcachehits = 0;
	int totcacheihits = 0;
	cs = cfg.cardserver;
	while(cs) {
		totecm += cs->ecmaccepted+cs->ecmdenied;
		totecmaccepted += cs->ecmaccepted;
		totecmok += cs->ecmok;
		totcachehits += cs->hits.csp;
#ifdef CACHEEX
		totcachehits += cs->hits.cacheex;
#endif
		totcacheihits += cs->hits.instant.csp;
#ifdef CACHEEX
		totcacheihits += cs->hits.instant.cacheex;
#endif
		cs = cs->next;
	}
	sprintf( http_buf,"<td align=center>%d</td>",totecm); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	tcp_writeecmdata(&tcpbuf, sock, totecmaccepted, totecm);
	tcp_writeecmdata(&tcpbuf, sock, totecmok, totecmaccepted);
	tcp_writeecmdata(&tcpbuf, sock, totcachehits, totecmok);
	tcp_writeecmdata(&tcpbuf, sock, totcacheihits, totcachehits);
	sprintf( http_buf, "<td colspan=2> </td></tr>"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	// Speed
	uint ticks = GetTickCount()/1000;
	sprintf( http_buf,"<tr class=alt2><td align=right>Average speed</td><td colspan=2 align=center>(per minute)</td>"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"<td align=center>%d</td>", totecm*60/ticks); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"<td>%d</td>", totecmaccepted*60/ticks); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"<td>%d</td>", totecmok*60/ticks); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"<td>%d</td>", totcachehits*60/ticks); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"<td>%d</td>", totcacheihits*60/ticks); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf, "<td colspan=2> </td></tr>"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

	sprintf( http_buf, "\n</table>"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

	if (get_action==ACTION_PAGE) {
		tcp_writestr(&tcpbuf, sock, "\n</div></body></html>");
	}
	tcp_flush(&tcpbuf, sock);
}

///////////////////////////////////////////////////////////////////////////////
// PROFILE
///////////////////////////////////////////////////////////////////////////////

void cs_clients( struct cardserver_data *cs, int *total, int *connected, int *active )
{
	*total = 0;
	*connected = 0;
	*active = 0;
	struct cs_client_data *cli=cs->newcamd.client;
	while (cli) {
		(*total)++;
		if (cli->connection.status>0) {
			(*connected)++;
			if ( (GetTickCount()-cli->lastecmtime) < 20000 ) (*active)++;
		}
		cli=cli->next;
	}
}

void cs_allclients( int *total, int *connected, int *active )
{
	*total = 0;
	*connected = 0;
	*active = 0;

	struct cardserver_data *cs = cfg.cardserver;
	while (cs) {
		struct cs_client_data *cli = cs->newcamd.client;
		while (cli) {
			(*total)++;
			if (cli->connection.status>0) {
				(*connected)++;
				if ( (GetTickCount()-cli->lastecmtime) < 20000 ) (*active)++;
			}
			cli=cli->next;
		}
		cs = cs->next;
	}
}


#ifdef RADEGAST_SRV

int connected_radegast_clients(struct cardserver_data *cs)
{
	int nb=0;
	struct rdgd_client_data *rdgdcli=cs->radegast.client;
	if (cs->radegast.handle)
	while (rdgdcli) {
		if (rdgdcli->handle>0) nb++;
		rdgdcli=rdgdcli->next;
	}
	return nb;
}

#endif

char *programid(unsigned int id)
{
	typedef struct {
		char name[13];
		unsigned int id;
	} tnewcamdprog; 

	static tnewcamdprog camdp[] = { 
		{ "Generic", 0x0000 },
		{ "VDRSC",   0x5644 },
		{ "LCE", 0x4C43 },
		{ "Camd3", 0x4333 },
		{ "Radegast", 0x7264 },
		{ "Gbox2CS", 0x6762 },
		{ "Mgcamd", 0x6D67 },
		{ "WinCSC", 0x7763 },
		{ "newcs", 0x6E73 },
		{ "cx", 0x6378 },
		{ "Kaffeine", 0x6B61 },
		{ "Evocamd", 0x6576 },
		{ "CCcam", 0x4343 },
		{ "Tecview", 0x5456 },
		{ "AlexCS", 0x414C },
		{ "Rqcamd", 0x0666 },
		{ "Rq-echo", 0x0667 },
		{ "Acamd", 0x9911 },
		{ "Cardlink", 0x434C },
		{ "Octagon", 0x4765 },
		{ "sbcl", 0x5342 },
		{ "NextYE2k", 0x6E65 },
		{ "NextYE2k", 0x4E58 },
		{ "DiabloCam/UW", 0x4453 },
		{ "OScam", 0x8888 },
		{ "Scam", 0x7363 },
		{ "Rq-sssp/CW", 0x0669 },
		{ "Rq-sssp/CS", 0x0665 },
		{ "JlsRq", 0x0769 },
		{ "eyetvCamd", 0x4543 }
	};
	static char unknown[] = "Unknown";
	unsigned int i;
	id = id & 0xffff;
	for( i=0; i<sizeof(camdp)/sizeof(tnewcamdprog); i++ )
		if (camdp[i].id==id) return camdp[i].name;
	return unknown;
}

char* str_laststatus[] = { "NOK", "OK" };


///////////////////////////////////////////////////////////////////////////////

void getnewcamdclientcells(struct cs_client_data *cli, char cell[10][2048])
{
	char temp[2048];
	unsigned int ticks = GetTickCount();
	unsigned int d;
	// CELL0 # User name
	sprintf( cell[0],"<a href='/newcamdclient?id=%d'>%s</a>", cli->id, cli->user);
	// CELL1 # PROGRAM ID
	if (cli->connection.status>0)
		sprintf( cell[1],"<span title='%04x'>%s</span>", cli->progid, programid(cli->progid));
	else
		strcpy( cell[1], " ");
	// CELL2 # IP
	if (cli->connection.status>0) {
		char *p = getcountrycodebyip(cli->ip);
		if (p) sprintf( cell[2],"<img src='/flag_%s.gif' title='%s'> %s", p, getcountryname(p), (char*)ip2string(cli->ip) ); else sprintf( cell[2], "%s", (char*)ip2string(cli->ip) );
	}
	else
		strcpy( cell[2], " ");
	// CELL3 # CONNECTION TIME
	if (cli->connection.status>0) {
		d = (ticks-cli->connection.time)/1000;
		if (cli->ecm.busy) sprintf( cell[9], "busy"); else sprintf( cell[9], "online");
		sprintf( cell[3],"%02dd %02d:%02d:%02d", d/(3600*24), (d/3600)%24, (d/60)%60, d%60);
	}
	else {
		sprintf( cell[9], "offline");
		if (cli->flags&FLAG_DELETE) sprintf( cell[3],"Removed");
		else if (cli->flags&FLAG_EXPIRED) sprintf( cell[3],"Expired");
		else if (cli->flags&FLAG_DISABLE) sprintf( cell[3],"Disabled");
		else sprintf( cell[3],"offline");
	}
#ifdef EXPIREDATE
	if (cli->enddate.tm_year) {
		sprintf( temp,"<br>Expire: %d-%02d-%02d", 1900+cli->enddate.tm_year, cli->enddate.tm_mon+1, cli->enddate.tm_mday);
		strcat( cell[3], temp );
	}
#endif
	sprintf( temp, "<table class=\"connect_data\"><tr><td>Successful Login: %d</td><td>Aborted Connections: %d</td><td>Total Zap: %d</td><td>Channel Freeze: %d</td></tr></table>", cli->nblogin, cli->nbloginerror, cli->zap, cli->freeze );
	strcat( cell[3], temp );

	// ECM STAT
#ifdef SRV_CSCACHE
	if (cli->cachedcw) sprintf( cell[4], "%d [%d]", cli->ecmnb, cli->cachedcw); else sprintf( cell[4], "%d", cli->ecmnb );
#else
	sprintf( cell[4], "%d", cli->ecmnb );
#endif
	//
	int ecmaccepted = cli->ecmnb-cli->ecmdenied;
	getstatcell( ecmaccepted, cli->ecmnb, cell[5]);
	getstatcell( cli->ecmok, ecmaccepted, cell[6]);
	// Ecm Time
	if (cli->ecmok)
		sprintf( cell[7],"%d ms",(cli->ecmoktime/cli->ecmok) );
	else
		sprintf( cell[7],"-- ms");

	//Last Used Share
	if (cli->connection.status<=0 && cli->connection.lastseen) {
		d = (ticks-cli->connection.lastseen)/1000;
		sprintf( cell[8],"Last Seen %02dd %02d:%02d:%02d", d/(3600*24),(d/3600)%24,(d/60)%60,d%60);
	}
	else if ( cli->lastecm.caid ) {
		if (cli->lastecm.status) sprintf( cell[8],"<span class=success"); else sprintf( cell[8],"<span class=failed");
		sprintf( temp," title='%04x:%06x:%04x'>ch %s (%dms) %s ",cli->lastecm.caid, cli->lastecm.prov, cli->lastecm.sid, getchname(cli->lastecm.caid, cli->lastecm.prov, cli->lastecm.sid) , cli->lastecm.decodetime, str_laststatus[cli->lastecm.status] );
		strcat( cell[8], temp);
		if ( (GetTickCount()-cli->ecm.recvtime) < 20000 ) {
			// From ???
			if (cli->lastecm.status) {
				strcat( cell[8], " / from ");
				src2string(cli->lastecm.dcwsrctype, cli->lastecm.dcwsrcid, temp);
				strcat( cell[8], temp);
			}
		}
		strcat( cell[8], "</span>");
	}
	else strcpy( cell[8], " ");

	strcat( cell[8], "<span style='float:right;'>");
	if ( !(cli->flags&(FLAG_DELETE|FLAG_EXPIRED)) ) {
		if (cli->flags&FLAG_DISABLE) {
			sprintf( temp," <img title='Enable' src='enable.png' OnClick=\"imgrequest('/newcamdclient?id=%d&action=enable',this);\">",cli->id);
			strcat( cell[8], temp );
		}
		else {
			sprintf( temp," <img title='disable' src='disable.png' OnClick=\"imgrequest('/newcamdclient?id=%d&action=disable',this);\">",cli->id);
			strcat( cell[8], temp );
		}
	}
	sprintf( temp," <img title='Debug' src='debug.png' OnClick=\"imgrequest('/newcamdclient?id=%d&action=debug',this);\">",cli->id);
	strcat( cell[8], temp );
	strcat( cell[8], "</span>");

}

void http_send_newcamd(int sock, http_request *req) // page, div, row
{
	char http_buf[2048];
	char cell[10][2048];
	struct tcp_buffer_data tcpbuf;
	struct cs_client_data *cli;

	//  Get Params
	char *str_list = isset_get( req, "list");
	int get_list = LIST_ACTIVE;
	if (str_list) {
		if (!strcmp(str_list,"connected")) get_list = LIST_CONNECTED;
		else if (!strcmp(str_list,"all")) get_list = LIST_ALL;
		else str_list=NULL;
	}
	if (!str_list) str_list = "active";
	// Param 'action'
	char *str_action = isset_get( req, "action");
	int get_action;
	if (str_action) {
		if (!strcmp(str_action,"div")) get_action = ACTION_DIV;
		else if (!strcmp(str_action,"row")) get_action = ACTION_ROW;
#ifndef PUBLIC
		else if (!strcmp(str_action,"xml")) get_action = ACTION_XML; // Get Clients info in xml
#endif
		else if (!strcmp(str_action,"disable")) get_action = ACTION_DISABLE;
		else if (!strcmp(str_action,"enable")) get_action = ACTION_ENABLE;
		else if (!strcmp(str_action,"status")) get_action = ACTION_STATUS;
		else if (!strcmp(str_action,"debug")) get_action = ACTION_DEBUG;
		else str_action = NULL;
	}
	if (!str_action) { str_action = "page"; get_action = ACTION_PAGE; }

	// Profile ID
	char *str_pid = isset_get( req, "pid");
	int get_pid;
	if (str_pid) get_pid = atoi(str_pid); else get_pid = 0;
	struct cardserver_data *cs = getcsbyid(get_pid);
////
	if (get_action==ACTION_XML) {
		tcp_init(&tcpbuf);
		tcp_writestr(&tcpbuf, sock, "HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n");

		tcp_writestr(&tcpbuf, sock, "<multics>");

		struct cardserver_data *srv;
		if (cs) srv = cs; else srv = cfg.cardserver;
		while (srv) {
			tcp_writestr(&tcpbuf, sock, "\n<newcamd>");
			sprintf(http_buf, "<id>%d</id>", srv->id); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			sprintf(http_buf, "<port>%d</port>", srv->newcamd.port); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			sprintf(http_buf, "<status>%d</status>", (srv->newcamd.handle>0) ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			uint32_t ticks = GetTickCount();
			struct cs_client_data *cli = srv->newcamd.client;
			while (cli) {
				tcp_writestr(&tcpbuf, sock, "<user>");
				sprintf(http_buf, "<name>%s</name>", cli->user); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				if (cli->connection.status>0) {
					tcp_writestr(&tcpbuf, sock, "<status>1</status>");
					sprintf( http_buf,"<ip>%s</ip>", (char*)ip2string(cli->ip) ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					char *p = getcountrycodebyip(cli->ip);
					if (p) sprintf(http_buf, "<country>%s</country>", p); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					uint32_t d = (ticks - cli->connection.time)/1000;
					sprintf(http_buf, "<connected>%02dd %02d:%02d:%02d</connected>", d/(3600*24), (d/3600)%24, (d/60)%60, d%60); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				}
				else {
					sprintf(http_buf, "<status>%d</status>",cli->flags&0x0E);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				}
				tcp_writestr(&tcpbuf, sock, "</user>");
				cli = cli->next;
			}
			tcp_writestr(&tcpbuf, sock, "\n</newcamd>");

			if (cs) break; else srv = srv->next;
		}
		tcp_writestr(&tcpbuf, sock, "\n</multics>");
		tcp_flush(&tcpbuf, sock);
		return;
	}

	char *id = isset_get( req, "id");
	if (id)	{ // XML
		int i = atoi(id);
		struct cs_client_data *cli = getnewcamdclientbyid(i);
		if (!cli) return;
		// Send XML CELLS
		getnewcamdclientcells(cli,cell);
		for(i=0; i<10; i++) xmlescape( cell[i] );
		char buf[5000] = "";
		sprintf( buf, "<newcamd>\n<c0>%s</c0>\n<c1>%s</c1>\n<c2>%s</c2>\n<c3_c>%s</c3_c>\n<c3>%s</c3>\n<c4>%s</c4>\n<c5>%s</c5>\n<c6>%s</c6>\n<c7>%s</c7>\n<c8>%s</c8>\n</newcamd>\n",cell[0],cell[1],cell[2],cell[9],cell[3],cell[4],cell[5],cell[6],cell[7],cell[8] );
		http_send_xml( sock, req, buf, strlen(buf));
		return;
	}

	tcp_init(&tcpbuf);
	if (get_action==ACTION_PAGE) {
		tcp_write(&tcpbuf, sock, http_replyok, strlen(http_replyok) );
		tcp_write(&tcpbuf, sock, http_html, strlen(http_html) );
		tcp_write(&tcpbuf, sock, http_head, strlen(http_head) );
		sprintf( http_buf, html_title, cfg.http.title, "Newcamd"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		tcp_write(&tcpbuf, sock, http_link, strlen(http_link) );
		tcp_write(&tcpbuf, sock, http_style, strlen(http_style) );
		// JS
        tcp_write(&tcpbuf, sock, http_javascript, strlen(http_javascript) );
		tcp_writestr(&tcpbuf, sock, "\n<script type='text/javascript'>");
		// ACTIONS REQUEST
		tcp_writestr(&tcpbuf, sock, "\nfunction imgrequest( url, el )\n{\n	var httpRequest;\n	try { httpRequest = new XMLHttpRequest(); }\n	catch (trymicrosoft) { try { httpRequest = new ActiveXObject('Msxml2.XMLHTTP'); } catch (oldermicrosoft) { try { httpRequest = new ActiveXObject('Microsoft.XMLHTTP'); } catch(failed) { httpRequest = false; } } }\n	if (!httpRequest) { alert('Your browser does not support Ajax.'); return false; }\n	if ( typeof(el)!='undefined' ) {\n		el.onclick = null;\n		el.style.opacity = '0.7';\n		httpRequest.onreadystatechange = function()\n		{\n			if (httpRequest.readyState == 4) if (httpRequest.status == 200) el.style.opacity = '0.3';\n		}\n	}\n	httpRequest.open('GET', url, true);\n	httpRequest.send(null);\n}\n");
		// UPD ROW
		tcp_writestr(&tcpbuf, sock, "\nfunction xmlupdateRow( xmlDoc, id )\n{\n	var row = document.getElementById(id);\n	row.cells.item(0).innerHTML = xmlDoc.getElementsByTagName('c0')[0].childNodes[0].nodeValue;\n	row.cells.item(1).innerHTML = xmlDoc.getElementsByTagName('c1')[0].childNodes[0].nodeValue;\n	row.cells.item(2).innerHTML = xmlDoc.getElementsByTagName('c2')[0].childNodes[0].nodeValue;\n	row.cells.item(3).className = xmlDoc.getElementsByTagName('c3_c')[0].childNodes[0].nodeValue;\n	row.cells.item(3).innerHTML = xmlDoc.getElementsByTagName('c3')[0].childNodes[0].nodeValue;\n	row.cells.item(4).innerHTML = xmlDoc.getElementsByTagName('c4')[0].childNodes[0].nodeValue;\n	row.cells.item(5).innerHTML = xmlDoc.getElementsByTagName('c5')[0].childNodes[0].nodeValue;\n	row.cells.item(6).innerHTML = xmlDoc.getElementsByTagName('c6')[0].childNodes[0].nodeValue;\n	row.cells.item(7).innerHTML = xmlDoc.getElementsByTagName('c7')[0].childNodes[0].nodeValue;\n	row.cells.item(8).innerHTML = xmlDoc.getElementsByTagName('c8')[0].childNodes[0].nodeValue;\n}\n");
		char url[256];
		sprintf( url, "'/newcamd?id='+idx");
		sprintf( http_buf, HTTP_UPDATE_ROW, url);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		// UPD DIV
		sprintf( url, "/newcamd?pid=%d&list=%s&action=div", get_pid, str_list);
		sprintf( http_buf, HTTP_UPDATE_DIV, cfg.http.autorefresh*1000, url);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		//
		tcp_writestr(&tcpbuf, sock, "\nfunction start()\n{\n	setautorefresh(autorefresh);\n}");
		tcp_writestr(&tcpbuf, sock, "\n</script>\n");
		//
		tcp_write(&tcpbuf, sock, http_head_, strlen(http_head_) );
		tcp_writestr(&tcpbuf, sock, "\n<body onload=\"start();\">");
		tcp_write_menu(&tcpbuf, sock,PAGE_NEWCAMD);
		// DIV
		tcp_writestr(&tcpbuf, sock, "<div id='mainDiv'>");
	}

	sprintf( http_buf, "<select style=\"width:200px;\" onchange=\"parent.location.href='/newcamd?pid='+this.value\"> ><option value=0>All Profiles(%d)</option>", total_profiles());
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	struct cardserver_data *tmp = cfg.cardserver;
	while (tmp) {
		if (tmp->id==get_pid) sprintf( http_buf, "<option value=%d selected> [%d] %s </option>", tmp->id, tmp->newcamd.port, tmp->name);
		else sprintf( http_buf, "<option value=%d> [%d] %s </option>", tmp->id, tmp->newcamd.port, tmp->name);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		tmp = tmp->next;
	}
	sprintf( http_buf, "</select> ");
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

	//
	int total, connected, active;
	if (cs) cs_clients( cs, &total, &connected, &active ); else cs_allclients( &total, &connected, &active );
	char *class1 = "button"; char *class2 = "sbutton";
	char *class;
	if (get_list==LIST_ACTIVE) class = class2; else class = class1;
	sprintf( http_buf, " <input type=button class=%s onclick=\"parent.location='/newcamd?pid=%d&amp;list=active'\" value='Active Clients(%d)'>", class, get_pid,active);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	if (get_list==LIST_CONNECTED) class = class2; else class = class1;
	sprintf( http_buf, " <input type=button class=%s onclick=\"parent.location='/newcamd?pid=%d&amp;list=connected'\" value='Connected Clients(%d)'>", class, get_pid,connected);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	if (get_list==LIST_ALL) class = class2; else class = class1;
	sprintf( http_buf, " <input type=button class=%s onclick=\"parent.location='/newcamd?pid=%d&amp;list=all'\" value='All Clients(%d)'>", class, get_pid,total);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );


	//NEWCAMD CLIENTS
	if (cs) {
		//
		sprintf( http_buf, "<br><table class=maintable width=100%%><tr><th width=100px>Client</th><th width=70px>Program</th><th width=120px>IP Address</th><th width=100px>Connected</th><th width=60px>TotalEcm</th><th width=90px>AcceptedEcm</th><th width=90px>EcmOK</th><th width=50px>EcmTime</th><th>Last used share</th></tr>\n");
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		cli = cs->newcamd.client;
		int alt=0;

		if (get_list==LIST_ACTIVE) {
			while (cli) {
				if ( (cli->connection.status>0)&&((GetTickCount()-cli->lastecmtime) < 20000) ) {
					if (alt==1) alt=2; else alt=1;
					getnewcamdclientcells(cli, cell);
					sprintf( http_buf,"<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td>%s</td><td class=%s>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",cli->id,alt,cli->id,cell[0],cell[1],cell[2],cell[9],cell[3],cell[4],cell[5],cell[6],cell[7],cell[8]);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				}
				cli = cli->next;
			}
		}
		else if (get_list==LIST_ALL) {
			while (cli) {
				if (alt==1) alt=2; else alt=1;
				getnewcamdclientcells(cli, cell);
				sprintf( http_buf,"<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td>%s</td><td class=%s>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",cli->id,alt,cli->id,cell[0],cell[1],cell[2],cell[9],cell[3],cell[4],cell[5],cell[6],cell[7],cell[8]);
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				cli = cli->next;
			}
		}
		else if (get_list==LIST_CONNECTED) {
			while (cli) {
				if (cli->connection.status>0) {
					if (alt==1) alt=2; else alt=1;
					getnewcamdclientcells(cli, cell);
					sprintf( http_buf,"<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td>%s</td><td class=%s>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",cli->id,alt,cli->id,cell[0],cell[1],cell[2],cell[9],cell[3],cell[4],cell[5],cell[6],cell[7],cell[8]);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				}
				cli = cli->next;
			}
		}
	
		sprintf( http_buf, "</table>");
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}
	else {
		//
		sprintf( http_buf, "<br><table class=maintable width=100%%><tr><th width=100px>Client</th><th width=70px>Program</th><th width=120px>IP Address</th><th width=100px>Connected</th><th width=60px>TotalEcm</th><th width=90px>AcceptedEcm</th><th width=90px>EcmOK</th><th width=50px>EcmTime</th><th>Last used share</th></tr>\n");
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

		int alt=0;
		struct cardserver_data *cs = cfg.cardserver;
		while (cs) {
			int total, connected, active;
			cs_clients( cs, &total, &connected, &active );
			if ( (get_list==LIST_ACTIVE) && active ) {
				sprintf( http_buf, "<tr><td class=alt3 colspan=9>%s (%d)</td></tr>\n", cs->name, active); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				cli = cs->newcamd.client;
				while (cli) {
					if ( (cli->connection.status>0)&&((GetTickCount()-cli->lastecmtime) < 20000) ) {
						if (alt==1) alt=2; else alt=1;
						getnewcamdclientcells(cli, cell);
						sprintf( http_buf,"<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td>%s</td><td class=%s>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",cli->id,alt,cli->id,cell[0],cell[1],cell[2],cell[9],cell[3],cell[4],cell[5],cell[6],cell[7],cell[8]);
						tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					}
					cli = cli->next;
				}
			}
			else if ( (get_list==LIST_ALL) && total ) {
				sprintf( http_buf, "<tr><td class=alt3 colspan=9>%s (%d)</td></tr>\n", cs->name, total); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				cli = cs->newcamd.client;
				while (cli) {
					if (alt==1) alt=2; else alt=1;
					getnewcamdclientcells(cli, cell);
					sprintf( http_buf,"<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td>%s</td><td class=%s>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",cli->id,alt,cli->id,cell[0],cell[1],cell[2],cell[9],cell[3],cell[4],cell[5],cell[6],cell[7],cell[8]);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					cli = cli->next;
				}
			}
			else if ( (get_list==LIST_CONNECTED) && connected ) {
				sprintf( http_buf, "<tr><td class=alt3 colspan=9>%s (%d)</td></tr>\n", cs->name, connected); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				cli = cs->newcamd.client;
				while (cli) {
					if (cli->connection.status>0) {
						if (alt==1) alt=2; else alt=1;
						getnewcamdclientcells(cli, cell);
						sprintf( http_buf,"<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td>%s</td><td class=%s>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",cli->id,alt,cli->id,cell[0],cell[1],cell[2],cell[9],cell[3],cell[4],cell[5],cell[6],cell[7],cell[8]);
						tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					}
					cli = cli->next;
				}
			}
			cs = cs->next;
		}
		sprintf( http_buf, "</table>");
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}

	if (get_action==ACTION_PAGE) {
		tcp_writestr(&tcpbuf, sock, "</div></body></html>");
	}

	tcp_flush(&tcpbuf, sock);
}


///////////////////////////////////////////////////////////////////////////////
void http_send_newcamd_client(int sock, http_request *req)
{
	char http_buf[2048];
	struct tcp_buffer_data tcpbuf;
	char *str_id = isset_get( req, "id");
	if (!str_id) return; //error
	int get_id = atoi(str_id);
	//
	struct cs_client_data *cli = getnewcamdclientbyid( get_id );
	if (!cli) return;
	// Action
	char *str_action = isset_get( req, "action");
	int get_action = 0;
	if (str_action) {
		if (!strcmp(str_action,"div")) get_action = 1;
		else if (!strcmp(str_action,"row")) get_action = 2;
		else if (!strcmp(str_action,"disable")) get_action = 3;
		else if (!strcmp(str_action,"enable")) get_action = 4;
		else if (!strcmp(str_action,"status")) get_action = 5;
		else if (!strcmp(str_action,"info")) get_action = 6; // XML info
		else if (!strcmp(str_action,"debug")) get_action = 7;
		else str_action = NULL;
	}
	if (!str_action) str_action = "page";
	//
	if (get_action==3) {
		cli->flags |= FLAG_DISABLE;
		if (cli->connection.status>0) cs_disconnect_cli(cli);
		http_send_ok(sock);
		return;
	}
	else if (get_action==4) {
		cli->flags &= ~FLAG_DISABLE;
		http_send_ok(sock);
		return;
	}
	else if (get_action==5) {
		if (cli->connection.status>0) http_send_text(sock,"connected"); else http_send_text(sock,"disconnected");
		return;
	}
	else if (get_action==7) {
		flagdebug = getdbgflag( DBG_NEWCAMD, cli->pid, cli->id);
		http_send_ok(sock);
		return;
	}
	//
	tcp_init(&tcpbuf);
	if (get_action==0) {
		tcp_write(&tcpbuf, sock, http_replyok, strlen(http_replyok) );
		tcp_write(&tcpbuf, sock, http_html, strlen(http_html) );
		tcp_write(&tcpbuf, sock, http_head, strlen(http_head) );
		sprintf( http_buf, html_title, cfg.http.title, "Newcamd Client"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		tcp_write(&tcpbuf, sock, http_link, strlen(http_link) );
		tcp_write(&tcpbuf, sock, http_style, strlen(http_style) );
		// JS
        tcp_write(&tcpbuf, sock, http_javascript, strlen(http_javascript) );
		tcp_writestr(&tcpbuf, sock, "\n<script type='text/javascript'>");
		// UPD DIV
		char url[256];
		sprintf( url, "/newcamdclient?id=%d&action=div", get_id);
		sprintf( http_buf, HTTP_UPDATE_DIV, cfg.http.autorefresh*1000, url);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		//
		tcp_writestr(&tcpbuf, sock, "\nfunction start()\n{\n	setautorefresh(autorefresh);\n}");
		tcp_writestr(&tcpbuf, sock, "\n</script>\n");
		tcp_write(&tcpbuf, sock, http_head_, strlen(http_head_) );
		tcp_writestr(&tcpbuf, sock, "<body onload=\"start();\">");
		tcp_write_menu(&tcpbuf, sock,0);
		// DIV
		tcp_writestr(&tcpbuf, sock, "<div id='mainDiv'>");
	}
	//
	tcp_writestr(&tcpbuf, sock, "<table style=\"padding:0px; margin:0px;\" width=\"100%%\"><tbody>\n" );
	tcp_writestr(&tcpbuf, sock, "<tr><td style=\"vertical-align:top; width:400px;\">\n" );
	//
	tcp_writestr(&tcpbuf, sock, "<table class=infotable><tbody>\n<tr><th colspan=2>Newcamd Client Informations</th></tr>\n" );
	// Profile
	struct cardserver_data *cs = getcsbyid( cli->pid );
	if (cs) {
		sprintf( http_buf,"<tr><td class=left>Profile</td><td class=right><a href='/profile?id=%d'>%s</a></td></tr>\n", cs->id, cs->name);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}
	// NAME
	sprintf( http_buf,"<tr><td class=left>User name</td><td class=right>%s</td></tr>\n",cli->user);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	// Connection Time
	if (cli->connection.status>0) {
		tcp_writestr(&tcpbuf, sock, "<tr><td class=left>Status</td><td class=right>Connected</td></tr>\n");
		uint32_t d = (GetTickCount()-cli->connection.time)/1000;
		sprintf( http_buf,"<tr><td class=left>Connection time</td><td class=right>%02dd %02d:%02d:%02d</td></tr>\n", d/(3600*24), (d/3600)%24, (d/60)%60, d%60);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		// IP
		sprintf( http_buf,"<tr><td class=left>IP Address</td><td class=right>%s</td></tr>\n",(char*)ip2string(cli->ip) );
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		// Program ID
		sprintf( http_buf,"<tr><td class=left>Client Program</td><td class=right>%s(%04x)</td></tr>",programid(cli->progid), cli->progid );
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}
	else {
		tcp_writestr(&tcpbuf, sock, "<tr><td class=left>Status</td><td class=right>Disconnected</td></tr>\n");
		if ( cli->connection.status<=0 && cli->connection.lastseen) {
			uint32_t d = (GetTickCount()-cli->connection.lastseen)/1000;
			sprintf( http_buf,"<tr><td class=left>Last Seen</td><td class=right>%02dd %02d:%02d:%02d</td></tr>\n", d/(3600*24),(d/3600)%24,(d/60)%60,d%60);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		}
	}
	// UPTIME
	if ( cli->connection.uptime || (cli->connection.status>0) ) {
		uint32_t uptime;
		if (cli->connection.status>0) uptime = (GetTickCount()-cli->connection.time)+cli->connection.uptime; else uptime = cli->connection.uptime;
		uptime /= 1000;
		sprintf( http_buf,"<tr><td class=left>Uptime</td><td class=right>%02dd %02d:%02d:%02d</td></tr>",uptime/(3600*24),(uptime/3600)%24,(uptime/60)%60,uptime%60);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}
#ifdef CHECK_NEXTDCW
	sprintf( http_buf,"<tr><td class=left>DCW CHECK</td><td class=right>%s</td></tr>", yesno(cli->dcwcheck) );
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
#endif
	tcp_writestr(&tcpbuf, sock, "</tbody></table><br>\n" );

	// INFO
	struct client_info_data *info = cli->info;
	if (info) {
		tcp_writestr(&tcpbuf, sock, "<table class=\"infotable\"><tbody>\n" );
		tcp_writestr(&tcpbuf, sock, "<tr><th colspan=2>Additional Informations</th></tr>\n" );
		while (info) {
			sprintf( http_buf,"<tr><td class=left>%s</td><td class=right>%s</td></tr>\n",info->name,info->value);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			info = info->next;
		}
		tcp_writestr(&tcpbuf, sock, "</tbody></table><br>\n" );
	}

	// Ecm Stat
	tcp_writestr(&tcpbuf, sock, "<table class=\"infotable\"><tbody>\n" );
	tcp_writestr(&tcpbuf, sock, "<tr><th colspan=2>ECM Statistics</th></tr>\n" );
	int ecmaccepted = cli->ecmnb-cli->ecmdenied;
	sprintf( http_buf, "<tr><td class=left>Total ECM requests</td><td class=right>%d</td></tr>\n", cli->ecmnb);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf, "<tr><td class=left>Accepted ECM requests</td><td class=right>%d</td></tr>\n", ecmaccepted);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf, "<tr><td class=left>Good ECM answer</td><td class=right>%d</td></tr>\n", cli->ecmok);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	//Ecm Time
	if (cli->ecmok) {
		sprintf( http_buf,"<tr><td class=left>Average Time</td><td class=right>%d ms</td></tr>\n",(cli->ecmoktime/cli->ecmok) );
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}
#ifdef SRV_CSCACHE
	sprintf( http_buf, "<tr><td class=left>Cached DCW</td><td class=right>%d</td></tr>\n", cli->cachedcw);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
#endif
	// Freeze
	sprintf( http_buf,"<tr><td class=left>Total Freeze</td><td class=right>%d</td></tr>\n", cli->freeze);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	tcp_writestr(&tcpbuf, sock, "</tbody></table><br>\n" );


	tcp_writestr(&tcpbuf, sock, "</td><td style=\"vertical-align:top;\">\n" );

	//Last Used Share
	if ( cli->lastecm.caid ) {
		tcp_writestr(&tcpbuf, sock, "<table class=\"infotable\"><tbody>\n" );
		tcp_writestr(&tcpbuf, sock, "<tr><th>Last Used share</th></tr>\n");
		// Decode Status
		if (cli->lastecm.status)
			sprintf( http_buf,"<tr><td>Decode success</td></tr>\n");
		else
			sprintf( http_buf,"<tr><td>Decode failed</td></tr>\n");
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		// Channel
		sprintf( http_buf,"<tr><td>Channel %s (%dms) %s</td></tr>\n", getchname(cli->lastecm.caid, cli->lastecm.prov, cli->lastecm.sid) , cli->lastecm.decodetime, str_laststatus[cli->lastecm.status] );
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

		// Server
		if ( (GetTickCount()-cli->ecm.recvtime) < 20000 ) {
			// From ???
			if (cli->lastecm.status) {
				tcp_writestr(&tcpbuf, sock, "<tr><td>From ");
				src2string(cli->lastecm.dcwsrctype, cli->lastecm.dcwsrcid, http_buf );
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				tcp_writestr(&tcpbuf, sock, "</td></tr>");
			}
			// Last ECM
			ECM_DATA *ecm = cli->lastecm.request;
			// ECM
			sprintf( http_buf,"<tr><td>ECM(%d): ", ecm->ecmlen); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			array2hex( ecm->ecm, http_buf, ecm->ecmlen );	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			sprintf( http_buf,"</td></tr>\n"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			// DCW
			if (cli->lastecm.status) {
				sprintf( http_buf,"<tr><td>CW: ");	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				array2hex( ecm->cw, http_buf, 16 );	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				sprintf( http_buf,"</td></tr>\n"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			}
#ifdef CHECK_NEXTDCW
			if ( ecm->lastdecode.ecm && (ecm->lastdecode.counter>0) ) {
				sprintf( http_buf,"<tr><td>Previous CW: "); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				array2hex( ecm->lastdecode.dcw, http_buf, 16 ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				tcp_writestr(&tcpbuf, sock, "</td></tr>\n");
				if (ecm->lastdecode.error) {
					sprintf( http_buf,"<tr><td>Errors = %d</td></tr>\n", ecm->lastdecode.error);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				}
				sprintf( http_buf,"<tr><td>Total Cycles = %d</td></tr>\n<tr><td>ECM Interval = %ds</td></tr>\n", ecm->lastdecode.counter, ecm->lastdecode.dcwchangetime/1000);
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			}
#endif
			//
			if (ecm->server[0].srvid) {
				sprintf( http_buf, "<tr><td><table class='infotable'><tbody><tr><th width='30px'>ID</th><th width='250px'>Server</th><th width='50px'>Status</th><th width='70px'>Start time</th><th width='70px'>End time</th><th width='90px'>Elapsed time</th><th>CW</th></tr></tbody>");
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				int i;
				for(i=0; i<20; i++) {
					if (!ecm->server[i].srvid) break;
					char* str_srvstatus[] = { "WAIT", "OK", "NOK", "BUSY" };
					struct server_data *srv = getsrvbyid(ecm->server[i].srvid);
					if (srv) {
						sprintf( http_buf,"<tr><td>%d</td><td>%s:%d</td><td>%s</td><td>%dms</td>", i+1, srv->host->name, srv->port, str_srvstatus[ecm->server[i].flag], ecm->server[i].sendtime - ecm->recvtime );
						tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
						// Recv Time
						if (ecm->server[i].statustime>ecm->server[i].sendtime)
							sprintf( http_buf,"<td>%dms</td><td>%dms</td>", ecm->server[i].statustime - ecm->recvtime, ecm->server[i].statustime-ecm->server[i].sendtime );
						else
							sprintf( http_buf,"<td>--</td><td>--</td>");
						tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
						// DCW
						if (ecm->server[i].flag==ECM_SRV_REPLY_GOOD) {
							sprintf( http_buf,"<td>"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
							array2hex( ecm->server[i].dcw, http_buf, 16 );	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
							sprintf( http_buf,"</td>"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
						}
						else {
							sprintf( http_buf,"<td>--</td>");
							tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
						}
						sprintf( http_buf,"</tr>");
						tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					}
				}
				tcp_writestr(&tcpbuf, sock, "</tbody></table></td></tr>\n" );
			}
		}
		tcp_writestr(&tcpbuf, sock, "</tbody></table><br>\n" );
	}

	// Current Busy Ecm
	if (cli->ecm.busy) {
		ECM_DATA *ecm = cli->ecm.request;
		if (ecm) http_send_ecmstatus(&tcpbuf, sock, ecm);
	}

	tcp_writestr(&tcpbuf, sock, "</td></tr></tbody></table>" );

	if (get_action==0) {
		tcp_writestr(&tcpbuf, sock, "</div>");
		tcp_writestr(&tcpbuf, sock, "</body></html>");
	}
	tcp_flush(&tcpbuf, sock);
}


void http_send_profile(int sock, http_request *req)
{
	char http_buf[1024];
	struct tcp_buffer_data tcpbuf;
	// Get Profile
	int get_id = 0;
	char *str_id = isset_get( req, "id");
	if (str_id)	get_id = atoi(str_id);
	struct cardserver_data *cs = getcsbyid(get_id);
	if (!cs) return;
	// Action
	char *str_action = isset_get( req, "action");
	int get_action = 0;
	if (str_action) {
		if (!strcmp(str_action,"div")) get_action = 1;
		else if (!strcmp(str_action,"row")) get_action = 2;
		else if (!strcmp(str_action,"disable")) get_action = 3;
		else if (!strcmp(str_action,"enable")) get_action = 4;
		else if (!strcmp(str_action,"status")) get_action = 5;
#ifndef PUBLIC
		else if (!strcmp(str_action,"xml")) get_action = 6; // XML info
#endif
		else if (!strcmp(str_action,"debug")) get_action = 7;
		else str_action = NULL;
	}
	if (!str_action) str_action = "page";
	//
	if (get_action==3) {
		cs->flags |= FLAG_DISABLE;
		////////// cc_disconnect_cli(cli);
		http_send_ok(sock);
		return;
	}
	else if (get_action==4) {
		cs->flags &= ~FLAG_DISABLE;
		http_send_ok(sock);
		return;
	}
	else if (get_action==5) {
		if (IS_DISABLED(cs->flags)) http_send_text(sock,"active"); else http_send_text(sock,"inactive");
		return;
	}
	else if (get_action==7) {
		flagdebug = getdbgflag( DBG_NEWCAMD, cs->id, 0);
		http_send_ok(sock);
		return;
	}

	//
	tcp_init(&tcpbuf);
	tcp_write(&tcpbuf, sock, http_replyok, strlen(http_replyok) );
	tcp_write(&tcpbuf, sock, http_html, strlen(http_html) );
	tcp_write(&tcpbuf, sock, http_head, strlen(http_head) );
	sprintf( http_buf, html_title, cfg.http.title, "Profile"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	tcp_write(&tcpbuf, sock, http_link, strlen(http_link) );
	tcp_write(&tcpbuf, sock, http_style, strlen(http_style) );
	tcp_write(&tcpbuf, sock, http_head_, strlen(http_head_) );
	tcp_write(&tcpbuf, sock, http_body, strlen(http_body) );
	tcp_write_menu(&tcpbuf, sock,0);

	sprintf( http_buf, "<input type=button onclick=\"parent.location='/newcamd?pid=%d'\" value='Newcamd Clients'>", cs->id);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

	sprintf( http_buf, "<br><br><div class=\"outer\"> <div class=\"top\"><b>Profile: %s</b><ul><li>Newcamd Port = %d</li>",cs->name, cs->newcamd.port);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
#ifdef RADEGAST_SRV
	sprintf( http_buf, "<li>Radegast Port = %d</li>", cs->radegast.port);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
#endif
	sprintf( http_buf, "<li>Network ID = %04X</li>", cs->option.onid);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf, "<li>Caid = %04X</li><li>Providers =", cs->card.caid);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	int i;
	for (i=0;i<cs->card.nbprov;i++) {
		sprintf( http_buf, " %06x",cs->card.prov[i].id);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}
	sprintf( http_buf, "</li><li>Total ECM = %d</li> <li>Accepted ECM = %d</li><li>Ecm OK = %d</li><li>Ecm Time = %dms</li><li>Total Cache Hits = %d</li><li>Instant Cache Hits = %d</li></ul>", cs->ecmaccepted+cs->ecmdenied, cs->ecmaccepted, cs->ecmok, cs->ecmoktime/(cs->ecmok+1), cs->hits.csp, cs->hits.instant.csp);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

	sprintf( http_buf, "</div><span style=\"float:right\"><table class=option border=1px cellspacing=0><tr><th width=150px>Option</th><th width=50px>Value</th></tr>");
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

	sprintf( http_buf,"<tr><td>ECM CHECK</td><td>%s</td></tr>", yesno(cs->option.checkecm)); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"<tr><td>ECM CHECK LENGTH</td><td>%s</td></tr>", yesno(cs->option.checkecmlength)); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"<tr><td>DCW TIMEOUT</td><td>%dms</td></tr>", cs->option.dcw.timeout); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
#ifndef PUBLIC
	sprintf( http_buf,"<tr><td>DCW RETRY</td><td>%d</td></tr>", cs->option.dcw.retry ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
#endif
	sprintf( http_buf,"<tr><td>DCW CHECK</td><td>%s</td></tr>", yesno(cs->option.dcw.check) ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"<tr><td>DCW HALFNULLED</td><td>%s</td></tr>", yesno(cs->option.dcw.halfnulled) ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
#ifdef DCWSWAP
	sprintf( http_buf,"<tr><td>DCW SWAP</td><td>%s</td></tr>", yesno(cs->option.dcw.swap) ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
#endif
	sprintf( http_buf,"<tr><td>DCW MAXFAILED</td><td>%d</td></tr>", cs->option.maxfailedecm); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"<tr><td>SERVER MAX</td><td>%d</td></tr>", cs->option.server.max); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"<tr><td>SERVER INTERVAL</td><td>%dms</td></tr>", cs->option.server.interval); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"<tr><td>SERVER TIMEOUT</td><td>%dms</td></tr>", cs->option.server.timeout); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
//	sprintf( http_buf,"<tr><td>SERVER TIMEPERECM:</td><td>%d</td></tr>", cs->option.server.timeperecm); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"<tr><td>SERVER VALIDECMTIME</td><td>%dms</td></tr>", cs->option.server.validecmtime); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"<tr><td>SERVER FIRST</td><td>%d</td></tr>", cs->option.server.first); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	//
	sprintf( http_buf,"<tr><td>ACCEPT NULL CAID</td><td>%s</td></tr>", yesno(cs->option.faccept0caid) ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"<tr><td>ACCEPT NULL PROVIDER</td><td>%s</td></tr>", yesno(cs->option.faccept0provider) ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"<tr><td>ACCEPT NULL SID</td><td>%s</td></tr>", yesno(cs->option.faccept0sid) ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	//
	sprintf( http_buf,"<tr><td>ENABLE CCCAM</td><td>%s</td></tr>", yesno(cs->option.fallowcccam) ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"<tr><td>ENABLE NEWCAMD</td><td>%s</td></tr>", yesno(cs->option.fallownewcamd) ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"<tr><td>ENABLE RADEGAST</td><td>%s</td></tr>", yesno(cs->option.fallowradegast) ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"<tr><td>ENABLE CAMD35</td><td>%s</td></tr>", yesno(cs->option.fallowcamd35) ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"<tr><td>ENABLE CS378X</td><td>%s</td></tr>", yesno(cs->option.fallowcs378x) ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
//	sprintf( http_buf,"<tr><td>ENABLE SKIPCWC</td><td>%s</td></tr>", yesno(cs->option.fallowskipcwc) ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"<tr><td>ENABLE CACHE</td><td>%s</td></tr>", yesno(cs->option.fallowcache) ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
#ifdef CACHEEX
	sprintf( http_buf,"<tr><td>ENABLE CACHEEX</td><td>%s</td></tr>", yesno(cs->option.fallowcacheex) ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"<tr><td>CACHEEX MAXHOP</td><td>%d</td></tr>", cs->option.cacheex.maxhop ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	//sprintf( http_buf,"<tr><td>CACHEEX VALIDECMTIME</td><td>%dms</td></tr>", cs->option.cacheexvalidtime ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
#endif
	//
	sprintf( http_buf,"<tr><td>RETRY NEWCAMD</td><td>%d</td></tr>", cs->option.retry.newcamd); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"<tr><td>RETRY CCCAM</td><td>%d</td></tr>", cs->option.retry.cccam); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"<tr><td>CACHE TIMEOUT</td><td>%dms</td></tr>", cs->option.cachetimeout); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"<tr><td>CACHE SENDREQ</td><td>%s</td></tr>", yesno(cs->option.cachesendreq) ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
#ifndef PUBLIC
	//sprintf( http_buf,"<tr><td>CACHE RESENDREQ</td><td>%s</td></tr>", yesno(cs->option.cacheresendreq) ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"<tr><td>CACHE SENDREP</td><td>%s</td></tr>", yesno(cs->option.cachesendrep) ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"<tr><td>CACHE STATIC</td><td>%s</td></tr>", yesno(cs->option.cachestatic) ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
#endif
	sprintf( http_buf, "</table></span></div><br><br>"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	tcp_writestr(&tcpbuf, sock, "<div style=\"clear:both\"></div>" );

/*
#ifdef RADEGAST_SRV
	struct rdgd_client_data *rdgdcli;
	if (cs->radegast.handle && cs->radegast.client) {
		//READEGAST CLIENTS
		sprintf( http_buf, "<br>Connected Radegast Clients: %d<br><table class=maintable width=100%%><tr><th width=110px>IP Address</th><th width=100px>Connected</th><th width=60px>TotalEcm</th><th width=90px>AcceptedEcm</th><th width=90px>EcmOK</th><th width=50px>EcmTime</th><th>Last used share</th></tr>", connected_radegast_clients(cs));
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		rdgdcli = cs->radegast.client;
		int alt=0;
		while (rdgdcli) {
			if (rdgdcli->handle>0) {
				if (alt==1) alt=2; else alt=1;
				d = (GetTickCount()-rdgdcli->connected)/1000;
				if (rdgdcli->ecm.busy)
					sprintf( http_buf,"<tr class=alt%d><td>%s</td><td class=\"busy\">%02dd %02d:%02d:%02d</td>",alt,(char*)ip2string(rdgdcli->ip), d/(3600*24), (d/3600)%24, (d/60)%60, d%60);
				else
					sprintf( http_buf,"<tr class=alt%d><td>%s</td><td class=\"online\">%02dd %02d:%02d:%02d</td>",alt,(char*)ip2string(rdgdcli->ip), d/(3600*24), (d/3600)%24, (d/60)%60, d%60);
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

				sprintf( http_buf, "<td align=center>%d</td>", rdgdcli->ecmnb );
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				int ecmaccepted = rdgdcli->ecmnb-rdgdcli->ecmdenied;
				tcp_writeecmdata(&tcpbuf, sock, ecmaccepted, rdgdcli->ecmnb);
				tcp_writeecmdata(&tcpbuf, sock, rdgdcli->ecmok, ecmaccepted);
				//Ecm Time
				if (rdgdcli->ecmok)
					sprintf( http_buf,"<td align=center>%d ms</td>",(rdgdcli->ecmoktime/rdgdcli->ecmok) );
				else
					sprintf( http_buf,"<td align=center>-- ms</td>");
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				//Last Used Share
				if ( rdgdcli->ecm.lastcaid ) {
					if (rdgdcli->ecm.laststatus) sprintf( http_buf,"<td class=success>"); else sprintf( http_buf,"<td class=failed>");
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					sprintf( http_buf,"ch %s (%dms) %s ", getchname(rdgdcli->ecm.lastcaid, rdgdcli->ecm.lastprov, rdgdcli->ecm.lastsid) , rdgdcli->ecm.lastdecodetime, str_laststatus[rdgdcli->ecm.laststatus] );
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					if ( (GetTickCount()-rdgdcli->ecm.recvtime) < 20000 ) {
						if (rdgdcli->ecm.lastdcwsrctype==DCW_SOURCE_SERVER) {
							struct server_data *srv = getsrvbyid(rdgdcli->ecm.lastdcwsrcid);
							if (srv) {
								sprintf( http_buf," / from server (%s:%d)", srv->host->name, srv->port);
								tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
							}
						}
						else if (rdgdcli->ecm.lastdcwsrctype==DCW_SOURCE_CACHE) {
							struct cachepeer_data *peer = getpeerbyid(rdgdcli->ecm.lastdcwsrcid);
							if (peer) {
								sprintf( http_buf," / from cache peer (%s:%d)", peer->host->name, peer->port);
								tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
							}
						}
					}
					sprintf( http_buf,"</td>");
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				}
				else {
					sprintf( http_buf,"<td> </td>");
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				}
				sprintf( http_buf,"</tr>");
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			}
			rdgdcli = rdgdcli->next;
		}
		sprintf( http_buf, "</table>");
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}
#endif

*/

	// Send Stat
	sprintf( http_buf, "<style type=\"text/css\">\n.mainborder\n{ background: #d2d2d2; border: 1px solid #0B198C; border-spacing: 0px; font: 10px verdana, geneva, lucida, 'lucida grande', arial, helvetica, sans-serif; padding: 1 2; }\n.redborder { background: #d25555; border-left: 1px solid #eee; border-right: 1px solid #eee; border-bottom: 1px solid #eee; border-spacing: 0px; font: 9px verdana, geneva, lucida, 'lucida grande', arial, helvetica, sans-serif; }\n.greenborder { background: #55d255; border-left: 1px solid #eee; border-right: 1px solid #eee; border-bottom: 1px solid #eee; border-spacing: 0px; font: 9px verdana, geneva, lucida, 'lucida grande', arial, helvetica, sans-serif; }\n.cacheborder { background: #5555e2; border-left: 1px solid #eee; border-right: 1px solid #eee; border-bottom: 1px solid #eee; border-spacing: 0px; font: 9px verdana, geneva, lucida, 'lucida grande', arial, helvetica, sans-serif; }\n</style>\n");
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
#ifdef SRV_CSCACHE
	sprintf( http_buf, "<style type=\"text/css\">\n.clientsborder { background: goldenrod; border-left: 1px solid #eee; border-right: 1px solid #eee; border-bottom: 1px solid #eee; border-spacing: 0px; font: 9px verdana, geneva, lucida, 'lucida grande', arial, helvetica, sans-serif; }\n</style>\n");
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
#endif
#ifdef CACHEEX
	sprintf( http_buf, "<style type=\"text/css\">\n.cacheexborder { background: darkblue; border-left: 1px solid #eee; border-right: 1px solid #eee; border-bottom: 1px solid #eee; border-spacing: 0px; font: 9px verdana, geneva, lucida, 'lucida grande', arial, helvetica, sans-serif; }\n</style>\n");
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
#endif
	if (cs->ecmok) {
		sprintf( http_buf, "\n<br><br><table class=\"mainborder\" width=100%%>"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		sprintf( http_buf, "<tr><td><div class=\"redborder\" style=\"height: 10px; width: 10px;\"></div> </td><td width=100%%>Total DCW number</td></tr><tr><td><div class=greenborder style=\"height: 10px; width: 10px;\"></div> </td><td width=100%%>Number of DCW from servers</td></tr><tr><td><div class=cacheborder style=\"height: 10px; width: 10px;\"></div> </td><td width=100%%>Number of DCW from Cache</td></tr><tr><td><div class=cacheexborder style=\"height: 10px; width: 10px;\"></div> </td><td width=100%%>Number of DCW from CacheEX</td></tr><tr><td><div class=clientsborder style=\"height: 10px; width: 10px;\"></div> </td><td width=100%%>Number of DCW from Newcamd/Mgcamd Clients</td></tr>\n"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		//Get Max of ttime
		int max=1;
		int timeout = cs->option.dcw.timeout * (cs->option.dcw.retry+1);
		if (timeout>10000) timeout = 10000;
		for(i=0; i<(timeout/100); i++) if (max<cs->ttime[i]) max=cs->ttime[i];
		for(i=0; i<(timeout/100); i++) {
			sprintf( http_buf, "<tr><td>%d.%ds</td><td>", i/10,i%10 );
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			// RED
			int width = cs->ttime[i]*100/max;
			if (width>10)
				sprintf( http_buf, "<div class=redborder style='height:3px; width:%d%%'><span style=\"float: right;\">%d</span></div>", width, cs->ttime[i] );
			else {
				if (!width && cs->ttime[i])
					sprintf( http_buf, "<div class=redborder style='height:2px; width:1px;'></div>");
				else
					sprintf( http_buf, "<div class=redborder style='height:2px; width:%d%%'></div>", width );
			}
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			// GREEN
			width = cs->ttimecards[i]*100/max;
			if ( !width && cs->ttimecards[i] )
				sprintf( http_buf, "<div class=greenborder style='height:2px; width:1px;'></div>");
			else
				sprintf( http_buf, "<div class=greenborder style='height:2px; width:%d%%'></div>", width );
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			// CACHE - BLUE
			width = cs->ttimecache[i]*100/max;
			if ( !width && cs->ttimecache[i] )
				sprintf( http_buf, "<div class=cacheborder style='height:2px; width:1px;'></div>");
			else
				sprintf( http_buf, "<div class=cacheborder style='height:2px; width:%d%%'></div>", width );
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			// CACHEEX
			width = cs->ttimecacheex[i]*100/max;
			if ( !width && cs->ttimecacheex[i] )
				sprintf( http_buf, "<div class=cacheexborder style='height:2px; width:1px;'></div>");
			else
				sprintf( http_buf, "<div class=cacheexborder style='height:2px; width:%d%%'></div>", width );
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
#ifdef SRV_CSCACHE
			// YELLOW
			width = cs->ttimeclients[i]*100/max;
			if ( !width && cs->ttimeclients[i] )
				sprintf( http_buf, "<div class=clientsborder style='height:2px; width:1px;'></div>");
			else
				sprintf( http_buf, "<div class=clientsborder style='height:2px; width:%d%%'></div>", width );
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
#endif
			//
			sprintf( http_buf, "</td></tr>");
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		}
		sprintf( http_buf, "</table><br>\n"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}

#ifndef PUBLIC
	// Runtime SIDS
	if (cs->deniedsids[0].sid) {
		sprintf( http_buf, "<br><b>Available Servers</b>");
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		int maxcards = 0;
		for(i=0; i<1024; i++) {
			if (cs->deniedsids[i].sid) {
				if (cs->deniedsids[i].nbsrv>maxcards) maxcards = cs->deniedsids[i].nbsrv;
			}
			else break;
		}

		int icard = 0;
		while(icard<=maxcards) {
			sprintf( http_buf, "<br>%d cards: ",icard);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			for(i=0; i<1024; i++)
				if (cs->deniedsids[i].sid) {
					if (cs->deniedsids[i].nbsrv==icard) {
						sprintf( http_buf, "%04x ", cs->deniedsids[i].sid);
						tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					}
				}
				else break;
			icard++;
		}
	}

	if (cs->sidlist.data) {
		sprintf( http_buf, "<br><table> <tr><th>SID:CHID:ECMLEN.CW1CYCLE</th> <th>ECMNB</td> <th>ECMOK</th> </tr>");
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

		int i;
		struct sid_chid_ecmlen_data *sids = cs->sidlist.data;
		for(i=0;i<MAX_SIDS;i++,sids++) {
			if (!sids->sid) break;
			sprintf( http_buf, "<tr> <td>%04x:%04x:%04x.%02x</td> <td>%d</td> <td>%d</td> </tr>", sids->sid, sids->chid, sids->ecmlen, sids->cw1cycle, sids->ecmnb, sids->ecmok );
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		}

		sprintf( http_buf, "</table>");
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

		// show sid file
		if (cs->card.nbprov==1) {
			struct sid_chid_ecmlen_data *sids = cs->sidlist.data;
			for(i=0;i<MAX_SIDS;i++,sids++) {
				if (!sids->sid) break;
				struct chninfo_data *chn = getchninfo(cs->card.caid, cs->card.prov[0].id, sids->sid);
				if (!chn) continue;
				if (sids->cw1cycle)
					sprintf( http_buf, "%04x:%06x:%04x.%02x \"%s\"<br>", cs->card.caid, cs->card.prov[0].id, sids->sid, sids->cw1cycle, chn->name );
				else
					sprintf( http_buf, "%04x:%06x:%04x \"%s\"<br>", cs->card.caid, cs->card.prov[0].id, sids->sid, chn->name );
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			}
		}
	}

	for(i=0; i<cs->card.nbprov; i++) {
		if (cs->card.prov[i].sidlist.data) {
			sprintf( http_buf, "<br><br>SIDLIST FOR PROVIDER: %06x<br><table> <tr><th>SID:CHID:ECMLEN.CW1CYCLE</th> <th>ECMNB</td> <th>ECMOK</th> </tr>",cs->card.prov[i].id);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			struct sid_chid_ecmlen_data *sids = cs->card.prov[i].sidlist.data;
			int j;
			for(j=0;j<MAX_SIDS;j++,sids++) {
				if (j>=cs->card.prov[i].sidlist.total) break;
				if (!sids->sid) break;
				sprintf( http_buf, "<tr> <td>%04x:%04x:%04x.%02x</td> <td>%d</td> <td>%d</td> </tr>", sids->sid, sids->chid, sids->ecmlen, sids->cw1cycle, sids->ecmnb, sids->ecmok );
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			}
			sprintf( http_buf, "</table>");
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

			tcp_writestr(&tcpbuf, sock, "<pre style='width:80%;height:50%; border:1 solid #777'>");
			sids = cs->card.prov[i].sidlist.data;
			for(i=0;i<MAX_SIDS;i++,sids++) {
				if (!sids->sid) break;
				struct chninfo_data *chn = getchninfo(cs->card.caid, cs->card.prov[0].id, sids->sid);
				if (!chn) continue;
				if (sids->cw1cycle)
					sprintf( http_buf, "%04x:%06x:%04x.%02x \"%s\"\n", cs->card.caid, cs->card.prov[0].id, sids->sid, sids->cw1cycle, chn->name );
				else
					sprintf( http_buf, "%04x:%06x:%04x \"%s\"\n", cs->card.caid, cs->card.prov[0].id, sids->sid, chn->name );
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			}
			tcp_writestr(&tcpbuf, sock, "</pre>");
		}
	}

#endif

	tcp_flush(&tcpbuf, sock);
}


////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

#ifdef CCCAM_SRV

void cccam_clients( struct cccam_server_data *cccam, int *total, int *connected, int *active )
{
	*total = 0;
	*connected = 0;
	*active = 0;
	struct cc_client_data *cli = cccam->client;
	while (cli) {
		(*total)++;
		if (cli->connection.status>0) {
			(*connected)++;
			if ( (GetTickCount()-cli->lastecmtime) < 20000 ) (*active)++;
		}
		cli=cli->next;
	}
}

void total_cccam_clients( struct config_data *cfg, int *total, int *connected, int *active )
{
	*total = 0;
	*connected = 0;
	*active = 0;
	struct cccam_server_data *cccam = cfg->cccam.server;
	while (cccam) {
		struct cc_client_data *cli = cccam->client;
		while (cli) {
			(*total)++;
			if (cli->connection.status>0) {
				(*connected)++;
				if ( (GetTickCount()-cli->lastecmtime) < 20000 ) (*active)++;
			}
			cli=cli->next;
		}
		cccam = cccam->next;
	}
}

void getcccamcells(struct cc_client_data *cli, char cell[10][2048])
{
	char temp[2048];
	unsigned int ticks = GetTickCount();
	unsigned int d;
	// CELL0 # NAME
	if (cli->realname)
		sprintf( cell[0],"<a href='/cccamclient?id=%d'>%s<br>%s</a>",cli->id,cli->user,cli->realname);
	else
		sprintf( cell[0],"<a href='/cccamclient?id=%d'>%s</a>",cli->id,cli->user);
	// CELL1 # VERSION
	if (strlen(cli->version)) sprintf( cell[1],"CCcam %s<br>%02x%02x%02x%02x%02x%02x%02x%02x", cli->version, cli->nodeid[0],cli->nodeid[1],cli->nodeid[2],cli->nodeid[3],cli->nodeid[4],cli->nodeid[5],cli->nodeid[6],cli->nodeid[7]);
	else strcpy( cell[1]," " ); 
	// CELL2 # IP
	char *p = getcountrycodebyip(cli->ip);
	if (cli->host)
		if (p) sprintf( cell[2],"<img src='/flag_%s.gif' title='%s'> %s<br>%s", p, getcountryname(p), (char*)ip2string(cli->ip), cli->host->name ); else sprintf( cell[2],"%s<br>%s",(char*)ip2string(cli->ip), cli->host->name );
	else
		if (p) sprintf( cell[2],"<img src='/flag_%s.gif' title='%s'> %s", p, getcountryname(p), (char*)ip2string(cli->ip) ); else sprintf( cell[2],"%s",(char*)ip2string(cli->ip) );
	// CELL3 # Connection Time
	if (cli->connection.status>0) {
		if (cli->ecm.busy) sprintf( cell[9],"busy"); else sprintf( cell[9],"online");
		d = (ticks-cli->connection.time)/1000;
		sprintf( cell[3], "%02dd %02d:%02d:%02d", d/(3600*24), (d/3600)%24, (d/60)%60, d%60);
	}
	else {
		strcpy( cell[9], "offline" );
		if (cli->flags&FLAG_DELETE) sprintf( cell[3],"Removed");
		else if (cli->flags&FLAG_EXPIRED) sprintf( cell[3],"Expired");
		else if (cli->flags&FLAG_DISABLE) sprintf( cell[3],"Disabled");
		else sprintf( cell[3],"offline");
	}
#ifdef EXPIREDATE
	if (cli->enddate.tm_year) {
		sprintf( temp,"<br>Expire: %d-%02d-%02d", 1900+cli->enddate.tm_year, cli->enddate.tm_mon+1, cli->enddate.tm_mday);
		strcat( cell[3], temp );
	}
#endif
	sprintf( temp, "<table class=\"connect_data\"><tr><td>Successful Login: %d</td><td>Aborted Connections: %d</td><td>Total Zapping: %d</td><td>Channel Freeze: %d</td></tr></table>", cli->nblogin, cli->nbloginerror, cli->zap, cli->freeze );
	strcat( cell[3], temp );

	// CELL4+5+6 # ECM STAT: TOTAL/ACCEPTED/OK
	sprintf( cell[4], "%d", cli->ecmnb);
	int ecmaccepted = cli->ecmnb-cli->ecmdenied;
	getstatcell( ecmaccepted, cli->ecmnb, cell[5]);
	getstatcell( cli->ecmok, ecmaccepted, cell[6]);
	// CELL7 # Ecm Time
	if (cli->ecmok) sprintf( cell[7],"%d ms",(cli->ecmoktime/cli->ecmok) ); else sprintf( cell[7],"-- ms");
	// CELL8 # Last Used Share
	if ( cli->connection.status<=0 && cli->connection.lastseen) {
		d = (ticks-cli->connection.lastseen)/1000;
		sprintf( cell[8],"Last Seen %02dd %02d:%02d:%02d", d/(3600*24),(d/3600)%24,(d/60)%60,d%60);
	}
	else if ( cli->lastecm.caid ) {
		if (cli->lastecm.status)  strcpy( cell[8],"<span class=success"); else strcpy( cell[8],"<span class=failed");
		sprintf( temp," title='%04x:%06x:%04x'>ch %s (%dms) %s ",cli->lastecm.caid, cli->lastecm.prov, cli->lastecm.sid, getchname(cli->lastecm.caid, cli->lastecm.prov, cli->lastecm.sid) , cli->lastecm.decodetime, str_laststatus[cli->lastecm.status] );
		strcat( cell[8], temp );
		if ( (GetTickCount()-cli->ecm.recvtime) < 20000 ) {
			// From ???
			if (cli->lastecm.status) {
				strcat( cell[8], " / from ");
				src2string(cli->lastecm.dcwsrctype, cli->lastecm.dcwsrcid, temp);
				strcat( cell[8], temp);
			}
		}
		strcat( cell[8], "</span>" );
	}
	else strcpy( cell[8], " ");
	strcat( cell[8], "<span style='float:right;'>");
	if ( !(cli->flags&(FLAG_DELETE|FLAG_EXPIRED)) ) {
		if (cli->flags&FLAG_DISABLE) {
			sprintf( temp," <img title='Enable' src='enable.png' OnClick=\"imgrequest('/cccamclient?action=enable&id=%d',this);\">",cli->id);
			strcat( cell[8], temp );
		}
		else {
			sprintf( temp," <img title='disable' src='disable.png' OnClick=\"imgrequest('/cccamclient?action=disable&id=%d',this);\">",cli->id);
			strcat( cell[8], temp );
		}
	}
	sprintf( temp," <img title='Debug' src='debug.png' OnClick=\"imgrequest('/cccamclient?action=debug&id=%d',this);\">",cli->id);
	strcat( cell[8], temp );
	strcat( cell[8], "</span>");
}

int total_cccam_servers()
{
	int count=0;
	struct cccam_server_data *srv = cfg.cccam.server;
	while (srv) {
		count++;
		srv = srv->next;
	}
	return count;
}	


void http_send_cccam(int sock, http_request *req)
{
	char http_buf[2048];
	struct tcp_buffer_data tcpbuf;
	char cell[10][2048];

	// Get Params
	char *str_action = isset_get( req, "action");
	char *str_list = isset_get( req, "list");
	char *str_id = isset_get( req, "id"); // CCcam server ID
	char *str_clid = isset_get( req, "clid"); // Client ID
#ifndef PUBLIC
	char *str_clname = isset_get( req, "clname"); // Client NAME
#endif
	// Param 'action'
	int get_action;
	if (str_action) {
		if (!strcmp(str_action,"div")) get_action = ACTION_DIV;
		else if (!strcmp(str_action,"row")) get_action = ACTION_ROW;
		else if (!strcmp(str_action,"xml")) get_action = ACTION_XML; // Get Clients info in xml
        else if (!strcmp(str_action,"json")) get_action = ACTION_JSON; // Get Clients info in xml
		else if (!strcmp(str_action,"disable")) get_action = ACTION_DISABLE;
		else if (!strcmp(str_action,"enable")) get_action = ACTION_ENABLE;
		else if (!strcmp(str_action,"status")) get_action = ACTION_STATUS;
		else if (!strcmp(str_action,"debug")) get_action = ACTION_DEBUG;
		else str_action = NULL;
	}
	if (!str_action) { str_action = "page"; get_action = ACTION_PAGE; }

	/////////////////////////////////////////////

	if (get_action==ACTION_ROW) {
		// Check for XML ROW
		struct cc_client_data *cli = NULL;
		if (str_clid) {
			cli = getcccamclientbyid( atoi(str_clid) );
			if (!cli) return;
		}

		else {
			if (str_id && str_clname) {
				struct cccam_server_data *cccam = getcccamserverbyid( atoi(str_id) );
				if (!cccam) return;
				cli = getcccamclientbyname( cccam, str_clname );
				if (!cli) return;
			}
			else return;
		}

		// Send XML CELLS
		getcccamcells(cli,cell);
		int i; for(i=0; i<10; i++) xmlescape( cell[i] );
		char buf[5000] = "";
		sprintf( buf, "<cccam>\n<c0>%s</c0>\n<c1>%s</c1>\n<c2>%s</c2>\n<c3_c>%s</c3_c>\n<c3>%s</c3>\n<c4>%s</c4>\n<c5>%s</c5>\n<c6>%s</c6>\n<c7>%s</c7>\n<c8>%s</c8>\n</cccam>\n",cell[0],cell[1],cell[2],cell[9],cell[3],cell[4],cell[5],cell[6],cell[7],cell[8] );
		http_send_xml( sock, req, buf, strlen(buf));
		return;
	}			
	else if (get_action==ACTION_XML) {
		struct cccam_server_data *cccam = NULL;
		if (str_id) cccam = getcccamserverbyid( atoi(str_id) );
		tcp_init(&tcpbuf);
		tcp_writestr(&tcpbuf, sock, "HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n");

		tcp_writestr(&tcpbuf, sock, "<multics>");

		struct cccam_server_data *srv;
		if (cccam) srv = cccam; else srv = cfg.cccam.server;
		while (srv) {
			tcp_writestr(&tcpbuf, sock, "\n<cccam>");
			sprintf(http_buf, "<id>%d</id>", srv->id); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			sprintf(http_buf, "<port>%d</port>", srv->port); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			sprintf(http_buf, "<status>%d</status>", (srv->handle>0) ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			uint32_t ticks = GetTickCount();
			struct cc_client_data *cli = srv->client;
			while (cli) {
				tcp_writestr(&tcpbuf, sock, "<user>");
				sprintf(http_buf, "<name>%s</name>", cli->user); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				if (cli->connection.status>0) {
					tcp_writestr(&tcpbuf, sock, "<status>1</status>");
					sprintf( http_buf,"<ip>%s</ip>", (char*)ip2string(cli->ip) ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					char *p = getcountrycodebyip(cli->ip);
					if (p) sprintf(http_buf, "<country>%s</country>", p); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					uint32_t d = (ticks - cli->connection.time)/1000;
					sprintf(http_buf, "<connected>%02dd %02d:%02d:%02d</connected>", d/(3600*24), (d/3600)%24, (d/60)%60, d%60); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				}
				else {
					sprintf(http_buf, "<status>%d</status>",cli->flags&0x0E);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				}
				tcp_writestr(&tcpbuf, sock, "</user>");
				cli = cli->next;
			}
			tcp_writestr(&tcpbuf, sock, "\n</cccam>");

			if (cccam) break; else srv = srv->next;
		}
		tcp_writestr(&tcpbuf, sock, "\n</multics>");
		tcp_flush(&tcpbuf, sock);
		return;
	}
    else if (get_action==ACTION_JSON) {
		struct cccam_server_data *cccam = NULL;
		if (str_id) cccam = getcccamserverbyid( atoi(str_id) );
		tcp_init(&tcpbuf);
		tcp_writestr(&tcpbuf, sock, "HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n");

		tcp_writestr(&tcpbuf, sock, "[");

		struct cccam_server_data *srv;
		if (cccam) srv = cccam; else srv = cfg.cccam.server;
		while (srv) {
			tcp_writestr(&tcpbuf, sock, "{");
			sprintf(http_buf, "\"id\": %d,", srv->id); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			sprintf(http_buf, "\"port\": %d,", srv->port); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			sprintf(http_buf, "\"status\": %d,", (srv->handle>0) ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			tcp_writestr(&tcpbuf, sock, "\"users\": [");
            uint32_t ticks = GetTickCount();
			struct cc_client_data *cli = srv->client;
			while (cli) {
				sprintf(http_buf, "{\"name\": \"%s\",", cli->user); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				if (cli->connection.status>0) {
					tcp_writestr(&tcpbuf, sock, "\"status\": 1,");
					sprintf( http_buf,"\"ip\": \"%s\",", (char*)ip2string(cli->ip) ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					char *p = getcountrycodebyip(cli->ip);
					if (p) sprintf(http_buf, "\"country\": \"%s\",", p); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					uint32_t d = (ticks - cli->connection.time)/1000;
                sprintf(http_buf, "\"connected\": %d}", d); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				}
				else {
                sprintf(http_buf, "\"status\": %d}",cli->flags&0x0E);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				}
                cli = cli->next;
                if (cli) tcp_writestr(&tcpbuf, sock, ",");
				
			}
            tcp_writestr(&tcpbuf, sock, "]");

			if (cccam) break; else srv = srv->next;
		}
    tcp_writestr(&tcpbuf, sock, "}]");
		tcp_flush(&tcpbuf, sock);
		return;
	}
    
	// Param 'id'
	int get_id = 0;
	if (str_id)	get_id = atoi(str_id);
	// Param 'list'
	int get_list = LIST_ACTIVE;
	if (str_list) {
		if (!strcmp(str_list,"connected")) get_list = LIST_CONNECTED;
		else if (!strcmp(str_list,"all")) get_list = LIST_ALL;
		else str_list = NULL;
	}
	if (!str_list) str_list = "active";
	//
	struct cccam_server_data *cccam = NULL;
	if (get_id) {
		cccam = getcccamserverbyid(get_id);
		if (!cccam) return;
	}

	tcp_init(&tcpbuf);
	tcp_write(&tcpbuf, sock, http_replyok, strlen(http_replyok) );
	if (get_action==ACTION_PAGE) {
		tcp_write(&tcpbuf, sock, http_html, strlen(http_html) );
		tcp_write(&tcpbuf, sock, http_head, strlen(http_head) );
		sprintf( http_buf, html_title, cfg.http.title, "CCcam"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		tcp_write(&tcpbuf, sock, http_link, strlen(http_link) );
		tcp_write(&tcpbuf, sock, http_style, strlen(http_style) );
		// JS
        tcp_write(&tcpbuf, sock, http_javascript, strlen(http_javascript) );
		tcp_writestr(&tcpbuf, sock, "\n<script type='text/javascript'>");
		// ACTIONS REQUEST
		tcp_writestr(&tcpbuf, sock, "\nfunction imgrequest( url, el )\n{\n	var httpRequest;\n	try { httpRequest = new XMLHttpRequest(); }\n	catch (trymicrosoft) { try { httpRequest = new ActiveXObject('Msxml2.XMLHTTP'); } catch (oldermicrosoft) { try { httpRequest = new ActiveXObject('Microsoft.XMLHTTP'); } catch(failed) { httpRequest = false; } } }\n	if (!httpRequest) { alert('Your browser does not support Ajax.'); return false; }\n	if ( typeof(el)!='undefined' ) {\n		el.onclick = null;\n		el.style.opacity = '0.7';\n		httpRequest.onreadystatechange = function()\n		{\n			if (httpRequest.readyState == 4) if (httpRequest.status == 200) el.style.opacity = '0.3';\n		}\n	}\n	httpRequest.open('GET', url, true);\n	httpRequest.send(null);\n}\n");
		// UPD ROW
		tcp_writestr(&tcpbuf, sock, "\nfunction xmlupdateRow( xmlDoc, id )\n{\n	var row = document.getElementById(id);\n	row.cells.item(0).innerHTML = xmlDoc.getElementsByTagName('c0')[0].childNodes[0].nodeValue;\n	row.cells.item(1).innerHTML = xmlDoc.getElementsByTagName('c1')[0].childNodes[0].nodeValue;\n	row.cells.item(2).innerHTML = xmlDoc.getElementsByTagName('c2')[0].childNodes[0].nodeValue;\n	row.cells.item(3).className = xmlDoc.getElementsByTagName('c3_c')[0].childNodes[0].nodeValue;\n	row.cells.item(3).innerHTML = xmlDoc.getElementsByTagName('c3')[0].childNodes[0].nodeValue;\n	row.cells.item(4).innerHTML = xmlDoc.getElementsByTagName('c4')[0].childNodes[0].nodeValue;\n	row.cells.item(5).innerHTML = xmlDoc.getElementsByTagName('c5')[0].childNodes[0].nodeValue;\n	row.cells.item(6).innerHTML = xmlDoc.getElementsByTagName('c6')[0].childNodes[0].nodeValue;\n	row.cells.item(7).innerHTML = xmlDoc.getElementsByTagName('c7')[0].childNodes[0].nodeValue;\n	row.cells.item(8).innerHTML = xmlDoc.getElementsByTagName('c8')[0].childNodes[0].nodeValue;\n}\n");
		char url[256];
		sprintf( url, "'/cccam?action=row&clid='+idx");
		sprintf( http_buf, HTTP_UPDATE_ROW, url);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		// UPD DIV
		sprintf( url, "/cccam?action=div&id=%d&list=%s", get_id, str_list);
		sprintf( http_buf, HTTP_UPDATE_DIV, cfg.http.autorefresh*1000, url);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		//
		tcp_writestr(&tcpbuf, sock, "\nfunction start()\n{\n	setautorefresh(autorefresh);\n}");
		tcp_writestr(&tcpbuf, sock, "\n</script>\n");
		tcp_write(&tcpbuf, sock, http_head_, strlen(http_head_) );
		tcp_writestr(&tcpbuf, sock, "<body onload=\"start();\">");
		tcp_write_menu(&tcpbuf, sock,PAGE_CCCAM);
		tcp_writestr(&tcpbuf, sock, "<table style=\"margin:0px; padding:0px; border-width:0px; border-spacing: 1px;\"><tr>");
		tcp_writestr(&tcpbuf, sock, "<td style=\"margin:0px; padding:0px;\"><a href='/cccam'><table border=1 width=200px>");
		// Total Servers
		sprintf( http_buf, "<tr><td>Total CCcam Servers: %d</td></tr>", total_cccam_servers() ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		// Nodeid
		sprintf( http_buf,"<tr><td>NodeID = %02x%02x%02x%02x%02x%02x%02x%02x</td></tr>", cfg.nodeid[0], cfg.nodeid[1], cfg.nodeid[2], cfg.nodeid[3], cfg.nodeid[4], cfg.nodeid[5], cfg.nodeid[6], cfg.nodeid[7]);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		// Version
		sprintf( http_buf, "<tr><td>Version = %s</td></tr>", cfg.cccam.version);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		tcp_writestr(&tcpbuf, sock, "</table></a></td>");
		// Servers
		if (cfg.cccam.server) {
			int counter = 0;
			struct cccam_server_data *cccam = cfg.cccam.server;
			while ( cccam && (counter<5) ) {
				sprintf( http_buf, "<td style=\"margin:0px; padding: 0px;\"><a href='/cccam?id=%d'><table border=1 width=150px>", cccam->id);
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				if (cccam->handle>0) sprintf( http_buf, "<tr><td>CCcam %d [<span class=success>ENABLED</span>]</td></tr>", cccam->id);
				else sprintf( http_buf, "<tr><td>CCcam %d [<span class=failed>DISABLED</span>]</td></tr>", cccam->id);
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				sprintf( http_buf, "<tr><td>Port = %d</td></tr>", cccam->port);
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				int total, connected, active;
				cccam_clients( cccam, &total, &connected, &active );
				sprintf( http_buf, "<tr><td>Connected: %d / %d</td></tr>", connected, total);
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				tcp_writestr(&tcpbuf, sock, "</table></a></td>");
				counter++;
				cccam = cccam->next;
			}
		}
		// End of table
		tcp_writestr(&tcpbuf, sock, "</tr></table><br>");
		// DIV
		tcp_writestr(&tcpbuf, sock, "\n<div id='mainDiv'>");
	}

	tcp_writestr(&tcpbuf, sock, "<select style=\"width:200px;\" onchange=\"parent.location.href='/cccam?id='+this.value\">");
	sprintf( http_buf, "<option value=0>ALL (%d)</option>", total_cccam_servers());
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	struct cccam_server_data *tmp = cfg.cccam.server;
	while (tmp) {
		if (get_id==tmp->id) sprintf( http_buf, "<option value=%d selected>[%d] CCcam %d</option>",tmp->id,tmp->port, tmp->id );
		else sprintf( http_buf, "<option value=%d>[%d] CCcam %d</option>",tmp->id,tmp->port, tmp->id );
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		tmp = tmp->next;
	}
	tcp_writestr(&tcpbuf, sock, "</select> ");
	//
	int total, connected, active;
	if (cccam) cccam_clients( cccam, &total, &connected, &active ); else total_cccam_clients( &cfg, &total, &connected, &active );
	char *class1 = "button"; char *class2 = "sbutton";
	char *class;
	if (get_list==LIST_ACTIVE) class = class2; else class = class1;
	sprintf( http_buf, "<input type=button class=%s onclick=\"parent.location='/cccam?id=%d&amp;list=active'\" value='Active Clients (%d)'>", class, get_id, active);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	if (get_list==LIST_CONNECTED) class = class2; else class = class1;
	sprintf( http_buf, " <input type=button class=%s onclick=\"parent.location='/cccam?id=%d&amp;list=connected'\" value='Connected Clients (%d)'>", class, get_id, connected);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	if (get_list==LIST_ALL) class = class2; else class = class1;
	sprintf( http_buf, " <input type=button class=%s onclick=\"parent.location='/cccam?id=%d&amp;list=all'\" value='All Clients (%d)'>", class, get_id, total);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	//
	if (get_id) { // One Server Selected
		// Table
		sprintf( http_buf, "\n<table class=maintable width=100%%><tr><th width=100px>Client</th><th width=70px>version</th><th width=120px>ip</th><th width=110px>Connected</th><th width=60px>TotalEcm</th><th width=90px>AcceptedEcm</th><th width=90px>EcmOK</th><th width=50px>EcmTime</th><th>Last used share</th></tr>");
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		struct cc_client_data *cli = cccam->client;
		int alt=0;
		if (get_list==LIST_ACTIVE) {
			while (cli) {
				if ( (cli->connection.status>0)&&((GetTickCount()-cli->lastecmtime) < 20000) ) {
					if (alt==1) alt=2; else alt=1;
					getcccamcells(cli,cell);
					sprintf( http_buf,"\n<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td>%s</td><td class=\"%s\">%s</td><td align=center>%s</td><td>%s</td><td>%s</td><td align=center>%s</td><td>%s</td></tr>\n",cli->id,alt,cli->id,cell[0],cell[1],cell[2],cell[9],cell[3],cell[4],cell[5],cell[6],cell[7],cell[8]);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				}
				cli = cli->next;
			}
		}
		else if (get_list==LIST_CONNECTED) {
			while (cli) {
				if (cli->connection.status>0) {
					if (alt==1) alt=2; else alt=1;
					getcccamcells(cli,cell);
					sprintf( http_buf,"\n<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td>%s</td><td class=\"%s\">%s</td><td align=center>%s</td><td>%s</td><td>%s</td><td align=center>%s</td><td>%s</td></tr>\n",cli->id,alt,cli->id,cell[0],cell[1],cell[2],cell[9],cell[3],cell[4],cell[5],cell[6],cell[7],cell[8]);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				}
				cli = cli->next;
			}
		}
		else { // ALL
			while (cli) {
				if (alt==1) alt=2; else alt=1;
				getcccamcells(cli,cell);
				sprintf( http_buf,"\n<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td>%s</td><td class=\"%s\">%s</td><td align=center>%s</td><td>%s</td><td>%s</td><td align=center>%s</td><td>%s</td></tr>\n",cli->id,alt,cli->id,cell[0],cell[1],cell[2],cell[9],cell[3],cell[4],cell[5],cell[6],cell[7],cell[8]);
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				cli = cli->next;
			}
		}
		sprintf( http_buf, "\n</table>");
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}

	else {
		// Table
		tcp_writestr(&tcpbuf,sock, "\n<table class=maintable width=100%>");
		tcp_writestr(&tcpbuf,sock, "\n<tr><th width=100px>Client</th><th width=70px>version</th><th width=120px>ip</th><th width=110px>Connected</th><th width=60px>TotalEcm</th><th width=90px>AcceptedEcm</th><th width=90px>EcmOK</th><th width=50px>EcmTime</th><th>Last used share</th></tr>");
		int alt=0;
		cccam = cfg.cccam.server;
		while (cccam) {
			int total, connected, active;
			cccam_clients( cccam, &total, &connected, &active );
			if ( (get_list==LIST_ACTIVE) && active ) {
				sprintf( http_buf,"\n<tr><td class=alt3 colspan=9> CCcam %d (%d)</td></tr>", cccam->id, active); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				struct cc_client_data *cli = cccam->client;
				while (cli) {
					if ( (cli->connection.status>0)&&((GetTickCount()-cli->lastecmtime) < 20000) ) {
						if (alt==1) alt=2; else alt=1;
						getcccamcells(cli,cell);
						sprintf( http_buf,"\n<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td>%s</td><td class=\"%s\">%s</td><td align=center>%s</td><td>%s</td><td>%s</td><td align=center>%s</td><td>%s</td></tr>\n",cli->id,alt,cli->id,cell[0],cell[1],cell[2],cell[9],cell[3],cell[4],cell[5],cell[6],cell[7],cell[8]);
						tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					}
					cli = cli->next;
				}
			}
			else if ( (get_list==LIST_ALL) && total ) {
				sprintf( http_buf,"\n<tr><td class=alt3 colspan=9> CCcam %d (%d)</td></tr>", cccam->id, total); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				struct cc_client_data *cli = cccam->client;
				while (cli) {
					if (alt==1) alt=2; else alt=1;
					getcccamcells(cli,cell);
					sprintf( http_buf,"\n<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td>%s</td><td class=\"%s\">%s</td><td align=center>%s</td><td>%s</td><td>%s</td><td align=center>%s</td><td>%s</td></tr>\n",cli->id,alt,cli->id,cell[0],cell[1],cell[2],cell[9],cell[3],cell[4],cell[5],cell[6],cell[7],cell[8]);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					cli = cli->next;
				}
			}
			else if ( (get_list==LIST_CONNECTED) && connected ) {
				sprintf( http_buf,"\n<tr><td class=alt3 colspan=9> CCcam %d (%d)</td></tr>", cccam->id, connected); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				struct cc_client_data *cli = cccam->client;
				while (cli) {
					if (cli->connection.status>0) {
						if (alt==1) alt=2; else alt=1;
						getcccamcells(cli,cell);
						sprintf( http_buf,"\n<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td>%s</td><td class=\"%s\">%s</td><td align=center>%s</td><td>%s</td><td>%s</td><td align=center>%s</td><td>%s</td></tr>\n",cli->id,alt,cli->id,cell[0],cell[1],cell[2],cell[9],cell[3],cell[4],cell[5],cell[6],cell[7],cell[8]);
						tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					}
					cli = cli->next;
				}
			}
			cccam = cccam->next;
		}
		sprintf( http_buf, "</table>");
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}
	if (get_action==ACTION_PAGE) {
		tcp_writestr(&tcpbuf, sock, "</div>");
		tcp_writestr(&tcpbuf, sock, "</body></html>");
	}

	tcp_flush(&tcpbuf, sock);
}



#ifdef CS378X_SRV

void getcs378xcells(struct camd35_client_data *cli, char cell[10][2048])
{
	char temp[2048];

	// CELL0 # NAME
	sprintf( cell[0],"<a href='/cs378xclient?id=%d'>%s</a>",cli->id,cli->user);

	// CELL1 # IP
	if ( cli->ip ) { // Get Last IP
		char *p = getcountrycodebyip(cli->ip);
		if (p) sprintf( cell[1],"<img src='/flag_%s.gif' title='%s'> %s", p, getcountryname(p), (char*)ip2string(cli->ip) ); else sprintf( cell[1],"%s",(char*)ip2string(cli->ip) );
	}
	else strcpy( cell[1], " ");

	// CELL2 # Connection Time
	if (cli->connection.status>0) {
		if (cli->ecm.busy) sprintf( cell[9],"busy"); else sprintf( cell[9],"online");
		uint d = (GetTickCount()-cli->connection.time)/1000;
		sprintf( cell[2], "%02dd %02d:%02d:%02d", d/(3600*24), (d/3600)%24, (d/60)%60, d%60);
	}
	else {
		sprintf( cell[9],"offline");
		if (cli->flags&FLAG_DELETE) sprintf( cell[2],"Removed");
		else if (cli->flags&FLAG_EXPIRED) sprintf( cell[2],"Expired");
		else if (cli->flags&FLAG_DISABLE) sprintf( cell[2],"Disabled");
		else sprintf( cell[2],"offline");
	}
	// CELL3+4+5 # ECM STAT: TOTAL/ACCEPTED/OK
	// ECM STAT
	sprintf( cell[3], "%d", cli->ecmnb );

	int ecmaccepted = cli->ecmnb-cli->ecmdenied;
	getstatcell( ecmaccepted, cli->ecmnb, cell[4]);
	getstatcell( cli->ecmok, ecmaccepted, cell[5]);

	// CELL6 # Ecm Time
	if (cli->ecmok) sprintf( cell[6],"%d ms",(cli->ecmoktime/cli->ecmok) ); else sprintf( cell[6],"-- ms");

	// CELL7 # Last Used Share
/*
	if ( srv->connection.status<=0 && srv->connection.lastseen) {
		int d = (GetTickCount()-cli->connection.lastseen)/1000;
		sprintf( cell[7],"Last Seen %02dd %02d:%02d:%02d", d/(3600*24),(d/3600)%24,(d/60)%60,d%60);
	}
	else
*/
	if ( cli->lastecm.caid ) {
		if (cli->lastecm.status)  strcpy( cell[7],"<span class=success"); else strcpy( cell[7],"<span class=failed");
		sprintf( temp," title='%04x:%06x:%04x'>ch %s (%dms) %s ",cli->lastecm.caid, cli->lastecm.prov, cli->lastecm.sid, getchname(cli->lastecm.caid, cli->lastecm.prov, cli->lastecm.sid) , cli->lastecm.decodetime, str_laststatus[cli->lastecm.status] );
		strcat( cell[7], temp );
		if ( (GetTickCount()-cli->ecm.recvtime) < 20000 ) {
			// From ???
			if (cli->lastecm.status) {
				strcat( cell[7], " / from ");
				src2string(cli->lastecm.dcwsrctype, cli->lastecm.dcwsrcid, temp);
				strcat( cell[7], temp);
			}
		}
		strcat( cell[7], "</span>" );
	}
	else strcpy( cell[7], " ");

	strcat( cell[7], "<span style='float:right;'>");
	if ( !(cli->flags&(FLAG_DELETE|FLAG_EXPIRED)) ) {
		if (cli->flags&FLAG_DISABLE) {
			sprintf( temp," <img title='Enable' src='enable.png' OnClick=\"imgrequest('/cs378xclient?id=%d&action=enable',this);\">",cli->id);
			strcat( cell[7], temp );
		}
		else {
			sprintf( temp," <img title='disable' src='disable.png' OnClick=\"imgrequest('/cs378xclient?id=%d&action=disable',this);\">",cli->id);
			strcat( cell[7], temp );
		}
	}
	sprintf( temp," <img title='Debug' src='debug.png' OnClick=\"imgrequest('/cs378xclient?id=%d&action=debug',this);\">",cli->id);
	strcat( cell[7], temp );
	strcat( cell[7], "</span>");
}

void total_cs378x_clients( int *total, int *connected, int *active )
{
	*total = 0;
	*connected = 0;
	*active = 0;
	struct camd35_server_data *cs378x = cfg.cs378x.server;
	while (cs378x) {
		struct camd35_client_data *cli = cs378x->client;
		while (cli) {
			(*total)++;
			if (cli->connection.status>0) {
				(*connected)++;
				if ( (GetTickCount()-cli->lastecmtime) < 20000 ) (*active)++;
			}
			cli=cli->next;
		}
		cs378x = cs378x->next;
	}
}

void cs378x_clients( struct camd35_server_data *cs378x, int *total, int *connected, int *active )
{
	*total = 0;
	*connected = 0;
	*active = 0;
	struct camd35_client_data *cli = cs378x->client;
	while (cli) {
		(*total)++;
		if (cli->connection.status>0) {
			(*connected)++;
			if ( (GetTickCount()-cli->lastecmtime) < 20000 ) (*active)++;
		}
		cli=cli->next;
	}
}

void http_send_cs378x(int sock, http_request *req)
{
	char http_buf[4096];
	struct tcp_buffer_data tcpbuf;
	char cell[10][2048];

	// Get Params
	char *str_action = isset_get( req, "action");
	char *str_list = isset_get( req, "list");
	char *str_id = isset_get( req, "id"); // server ID
	char *str_clid = isset_get( req, "clid"); // Client ID
	// Param 'action'
	int get_action;
	if (str_action) {
		if (!strcmp(str_action,"div")) get_action = ACTION_DIV;
		else if (!strcmp(str_action,"row")) get_action = ACTION_ROW;
#ifndef PUBLIC
		else if (!strcmp(str_action,"xml")) get_action = ACTION_XML; // Get Clients info in xml
#endif
		else if (!strcmp(str_action,"disable")) get_action = ACTION_DISABLE;
		else if (!strcmp(str_action,"enable")) get_action = ACTION_ENABLE;
		else if (!strcmp(str_action,"status")) get_action = ACTION_STATUS;
		else if (!strcmp(str_action,"debug")) get_action = ACTION_DEBUG;
		else str_action = NULL;
	}
	if (!str_action) { str_action = "page"; get_action = ACTION_PAGE; }
	/////////////////////////////////////////////
	if (get_action==ACTION_ROW) {
		// Check for XML ROW
		if (str_clid) {
			int id = atoi(str_clid);
			struct camd35_server_data *cs378x = cfg.cs378x.server;
			while (cs378x) {
				if (!(cs378x->flags&FLAG_DELETE)) {
					struct camd35_client_data *cli = cs378x->client;
					while (cli) {
						if ( !(cli->flags&FLAG_DELETE) && (cli->id==id) ) {
							// Send XML CELLS
							getcs378xcells(cli,cell);
							int i; for(i=0; i<10; i++) xmlescape( cell[i] );
							sprintf( http_buf, "<cs378x>\n<c0>%s</c0>\n<c1>%s</c1>\n<c2_c>%s</c2_c>\n<c2>%s</c2>\n<c3>%s</c3>\n<c4>%s</c4>\n<c5>%s</c5>\n<c6>%s</c6>\n<c7>%s</c7>\n</cs378x>\n",cell[0],cell[1],cell[9],cell[2],cell[3],cell[4],cell[5],cell[6],cell[7] );
							http_send_xml( sock, req, http_buf, strlen(http_buf));
						}
						cli = cli->next;
					}
				}
				cs378x = cs378x->next;
			}
		}
		return;
	}			

	// Param 'list'
	int get_list = LIST_ACTIVE;
	if (str_list) {
		if (!strcmp(str_list,"connected")) get_list = LIST_CONNECTED;
		else if (!strcmp(str_list,"all")) get_list = LIST_ALL;
		else str_list = NULL;
	}
	if (!str_list) str_list = "active";
	// Param 'id'
	int get_id = 0;
	struct camd35_server_data *cs378x = NULL;
	if (str_id)	{
		get_id = atoi(str_id);
		cs378x = cfg.cs378x.server;
		while (cs378x) {
			if (cs378x->id == get_id) break;
			cs378x = cs378x->next;
		}
		if (!cs378x) get_id = 0;
	}
	//
	tcp_init(&tcpbuf);
	if (get_action==ACTION_PAGE) {
		tcp_write(&tcpbuf, sock, http_replyok, strlen(http_replyok) );
		tcp_write(&tcpbuf, sock, http_html, strlen(http_html) );
		tcp_write(&tcpbuf, sock, http_head, strlen(http_head) );
		sprintf( http_buf, html_title, cfg.http.title, "cs378x"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		tcp_write(&tcpbuf, sock, http_link, strlen(http_link) );
		tcp_write(&tcpbuf, sock, http_style, strlen(http_style) );
		// JS
        tcp_write(&tcpbuf, sock, http_javascript, strlen(http_javascript) );
		tcp_writestr(&tcpbuf, sock, "\n<script type='text/javascript'>");
		// ACTIONS REQUEST
		tcp_writestr(&tcpbuf, sock, "\nfunction imgrequest( url, el )\n{\n	var httpRequest;\n	try { httpRequest = new XMLHttpRequest(); }\n	catch (trymicrosoft) { try { httpRequest = new ActiveXObject('Msxml2.XMLHTTP'); } catch (oldermicrosoft) { try { httpRequest = new ActiveXObject('Microsoft.XMLHTTP'); } catch(failed) { httpRequest = false; } } }\n	if (!httpRequest) { alert('Your browser does not support Ajax.'); return false; }\n	if ( typeof(el)!='undefined' ) {\n		el.onclick = null;\n		el.style.opacity = '0.7';\n		httpRequest.onreadystatechange = function()\n		{\n			if (httpRequest.readyState == 4) if (httpRequest.status == 200) el.style.opacity = '0.3';\n		}\n	}\n	httpRequest.open('GET', url, true);\n	httpRequest.send(null);\n}\n");
		// UPD ROW
		tcp_writestr(&tcpbuf, sock, "\nfunction xmlupdateRow( xmlDoc, id ) \n{\n    var row = document.getElementById(id);\n    	row.cells.item(0).innerHTML = xmlDoc.getElementsByTagName('c0')[0].childNodes[0].nodeValue;\n    row.cells.item(1).innerHTML = xmlDoc.getElementsByTagName('c1')[0].childNodes[0].nodeValue;\n    row.cells.item(2).className = xmlDoc.getElementsByTagName('c2_c')[0].childNodes[0].nodeValue;\n    row.cells.item(2).innerHTML = xmlDoc.getElementsByTagName('c2')[0].childNodes[0].nodeValue;\n    row.cells.item(3).innerHTML = xmlDoc.getElementsByTagName('c3')[0].childNodes[0].nodeValue;\n    row.cells.item(4).innerHTML = xmlDoc.getElementsByTagName('c4')[0].childNodes[0].nodeValue;\n    row.cells.item(5).innerHTML = xmlDoc.getElementsByTagName('c5')[0].childNodes[0].nodeValue;\n    row.cells.item(6).innerHTML = xmlDoc.getElementsByTagName('c6')[0].childNodes[0].nodeValue;\n    row.cells.item(7).innerHTML = xmlDoc.getElementsByTagName('c7')[0].childNodes[0].nodeValue;\n}");
		char url[256];
		sprintf( url, "'/cs378x?action=row&clid='+idx");
		sprintf( http_buf, HTTP_UPDATE_ROW, url);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		// UPD DIV
		sprintf( url, "/cs378x?action=div&id=%d&list=%s", get_id, str_list);
		sprintf( http_buf, HTTP_UPDATE_DIV, cfg.http.autorefresh*1000, url);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		//
		tcp_writestr(&tcpbuf, sock, "\nfunction start()\n{\n	setautorefresh(autorefresh);\n}");
		tcp_writestr(&tcpbuf, sock, "\n</script>\n");
		tcp_write(&tcpbuf, sock, http_head_, strlen(http_head_) );
		tcp_writestr(&tcpbuf, sock, "<body onload=\"start();\">");
		tcp_write_menu(&tcpbuf, sock,PAGE_CS378X);
		// DIV
		tcp_writestr(&tcpbuf, sock, "<div id='mainDiv'>");
	}

	tcp_writestr(&tcpbuf, sock, "<table style=\"margin:0px; padding:0px; border-width:0px; border-spacing: 1px;\"><tr>");
	tcp_writestr(&tcpbuf, sock, "<td style=\"margin:0px; padding:0px;\"><a href='/cs378x'><table border=1 width=200px>");
	// Total Servers
	sprintf( http_buf, "<tr><td>Total cs378x Servers: %d</td></tr>", cfg.cs378x.totalservers); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	int total, connected, active;
	total_cs378x_clients( &total, &connected, &active );
	sprintf( http_buf, "<tr><td>Connected Clients: %d / %d</td></tr>", connected, total ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	tcp_writestr(&tcpbuf, sock, "</table></a></td>");
	// Servers
	if (cfg.cs378x.server) {
		int counter = 0;
		struct camd35_server_data *cs378x = cfg.cs378x.server;
		while ( cs378x && (counter<5) ) {
			sprintf( http_buf, "<td style=\"margin:0px; padding: 0px;\"><a href='/cs378x?id=%d'><table border=1 width=150px>", cs378x->id);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			if (cs378x->handle>0) sprintf( http_buf, "<tr><td>cs378x %d [<span class=success>%d</span>]</td></tr>", cs378x->id, cs378x->port);
			else sprintf( http_buf, "<tr><td>cs378x %d [<span class=failed>%d</span>]</td></tr>", cs378x->id, cs378x->port);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			int total, connected, active;
			cs378x_clients( cs378x, &total, &connected, &active );
			sprintf( http_buf, "<tr><td>Connected: %d / %d</td></tr>", connected, total);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			tcp_writestr(&tcpbuf, sock, "</table></a></td>");
			counter++;
			cs378x = cs378x->next;
		}
	}
	// End of table
	tcp_writestr(&tcpbuf, sock, "</tr></table><br>");

	tcp_writestr(&tcpbuf, sock, "<select style=\"width:200px;\" onchange=\"parent.location.href='/cs378x?id='+this.value\">");
	sprintf( http_buf, "<option value=0>ALL (%d)</option>", cfg.cs378x.totalservers);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	struct camd35_server_data *tmp = cfg.cs378x.server;
	while (tmp) {
		if (get_id==tmp->id) sprintf( http_buf, "<option value=%d selected>[%d] cs378x %d</option>",tmp->id,tmp->port, tmp->id );
		else sprintf( http_buf, "<option value=%d>[%d] cs378x %d</option>",tmp->id,tmp->port, tmp->id );
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		tmp = tmp->next;
	}
	tcp_writestr(&tcpbuf, sock, "</select> ");
	//
	if (cs378x) cs378x_clients( cs378x, &total, &connected, &active ); else total_cs378x_clients( &total, &connected, &active );
	char *class1 = "button"; char *class2 = "sbutton";
	char *class;
	if (get_list==LIST_ACTIVE) class = class2; else class = class1;
	sprintf( http_buf, "<input type=button class=%s onclick=\"parent.location='/cs378x?id=%d&amp;list=active'\" value='Active Clients (%d)'>", class, get_id, active);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	if (get_list==LIST_CONNECTED) class = class2; else class = class1;
	sprintf( http_buf, " <input type=button class=%s onclick=\"parent.location='/cs378x?id=%d&amp;list=connected'\" value='Connected Clients (%d)'>", class, get_id, connected);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	if (get_list==LIST_ALL) class = class2; else class = class1;
	sprintf( http_buf, " <input type=button class=%s onclick=\"parent.location='/cs378x?id=%d&amp;list=all'\" value='All Clients (%d)'>", class, get_id, total);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	//
	if (get_id) { // One Server Selected
		// Table
		sprintf( http_buf, "\n<table class=maintable width=100%%><tr><th width=100px>Client</th><th width=120px>ip</th><th width=110px>Connected</th><th width=60px>TotalEcm</th><th width=90px>AcceptedEcm</th><th width=90px>EcmOK</th><th width=50px>EcmTime</th><th>Last used share</th></tr>");
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		struct camd35_client_data *cli = cs378x->client;
		int alt=0;
		if (get_list==LIST_ACTIVE) {
			while (cli) {
				if ( (cli->connection.status>0)&&((GetTickCount()-cli->lastecmtime) < 20000) ) {
					if (alt==1) alt=2; else alt=1;
					getcs378xcells(cli,cell);
					sprintf( http_buf,"\n<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td class=\"%s\">%s</td><td align=center>%s</td><td>%s</td><td>%s</td><td align=center>%s</td><td>%s</td></tr>\n",cli->id,alt,cli->id,cell[0],cell[1],cell[9],cell[2],cell[3],cell[4],cell[5],cell[6],cell[7]);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				}
				cli = cli->next;
			}
		}
		else if (get_list==LIST_CONNECTED) {
			while (cli) {
				if (cli->connection.status>0) {
					if (alt==1) alt=2; else alt=1;
					getcs378xcells(cli,cell);
					sprintf( http_buf,"\n<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td class=\"%s\">%s</td><td align=center>%s</td><td>%s</td><td>%s</td><td align=center>%s</td><td>%s</td></tr>\n",cli->id,alt,cli->id,cell[0],cell[1],cell[9],cell[2],cell[3],cell[4],cell[5],cell[6],cell[7]);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				}
				cli = cli->next;
			}
		}
		else { // ALL
			while (cli) {
				if (alt==1) alt=2; else alt=1;
				getcs378xcells(cli,cell);
				sprintf( http_buf,"\n<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td class=\"%s\">%s</td><td align=center>%s</td><td>%s</td><td>%s</td><td align=center>%s</td><td>%s</td></tr>\n",cli->id,alt,cli->id,cell[0],cell[1],cell[9],cell[2],cell[3],cell[4],cell[5],cell[6],cell[7]);
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				cli = cli->next;
			}
		}
		sprintf( http_buf, "\n</table>");
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}

	else {
		// Table
		tcp_writestr(&tcpbuf,sock, "\n<table class=maintable width=100%>");
		tcp_writestr(&tcpbuf,sock, "\n<tr><th width=100px>Client</th><th width=120px>ip</th><th width=110px>Connected</th><th width=60px>TotalEcm</th><th width=90px>AcceptedEcm</th><th width=90px>EcmOK</th><th width=50px>EcmTime</th><th>Last used share</th></tr>");
		int alt=0;
		cs378x = cfg.cs378x.server;
		while (cs378x) {
			int total, connected, active;
			cs378x_clients( cs378x, &total, &connected, &active );
			if ( (get_list==LIST_ACTIVE) && active ) {
				sprintf( http_buf,"\n<tr><td class=alt3 colspan=9> cs378x %d (%d)</td></tr>", cs378x->id, active); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				struct camd35_client_data *cli = cs378x->client;
				while (cli) {
					if ( (cli->connection.status>0)&&((GetTickCount()-cli->lastecmtime) < 20000) ) {
						if (alt==1) alt=2; else alt=1;
						getcs378xcells(cli,cell);
						sprintf( http_buf,"\n<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td class=\"%s\">%s</td><td align=center>%s</td><td>%s</td><td>%s</td><td align=center>%s</td><td>%s</td></tr>\n",cli->id,alt,cli->id,cell[0],cell[1],cell[9],cell[2],cell[3],cell[4],cell[5],cell[6],cell[7]);
						tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					}
					cli = cli->next;
				}
			}
			else if ( (get_list==LIST_ALL) && total ) {
				sprintf( http_buf,"\n<tr><td class=alt3 colspan=9> cs378x %d (%d)</td></tr>", cs378x->id, total); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				struct camd35_client_data *cli = cs378x->client;
				while (cli) {
					if (alt==1) alt=2; else alt=1;
					getcs378xcells(cli,cell);
					sprintf( http_buf,"\n<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td class=\"%s\">%s</td><td align=center>%s</td><td>%s</td><td>%s</td><td align=center>%s</td><td>%s</td></tr>\n",cli->id,alt,cli->id,cell[0],cell[1],cell[9],cell[2],cell[3],cell[4],cell[5],cell[6],cell[7]);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					cli = cli->next;
				}
			}
			else if ( (get_list==LIST_CONNECTED) && connected ) {
				sprintf( http_buf,"\n<tr><td class=alt3 colspan=9> cs378x %d (%d)</td></tr>", cs378x->id, connected); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				struct camd35_client_data *cli = cs378x->client;
				while (cli) {
					if (cli->connection.status>0) {
						if (alt==1) alt=2; else alt=1;
						getcs378xcells(cli,cell);
						sprintf( http_buf,"\n<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td class=\"%s\">%s</td><td align=center>%s</td><td>%s</td><td>%s</td><td align=center>%s</td><td>%s</td></tr>\n",cli->id,alt,cli->id,cell[0],cell[1],cell[9],cell[2],cell[3],cell[4],cell[5],cell[6],cell[7]);
						tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					}
					cli = cli->next;
				}
			}
			cs378x = cs378x->next;
		}
		sprintf( http_buf, "</table>");
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}
	if (get_action==ACTION_PAGE) {
		tcp_writestr(&tcpbuf, sock, "</div>");
		tcp_writestr(&tcpbuf, sock, "</body></html>");
	}

	tcp_flush(&tcpbuf, sock);
}

///////////////////////////////////////////////////////////////////////////////

void http_send_cs378x_client(int sock, http_request *req)
{
	char http_buf[2048];
	struct tcp_buffer_data tcpbuf;

	// Get Params
	char *str_action = isset_get( req, "action");
	char *str_id = isset_get( req, "id"); // Client ID
	char *str_name = isset_get( req, "name"); // Client NAME
	char *str_srvid = isset_get( req, "srvid"); // CCcam Server ID

	// Action
	int get_action = ACTION_PAGE;
	if (str_action) {
		if (!strcmp(str_action,"div")) get_action = ACTION_DIV;
		else if (!strcmp(str_action,"row")) get_action = ACTION_ROW;
		else if (!strcmp(str_action,"disable")) get_action = ACTION_DISABLE;
		else if (!strcmp(str_action,"enable")) get_action = ACTION_ENABLE;
		else if (!strcmp(str_action,"status")) get_action = ACTION_STATUS;
		else if (!strcmp(str_action,"debug")) get_action = ACTION_DEBUG;
		else if (!strcmp(str_action,"update")) get_action = ACTION_UPDATE;
		else str_action = NULL;
	}
	if (!str_action) { str_action = "page"; get_action = ACTION_PAGE; }

	/////////////////////////////////////////////

	// GET CLIENT
	struct camd35_client_data *cli = NULL;
	if (str_id) cli = getcs378xclientbyid( atoi(str_id) );
	if (!cli) return;
	//
	if (get_action==ACTION_DISABLE) {
		cli->flags |= FLAG_DISABLE;
		if (cli->connection.status>0) cs378x_disconnect_cli(cli);
		http_send_ok(sock);
		return;
	}
	else if (get_action==ACTION_ENABLE) {
		cli->flags &= ~FLAG_DISABLE;
		http_send_ok(sock);
		return;
	}
	else if (get_action==ACTION_STATUS) {
		if (cli->connection.status>0) http_send_text(sock,"connected"); else http_send_text(sock,"disconnected");
		return;
	}
	else if (get_action==ACTION_DEBUG) {
		flagdebug = getdbgflag( DBG_CS378X, 0, cli->id);
		http_send_ok(sock);
		return;
	}
	else if (get_action==ACTION_UPDATE) {
/*		char *str = isset_get( req, "expire"); // Client ID
		if (str) {
			if ( (str[4]=='-')&&(str[7]=='-') ) strptime(  str, "%Y-%m-%d %H", &cli->enddate);
			else if ( (str[2]=='-')&&(str[5]=='-') ) strptime(  str, "%d-%m-%Y %H", &cli->enddate);
		}
		str = isset_get( req, "active"); // Client ID
		if (str) {
			if (str[0]=='0') {
				cli->flags |= FLAG_DISABLE;
				if (cli->connection.status>0) cs378x_disconnect_cli(cli);
			}
			else cli->flags &= ~FLAG_DISABLE;
		}*/
		http_send_text(sock, "OK");
		return;
	}

	//
	tcp_init(&tcpbuf);
	if (get_action==ACTION_PAGE) {
		tcp_write(&tcpbuf, sock, http_replyok, strlen(http_replyok) );
		tcp_write(&tcpbuf, sock, http_html, strlen(http_html) );
		tcp_write(&tcpbuf, sock, http_head, strlen(http_head) );
		sprintf( http_buf, html_title, cfg.http.title, "Cs378x Client"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		tcp_write(&tcpbuf, sock, http_link, strlen(http_link) );
		tcp_write(&tcpbuf, sock, http_style, strlen(http_style) );
		// JS
        tcp_write(&tcpbuf, sock, http_javascript, strlen(http_javascript) );
		tcp_writestr(&tcpbuf, sock, "\n<script type='text/javascript'>");
		// UPD DIV
		char url[256];
		sprintf( url, "/cs378xclient?id=%d&action=div", cli->id);
		sprintf( http_buf, HTTP_UPDATE_DIV, cfg.http.autorefresh*1000, url);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		//
		tcp_writestr(&tcpbuf, sock, "\nfunction start()\n{\n	setautorefresh(autorefresh);\n}");
		tcp_writestr(&tcpbuf, sock, "\n</script>\n");
		tcp_write(&tcpbuf, sock, http_head_, strlen(http_head_) );
		tcp_writestr(&tcpbuf, sock, "<body onload=\"start();\">");
		tcp_write_menu(&tcpbuf, sock,0);
		// DIV
		tcp_writestr(&tcpbuf, sock, "<div id='mainDiv'>");
	}

	tcp_writestr(&tcpbuf, sock, "<table style=\"padding:0px; margin:0px;\" width=\"100%%\"><tbody>\n" );
	tcp_writestr(&tcpbuf, sock, "<tr><td style=\"vertical-align:top; width:400px;\">\n" );

	tcp_writestr(&tcpbuf, sock, "<table class=infotable><tbody>\n<tr><th colspan=2>Client Informations</th></tr>\n" );
	// NAME
	sprintf( http_buf,"<tr><td class=left>User name</td><td class=right>%s</td></tr>\n",cli->user);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	// Connection Time
	if (cli->connection.status>0) {
		tcp_writestr(&tcpbuf, sock, "<tr><td class=left>Status</td><td class=right>Connected</td></tr>\n");
		uint32_t d = (GetTickCount()-cli->connection.time)/1000;
		sprintf( http_buf,"<tr><td class=left>Connection time</td><td class=right>%02dd %02d:%02d:%02d</td></tr>\n", d/(3600*24), (d/3600)%24, (d/60)%60, d%60);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		// IP
		sprintf( http_buf,"<tr><td class=left>IP Address</td><td class=right>%s</td></tr>\n",(char*)ip2string(cli->ip) );
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		/*// Program ID
		sprintf( http_buf,"<tr><td class=left>Client Program</td><td class=right>%s(%04x)</td></tr>",programid(cli->progid), cli->progid );
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );*/
	}
	else {
		tcp_writestr(&tcpbuf, sock, "<tr><td class=left>Status</td><td class=right>Disconnected</td></tr>\n");
		if ( cli->connection.lastseen ) {
			uint32_t d = (GetTickCount()-cli->connection.lastseen)/1000;
			sprintf( http_buf,"<tr><td class=left>Last Seen</td><td class=right>%02dd %02d:%02d:%02d</td></tr>\n", d/(3600*24),(d/3600)%24,(d/60)%60,d%60);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		}
	}
	// UPTIME
	if ( cli->connection.uptime || (cli->connection.status>0) ) {
		uint32_t uptime;
		if (cli->connection.status>0) uptime = (GetTickCount()-cli->connection.time)+cli->connection.uptime; else uptime = cli->connection.uptime;
		uptime /= 1000;
		sprintf( http_buf,"<tr><td class=left>Uptime</td><td class=right>%02dd %02d:%02d:%02d</td></tr>",uptime/(3600*24),(uptime/3600)%24,(uptime/60)%60,uptime%60);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}
#ifdef CHECK_NEXTDCW
	sprintf( http_buf,"<tr><td class=left>DCW CHECK</td><td class=right>%s</td></tr>", yesno(cli->dcwcheck) );
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
#endif
	tcp_writestr(&tcpbuf, sock, "</tbody></table><br>\n" );


	// INFO
	struct client_info_data *info = cli->info;
	if (info) {
		tcp_writestr(&tcpbuf, sock, "<table class=\"infotable\"><tbody>\n" );
		tcp_writestr(&tcpbuf, sock, "<tr><th colspan=2>Additional Informations</th></tr>\n" );
		while (info) {
			sprintf( http_buf,"<tr><td class=left>%s</td><td class=right>%s</td></tr>\n",info->name,info->value);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			info = info->next;
		}
		tcp_writestr(&tcpbuf, sock, "</tbody></table><br>\n" );
	}

	// Ecm Stat
	tcp_writestr(&tcpbuf, sock, "<table class=\"infotable\"><tbody>\n" );
	tcp_writestr(&tcpbuf, sock, "<tr><th colspan=2>ECM Statistics</th></tr>\n" );
	int ecmaccepted = cli->ecmnb-cli->ecmdenied;
	sprintf( http_buf, "<tr><td class=left>Total ECM requests</td><td class=right>%d</td></tr>\n", cli->ecmnb);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf, "<tr><td class=left>Accepted ECM requests</td><td class=right>%d</td></tr>\n", ecmaccepted);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf, "<tr><td class=left>Good ECM answer</td><td class=right>%d</td></tr>\n", cli->ecmok);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	//Ecm Time
	if (cli->ecmok) {
		sprintf( http_buf,"<tr><td class=left>Average Time</td><td class=right>%d ms</td></tr>\n",(cli->ecmoktime/cli->ecmok) );
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}
//#ifdef SRV_CSCACHE
//	sprintf( http_buf, "<tr><td class=left>Cached CW</td><td class=right>%d</td></tr>\n", cli->cachedcw);
//	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
//#endif
	// Freeze
	sprintf( http_buf,"<tr><td class=left>Total Freeze</td><td class=right>%d</td></tr>\n", cli->freeze);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	tcp_writestr(&tcpbuf, sock, "</tbody></table><br>\n" );


	tcp_writestr(&tcpbuf, sock, "</td><td style=\"vertical-align:top;\">\n" );

	//Last Used Share
	if ( cli->lastecm.caid ) {
		tcp_writestr(&tcpbuf, sock, "<table class=\"infotable\"><tbody>\n" );
		tcp_writestr(&tcpbuf, sock, "<tr><th>Last Used share</th></tr>\n");
		// Decode Status
		if (cli->lastecm.status)
			sprintf( http_buf,"<tr><td>Decode success</td></tr>\n");
		else
			sprintf( http_buf,"<tr><td>Decode failed</td></tr>\n");
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		// Channel
		sprintf( http_buf,"<tr><td>Channel %s (%dms) %s</td></tr>\n", getchname(cli->lastecm.caid, cli->lastecm.prov, cli->lastecm.sid) , cli->lastecm.decodetime, str_laststatus[cli->lastecm.status] );
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

		// Server
		if ( (GetTickCount()-cli->ecm.recvtime) < 20000 ) {
			// From ???
			if (cli->lastecm.status) {
				tcp_writestr(&tcpbuf, sock, "<tr><td>From ");
				src2string(cli->lastecm.dcwsrctype, cli->lastecm.dcwsrcid, http_buf );
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				tcp_writestr(&tcpbuf, sock, "</td></tr>");
			}
			// Last ECM
			ECM_DATA *ecm = cli->lastecm.request;
			// ECM
			sprintf( http_buf,"<tr><td>ECM(%d): ", ecm->ecmlen); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			array2hex( ecm->ecm, http_buf, ecm->ecmlen );	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			sprintf( http_buf,"</td></tr>\n"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			// DCW
			if (cli->lastecm.status) {
				sprintf( http_buf,"<tr><td>CW: ");	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				array2hex( ecm->cw, http_buf, 16 );	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				sprintf( http_buf,"</td></tr>\n"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			}
#ifdef CHECK_NEXTDCW
			if ( ecm->lastdecode.ecm && (ecm->lastdecode.counter>0) ) {
				sprintf( http_buf,"<tr><td>Previous CW: "); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				array2hex( ecm->lastdecode.dcw, http_buf, 16 ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				tcp_writestr(&tcpbuf, sock, "</td></tr>\n");
				if (ecm->lastdecode.error) {
					sprintf( http_buf,"<tr><td>Errors = %d</td></tr>\n", ecm->lastdecode.error);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				}
				sprintf( http_buf,"<tr><td>Total Cycles = %d</td></tr>\n<tr><td>ECM Interval = %ds</td></tr>\n", ecm->lastdecode.counter, ecm->lastdecode.dcwchangetime/1000);
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			}
#endif
			//
			if (ecm->server[0].srvid) {
				sprintf( http_buf, "<tr><td><table class='infotable'><tbody><tr><th width='30px'>ID</th><th width='250px'>Server</th><th width='50px'>Status</th><th width='70px'>Start time</th><th width='70px'>End time</th><th width='90px'>Elapsed time</th><th>CW</th></tr></tbody>");
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				int i;
				for(i=0; i<20; i++) {
					if (!ecm->server[i].srvid) break;
					char* str_srvstatus[] = { "WAIT", "OK", "NOK", "BUSY" };
					struct server_data *srv = getsrvbyid(ecm->server[i].srvid);
					if (srv) {
						sprintf( http_buf,"<tr><td>%d</td><td>%s:%d</td><td>%s</td><td>%dms</td>", i+1, srv->host->name, srv->port, str_srvstatus[ecm->server[i].flag], ecm->server[i].sendtime - ecm->recvtime );
						tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
						// Recv Time
						if (ecm->server[i].statustime>ecm->server[i].sendtime)
							sprintf( http_buf,"<td>%dms</td><td>%dms</td>", ecm->server[i].statustime - ecm->recvtime, ecm->server[i].statustime-ecm->server[i].sendtime );
						else
							sprintf( http_buf,"<td>--</td><td>--</td>");
						tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
						// DCW
						if (ecm->server[i].flag==ECM_SRV_REPLY_GOOD) {
							sprintf( http_buf,"<td>"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
							array2hex( ecm->server[i].dcw, http_buf, 16 );	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
							sprintf( http_buf,"</td>"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
						}
						else {
							sprintf( http_buf,"<td>--</td>");
							tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
						}
						sprintf( http_buf,"</tr>");
						tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					}
				}
				tcp_writestr(&tcpbuf, sock, "</tbody></table></td></tr>\n" );
			}
		}
		tcp_writestr(&tcpbuf, sock, "</tbody></table><br>\n" );
	}

	// Current Busy Ecm
	if (cli->ecm.busy) {
		ECM_DATA *ecm = cli->ecm.request;
		if (ecm) http_send_ecmstatus(&tcpbuf, sock, ecm);
	}

	tcp_writestr(&tcpbuf, sock, "</td></tr></tbody></table>" );

	if (get_action==ACTION_PAGE) {
		tcp_writestr(&tcpbuf, sock, "</div>");
		tcp_writestr(&tcpbuf, sock, "</body></html>");
	}
	tcp_flush(&tcpbuf, sock);
}


#endif

















#ifdef CAMD35_SRV

void getcamd35cells(struct camd35_client_data *cli, char cell[10][2048])
{
	char temp[2048];
	uint d;

	// CELL0 # NAME
	sprintf( cell[0],"<a href='/camd35client?id=%d'>%s</a>",cli->id,cli->user);

	// CELL1 # IP
	if ( cli->ip ) { // Get Last IP
		char *p = getcountrycodebyip(cli->ip);
		if (p) sprintf( cell[1],"<img src='/flag_%s.gif' title='%s'> %s", p, getcountryname(p), (char*)ip2string(cli->ip) ); else sprintf( cell[1],"%s",(char*)ip2string(cli->ip) );
	}
	else strcpy( cell[1], " ");

	// CELL2 # Connection Time
	// Camd35 is UDP so there's no connection. Use cli->lastecmtime to check last received ecm time is less than 90 seconds
	if ((GetTickCount()-cli->lastecmtime) < 90000) {
		if (cli->ecm.busy) sprintf( cell[9],"busy"); else sprintf( cell[9],"online");
		sprintf( cell[2], "online");
	}
	else {
		sprintf( cell[9],"offline");
		if (cli->flags&FLAG_DELETE) sprintf( cell[2],"Removed");
		else if (cli->flags&FLAG_EXPIRED) sprintf( cell[2],"Expired");
		else if (cli->flags&FLAG_DISABLE) sprintf( cell[2],"Disabled");
		else sprintf( cell[2],"offline");
	}
	// CELL3+4+5 # ECM STAT: TOTAL/ACCEPTED/OK
	// ECM STAT
	sprintf( cell[3], "%d", cli->ecmnb );

	int ecmaccepted = cli->ecmnb-cli->ecmdenied;
	getstatcell( ecmaccepted, cli->ecmnb, cell[4]);
	getstatcell( cli->ecmok, ecmaccepted, cell[5]);

	// CELL6 # Ecm Time
	if (cli->ecmok) sprintf( cell[6],"%d ms",(cli->ecmoktime/cli->ecmok) ); else sprintf( cell[6],"-- ms");

	// CELL7 # Last Used Share
	if ( cli->lastecm.caid ) {
		if (cli->lastecm.status)  strcpy( cell[7],"<span class=success"); else strcpy( cell[7],"<span class=failed");
		sprintf( temp," title='%04x:%06x:%04x'>ch %s (%dms) %s ",cli->lastecm.caid, cli->lastecm.prov, cli->lastecm.sid, getchname(cli->lastecm.caid, cli->lastecm.prov, cli->lastecm.sid) , cli->lastecm.decodetime, str_laststatus[cli->lastecm.status] );
		strcat( cell[7], temp );
		if ( (GetTickCount()-cli->ecm.recvtime) < 20000 ) {
			// From ???
			if (cli->lastecm.status) {
				strcat( cell[7], " / from ");
				src2string(cli->lastecm.dcwsrctype, cli->lastecm.dcwsrcid, temp);
				strcat( cell[7], temp);
			}
		}
		strcat( cell[7], "</span>" );
	}
	else strcpy( cell[7], " ");

	strcat( cell[7], "<span style='float:right;'>");
	if ( !(cli->flags&(FLAG_DELETE|FLAG_EXPIRED)) ) {
		if (cli->flags&FLAG_DISABLE) {
			sprintf( temp," <img title='Enable' src='enable.png' OnClick=\"imgrequest('/camd35client?id=%d&action=enable',this);\">",cli->id);
			strcat( cell[7], temp );
		}
		else {
			sprintf( temp," <img title='disable' src='disable.png' OnClick=\"imgrequest('/camd35client?id=%d&action=disable',this);\">",cli->id);
			strcat( cell[7], temp );
		}
	}
	sprintf( temp," <img title='Debug' src='debug.png' OnClick=\"imgrequest('/camd35client?id=%d&action=debug',this);\">",cli->id);
	strcat( cell[7], temp );
	strcat( cell[7], "</span>");
}

void total_camd35_clients( int *total, int *connected, int *active )
{
	*total = 0;
	*connected = 0;
	*active = 0;
	struct camd35_server_data *camd35 = cfg.camd35.server;
	while (camd35) {
		struct camd35_client_data *cli = camd35->client;
		while (cli) {
			(*total)++;
			if ((GetTickCount()-cli->lastecmtime) < 90000) {   // No connection status in camd35 use lastecmtime < 90 seconds
				(*connected)++;
				if ( (GetTickCount()-cli->lastecmtime) < 20000 ) (*active)++;
			}
			cli=cli->next;
		}
		camd35 = camd35->next;
	}
}

void camd35_clients( struct camd35_server_data *camd35, int *total, int *connected, int *active )
{
	*total = 0;
	*connected = 0;
	*active = 0;
	struct camd35_client_data *cli = camd35->client;
	while (cli) {
		(*total)++;
		if ((GetTickCount()-cli->lastecmtime) < 90000) {
			(*connected)++;
			if ( (GetTickCount()-cli->lastecmtime) < 20000 ) (*active)++;
		}
		cli=cli->next;
	}
}

void http_send_camd35(int sock, http_request *req)
{
	char http_buf[4096];
	struct tcp_buffer_data tcpbuf;
	char cell[10][2048];

	// Get Params
	char *str_action = isset_get( req, "action");
	char *str_list = isset_get( req, "list");
	char *str_id = isset_get( req, "id"); // server ID
	char *str_clid = isset_get( req, "clid"); // Client ID
	// Param 'action'
	int get_action;
	if (str_action) {
		if (!strcmp(str_action,"div")) get_action = ACTION_DIV;
		else if (!strcmp(str_action,"row")) get_action = ACTION_ROW;
#ifndef PUBLIC
		else if (!strcmp(str_action,"xml")) get_action = ACTION_XML; // Get Clients info in xml
#endif
		else if (!strcmp(str_action,"disable")) get_action = ACTION_DISABLE;
		else if (!strcmp(str_action,"enable")) get_action = ACTION_ENABLE;
		else if (!strcmp(str_action,"status")) get_action = ACTION_STATUS;
		else if (!strcmp(str_action,"debug")) get_action = ACTION_DEBUG;
		else str_action = NULL;
	}
	if (!str_action) { str_action = "page"; get_action = ACTION_PAGE; }
	/////////////////////////////////////////////

	if (get_action==ACTION_ROW) {
		// Check for XML ROW
		struct camd35_client_data *cli = NULL;
		if (str_clid) {
			int id = atoi(str_clid);
			struct camd35_server_data *camd35 = cfg.camd35.server;
			while (camd35) {
				if (!(camd35->flags&FLAG_DELETE)) {
					struct camd35_client_data *cli = camd35->client;
					while (cli) {
						if ( !(cli->flags&FLAG_DELETE) && (cli->id==id) ) {
							// Send XML CELLS
							getcamd35cells(cli,cell);
							int i; for(i=0; i<10; i++) xmlescape( cell[i] );
							sprintf( http_buf, "<camd35>\n<c0>%s</c0>\n<c1>%s</c1>\n<c2_c>%s</c2_c>\n<c2>%s</c2>\n<c3>%s</c3>\n<c4>%s</c4>\n<c5>%s</c5>\n<c6>%s</c6>\n<c7>%s</c7>\n</camd35>\n",cell[0],cell[1],cell[9],cell[2],cell[3],cell[4],cell[5],cell[6],cell[7] );
							http_send_xml( sock, req, http_buf, strlen(http_buf));
						}
						cli = cli->next;
					}
				}
				camd35 = camd35->next;
			}
		}
		return;
	}			

	// Param 'list'
	int get_list = LIST_ACTIVE;
	if (str_list) {
		if (!strcmp(str_list,"connected")) get_list = LIST_CONNECTED;
		else if (!strcmp(str_list,"all")) get_list = LIST_ALL;
		else str_list = NULL;
	}
	if (!str_list) str_list = "active";
	// Param 'id'
	int get_id = 0;
	struct camd35_server_data *camd35 = NULL;
	if (str_id)	{
		get_id = atoi(str_id);
		camd35 = cfg.camd35.server;
		while (camd35) {
			if (camd35->id == get_id) break;
			camd35 = camd35->next;
		}
		if (!camd35) get_id = 0;
	}
	//
	tcp_init(&tcpbuf);
	if (get_action==ACTION_PAGE) {
		tcp_write(&tcpbuf, sock, http_replyok, strlen(http_replyok) );
		tcp_write(&tcpbuf, sock, http_html, strlen(http_html) );
		tcp_write(&tcpbuf, sock, http_head, strlen(http_head) );
		sprintf( http_buf, html_title, cfg.http.title, "camd35"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		tcp_write(&tcpbuf, sock, http_link, strlen(http_link) );
		tcp_write(&tcpbuf, sock, http_style, strlen(http_style) );
		// JS
        tcp_write(&tcpbuf, sock, http_javascript, strlen(http_javascript) );
		tcp_writestr(&tcpbuf, sock, "\n<script type='text/javascript'>");
		// ACTIONS REQUEST
		tcp_writestr(&tcpbuf, sock, "\nfunction imgrequest( url, el )\n{\n	var httpRequest;\n	try { httpRequest = new XMLHttpRequest(); }\n	catch (trymicrosoft) { try { httpRequest = new ActiveXObject('Msxml2.XMLHTTP'); } catch (oldermicrosoft) { try { httpRequest = new ActiveXObject('Microsoft.XMLHTTP'); } catch(failed) { httpRequest = false; } } }\n	if (!httpRequest) { alert('Your browser does not support Ajax.'); return false; }\n	if ( typeof(el)!='undefined' ) {\n		el.onclick = null;\n		el.style.opacity = '0.7';\n		httpRequest.onreadystatechange = function()\n		{\n			if (httpRequest.readyState == 4) if (httpRequest.status == 200) el.style.opacity = '0.3';\n		}\n	}\n	httpRequest.open('GET', url, true);\n	httpRequest.send(null);\n}\n");
		// UPD ROW
		tcp_writestr(&tcpbuf, sock, "\nfunction xmlupdateRow( xmlDoc, id ) \n{\n    var row = document.getElementById(id);\n    	row.cells.item(0).innerHTML = xmlDoc.getElementsByTagName('c0')[0].childNodes[0].nodeValue;\n    row.cells.item(1).innerHTML = xmlDoc.getElementsByTagName('c1')[0].childNodes[0].nodeValue;\n    row.cells.item(2).className = xmlDoc.getElementsByTagName('c2_c')[0].childNodes[0].nodeValue;\n    row.cells.item(2).innerHTML = xmlDoc.getElementsByTagName('c2')[0].childNodes[0].nodeValue;\n    row.cells.item(3).innerHTML = xmlDoc.getElementsByTagName('c3')[0].childNodes[0].nodeValue;\n    row.cells.item(4).innerHTML = xmlDoc.getElementsByTagName('c4')[0].childNodes[0].nodeValue;\n    row.cells.item(5).innerHTML = xmlDoc.getElementsByTagName('c5')[0].childNodes[0].nodeValue;\n    row.cells.item(6).innerHTML = xmlDoc.getElementsByTagName('c6')[0].childNodes[0].nodeValue;\n    row.cells.item(7).innerHTML = xmlDoc.getElementsByTagName('c7')[0].childNodes[0].nodeValue;\n}");
		char url[256];
		sprintf( url, "'/camd35?action=row&clid='+idx");
		sprintf( http_buf, HTTP_UPDATE_ROW, url);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		// UPD DIV
		sprintf( url, "/camd35?action=div&id=%d&list=%s", get_id, str_list);
		sprintf( http_buf, HTTP_UPDATE_DIV, cfg.http.autorefresh*1000, url);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		//
		tcp_writestr(&tcpbuf, sock, "\nfunction start()\n{\n	setautorefresh(autorefresh);\n}");
		tcp_writestr(&tcpbuf, sock, "\n</script>\n");
		tcp_write(&tcpbuf, sock, http_head_, strlen(http_head_) );
		tcp_writestr(&tcpbuf, sock, "<body onload=\"start();\">");
		tcp_write_menu(&tcpbuf, sock,PAGE_CAMD35);
		// DIV
		tcp_writestr(&tcpbuf, sock, "<div id='mainDiv'>");
	}

	tcp_writestr(&tcpbuf, sock, "<table style=\"margin:0px; padding:0px; border-width:0px; border-spacing: 1px;\"><tr>");
	tcp_writestr(&tcpbuf, sock, "<td style=\"margin:0px; padding:0px;\"><a href='/camd35'><table border=1 width=200px>");
	// Total Servers
	sprintf( http_buf, "<tr><td>Total Camd35 Servers: %d</td></tr>", cfg.camd35.totalservers); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	int total, connected, active;
	total_camd35_clients( &total, &connected, &active );
	sprintf( http_buf, "<tr><td>Connected Clients: %d / %d</td></tr>", connected, total ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	tcp_writestr(&tcpbuf, sock, "</table></a></td>");
	// Servers
	if (cfg.camd35.server) {
		int counter = 0;
		struct camd35_server_data *camd35 = cfg.camd35.server;
		while ( camd35 && (counter<5) ) {
			sprintf( http_buf, "<td style=\"margin:0px; padding: 0px;\"><a href='/camd35?id=%d'><table border=1 width=150px>", camd35->id);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			if (camd35->handle>0) sprintf( http_buf, "<tr><td>camd35 %d [<span class=success>%d</span>]</td></tr>", camd35->id, camd35->port);
			else sprintf( http_buf, "<tr><td>camd35 %d [<span class=failed>%d</span>]</td></tr>", camd35->id, camd35->port);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			int total, connected, active;
			camd35_clients( camd35, &total, &connected, &active );
			sprintf( http_buf, "<tr><td>Connected: %d / %d</td></tr>", connected, total);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			tcp_writestr(&tcpbuf, sock, "</table></a></td>");
			counter++;
			camd35 = camd35->next;
		}
	}
	// End of table
	tcp_writestr(&tcpbuf, sock, "</tr></table><br>");

	tcp_writestr(&tcpbuf, sock, "<select style=\"width:200px;\" onchange=\"parent.location.href='/camd35?id='+this.value\">");
	sprintf( http_buf, "<option value=0>ALL (%d)</option>", cfg.camd35.totalservers); //total_camd35_servers());
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	struct camd35_server_data *tmp = cfg.camd35.server;
	while (tmp) {
		if (get_id==tmp->id) sprintf( http_buf, "<option value=%d selected>[%d] camd35 %d</option>",tmp->id,tmp->port, tmp->id );
		else sprintf( http_buf, "<option value=%d>[%d] camd35 %d</option>",tmp->id,tmp->port, tmp->id );
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		tmp = tmp->next;
	}
	tcp_writestr(&tcpbuf, sock, "</select> ");
	//
	if (camd35) camd35_clients( camd35, &total, &connected, &active ); else total_camd35_clients( &total, &connected, &active );
	char *class1 = "button"; char *class2 = "sbutton";
	char *class;
	if (get_list==LIST_ACTIVE) class = class2; else class = class1;
	sprintf( http_buf, "<input type=button class=%s onclick=\"parent.location='/camd35?id=%d&amp;list=active'\" value='Active Clients (%d)'>", class, get_id, active);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	if (get_list==LIST_CONNECTED) class = class2; else class = class1;
	sprintf( http_buf, " <input type=button class=%s onclick=\"parent.location='/camd35?id=%d&amp;list=connected'\" value='Connected Clients (%d)'>", class, get_id, connected);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	if (get_list==LIST_ALL) class = class2; else class = class1;
	sprintf( http_buf, " <input type=button class=%s onclick=\"parent.location='/camd35?id=%d&amp;list=all'\" value='All Clients (%d)'>", class, get_id, total);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	//
	if (camd35) { // One Server Selected
		// Table
		sprintf( http_buf, "\n<table class=maintable width=100%%><tr><th width=100px>Client</th><th width=120px>ip</th><th width=110px>Connected</th><th width=60px>TotalEcm</th><th width=90px>AcceptedEcm</th><th width=90px>EcmOK</th><th width=50px>EcmTime</th><th>Last used share</th></tr>");
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		struct camd35_client_data *cli = camd35->client;
		int alt=0;
		if (get_list==LIST_ACTIVE) {
			while (cli) {
				if ( ((GetTickCount()-cli->lastecmtime) < 20000) ) {
					if (alt==1) alt=2; else alt=1;
					getcamd35cells(cli,cell);
					sprintf( http_buf,"\n<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td class=\"%s\">%s</td><td align=center>%s</td><td>%s</td><td>%s</td><td align=center>%s</td><td>%s</td></tr>\n",cli->id,alt,cli->id,cell[0],cell[1],cell[9],cell[2],cell[3],cell[4],cell[5],cell[6],cell[7]);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				}
				cli = cli->next;
			}
		}
		else if (get_list==LIST_CONNECTED) {
			while (cli) {
				if (((GetTickCount()-cli->lastecmtime) < 90000)) {
					if (alt==1) alt=2; else alt=1;
					getcamd35cells(cli,cell);
					sprintf( http_buf,"\n<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td class=\"%s\">%s</td><td align=center>%s</td><td>%s</td><td>%s</td><td align=center>%s</td><td>%s</td></tr>\n",cli->id,alt,cli->id,cell[0],cell[1],cell[9],cell[2],cell[3],cell[4],cell[5],cell[6],cell[7]);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				}
				cli = cli->next;
			}
		}
		else { // ALL
			while (cli) {
				if (alt==1) alt=2; else alt=1;
				getcamd35cells(cli,cell);
				sprintf( http_buf,"\n<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td class=\"%s\">%s</td><td align=center>%s</td><td>%s</td><td>%s</td><td align=center>%s</td><td>%s</td></tr>\n",cli->id,alt,cli->id,cell[0],cell[1],cell[9],cell[2],cell[3],cell[4],cell[5],cell[6],cell[7]);
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				cli = cli->next;
			}
		}
		sprintf( http_buf, "\n</table>");
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}

	else {
		// Table
		tcp_writestr(&tcpbuf,sock, "\n<table class=maintable width=100%>");
		tcp_writestr(&tcpbuf,sock, "\n<tr><th width=100px>Client</th><th width=120px>ip</th><th width=110px>Connected</th><th width=60px>TotalEcm</th><th width=90px>AcceptedEcm</th><th width=90px>EcmOK</th><th width=50px>EcmTime</th><th>Last used share</th></tr>");
		int alt=0;
		camd35 = cfg.camd35.server;
		while (camd35) {
			int total, connected, active;
			camd35_clients( camd35, &total, &connected, &active );
			if ( (get_list==LIST_ACTIVE) && active ) {
				sprintf( http_buf,"\n<tr><td class=alt3 colspan=9> camd35 %d (%d)</td></tr>", camd35->id, active); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				struct camd35_client_data *cli = camd35->client;
				while (cli) {
					if ( ((GetTickCount()-cli->lastecmtime) < 20000) ) {
						if (alt==1) alt=2; else alt=1;
						getcamd35cells(cli,cell);
						sprintf( http_buf,"\n<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td class=\"%s\">%s</td><td align=center>%s</td><td>%s</td><td>%s</td><td align=center>%s</td><td>%s</td></tr>\n",cli->id,alt,cli->id,cell[0],cell[1],cell[9],cell[2],cell[3],cell[4],cell[5],cell[6],cell[7]);
						tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					}
					cli = cli->next;
				}
			}
			else if ( (get_list==LIST_ALL) && total ) {
				sprintf( http_buf,"\n<tr><td class=alt3 colspan=9> camd35 %d (%d)</td></tr>", camd35->id, total); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				struct camd35_client_data *cli = camd35->client;
				while (cli) {
					if (alt==1) alt=2; else alt=1;
					getcamd35cells(cli,cell);
					sprintf( http_buf,"\n<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td class=\"%s\">%s</td><td align=center>%s</td><td>%s</td><td>%s</td><td align=center>%s</td><td>%s</td></tr>\n",cli->id,alt,cli->id,cell[0],cell[1],cell[9],cell[2],cell[3],cell[4],cell[5],cell[6],cell[7]);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					cli = cli->next;
				}
			}
			else if ( (get_list==LIST_CONNECTED) && connected ) {
				sprintf( http_buf,"\n<tr><td class=alt3 colspan=9> camd35 %d (%d)</td></tr>", camd35->id, connected); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				struct camd35_client_data *cli = camd35->client;
				while (cli) {
					if (((GetTickCount()-cli->lastecmtime) < 90000)) {
						if (alt==1) alt=2; else alt=1;
						getcamd35cells(cli,cell);
						sprintf( http_buf,"\n<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td class=\"%s\">%s</td><td align=center>%s</td><td>%s</td><td>%s</td><td align=center>%s</td><td>%s</td></tr>\n",cli->id,alt,cli->id,cell[0],cell[1],cell[9],cell[2],cell[3],cell[4],cell[5],cell[6],cell[7]);
						tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					}
					cli = cli->next;
				}
			}
			camd35 = camd35->next;
		}
		sprintf( http_buf, "</table>");
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}
	if (get_action==ACTION_PAGE) {
		tcp_writestr(&tcpbuf, sock, "</div>");
		tcp_writestr(&tcpbuf, sock, "</body></html>");
	}

	tcp_flush(&tcpbuf, sock);
}

///////////////////////////////////////////////////////////////////////////////

void http_send_camd35_client(int sock, http_request *req)
{
	char http_buf[2048];
	struct tcp_buffer_data tcpbuf;

	// Get Params
	char *str_action = isset_get( req, "action");
	char *str_id = isset_get( req, "id"); // Client ID
	char *str_name = isset_get( req, "name"); // Client NAME
	char *str_srvid = isset_get( req, "srvid"); // CCcam Server ID

	// Action
	int get_action = ACTION_PAGE;
	if (str_action) {
		if (!strcmp(str_action,"div")) get_action = ACTION_DIV;
		else if (!strcmp(str_action,"row")) get_action = ACTION_ROW;
		else if (!strcmp(str_action,"disable")) get_action = ACTION_DISABLE;
		else if (!strcmp(str_action,"enable")) get_action = ACTION_ENABLE;
		else if (!strcmp(str_action,"status")) get_action = ACTION_STATUS;
		else if (!strcmp(str_action,"debug")) get_action = ACTION_DEBUG;
		else if (!strcmp(str_action,"update")) get_action = ACTION_UPDATE;
		else str_action = NULL;
	}
	if (!str_action) { str_action = "page"; get_action = ACTION_PAGE; }

	/////////////////////////////////////////////

	// GET CLIENT
	struct camd35_client_data *cli = NULL;
	if (str_id) cli = getcamd35clientbyid( atoi(str_id) );
	if (!cli) return;
	//
	if (get_action==ACTION_DISABLE) {
		cli->flags |= FLAG_DISABLE;
		if (cli->connection.status>0) camd35_disconnect_cli(cli);
		http_send_ok(sock);
		return;
	}
	else if (get_action==ACTION_ENABLE) {
		cli->flags &= ~FLAG_DISABLE;
		http_send_ok(sock);
		return;
	}
	else if (get_action==ACTION_STATUS) {
		if (cli->connection.status>0) http_send_text(sock,"connected"); else http_send_text(sock,"disconnected");
		return;
	}
	else if (get_action==ACTION_DEBUG) {
		flagdebug = getdbgflag( DBG_CAMD35, 0, cli->id);
		http_send_ok(sock);
		return;
	}
	else if (get_action==ACTION_UPDATE) {
/*		char *str = isset_get( req, "expire"); // Client ID
		if (str) {
			if ( (str[4]=='-')&&(str[7]=='-') ) strptime(  str, "%Y-%m-%d %H", &cli->enddate);
			else if ( (str[2]=='-')&&(str[5]=='-') ) strptime(  str, "%d-%m-%Y %H", &cli->enddate);
		}
		str = isset_get( req, "active"); // Client ID
		if (str) {
			if (str[0]=='0') {
				cli->flags |= FLAG_DISABLE;
				if (cli->connection.status>0) camd35_disconnect_cli(cli);
			}
			else cli->flags &= ~FLAG_DISABLE;
		}*/
		http_send_text(sock, "OK");
		return;
	}

	//
	tcp_init(&tcpbuf);
	if (get_action==ACTION_PAGE) {
		tcp_write(&tcpbuf, sock, http_replyok, strlen(http_replyok) );
		tcp_write(&tcpbuf, sock, http_html, strlen(http_html) );
		tcp_write(&tcpbuf, sock, http_head, strlen(http_head) );
		sprintf( http_buf, html_title, cfg.http.title, "Camd35 Client"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		tcp_write(&tcpbuf, sock, http_link, strlen(http_link) );
		tcp_write(&tcpbuf, sock, http_style, strlen(http_style) );
		// JS
        tcp_write(&tcpbuf, sock, http_javascript, strlen(http_javascript) );
		tcp_writestr(&tcpbuf, sock, "\n<script type='text/javascript'>");
		// UPD DIV
		char url[256];
		sprintf( url, "/camd35client?id=%d&action=div", cli->id);
		sprintf( http_buf, HTTP_UPDATE_DIV, cfg.http.autorefresh*1000, url);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		//
		tcp_writestr(&tcpbuf, sock, "\nfunction start()\n{\n	setautorefresh(autorefresh);\n}");
		tcp_writestr(&tcpbuf, sock, "\n</script>\n");
		tcp_write(&tcpbuf, sock, http_head_, strlen(http_head_) );
		tcp_writestr(&tcpbuf, sock, "<body onload=\"start();\">");
		tcp_write_menu(&tcpbuf, sock,0);
		// DIV
		tcp_writestr(&tcpbuf, sock, "<div id='mainDiv'>");
	}

	tcp_writestr(&tcpbuf, sock, "<table style=\"padding:0px; margin:0px;\" width=\"100%%\"><tbody>\n" );
	tcp_writestr(&tcpbuf, sock, "<tr><td style=\"vertical-align:top; width:400px;\">\n" );

	tcp_writestr(&tcpbuf, sock, "<table class=infotable><tbody>\n<tr><th colspan=2>Client Informations</th></tr>\n" );
	// NAME
	sprintf( http_buf,"<tr><td class=left>User name</td><td class=right>%s</td></tr>\n",cli->user);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
#ifdef CHECK_NEXTDCW
	sprintf( http_buf,"<tr><td class=left>DCW CHECK</td><td class=right>%s</td></tr>", yesno(cli->dcwcheck) );
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
#endif
	tcp_writestr(&tcpbuf, sock, "</tbody></table><br>\n" );


	// INFO
	struct client_info_data *info = cli->info;
	if (info) {
		tcp_writestr(&tcpbuf, sock, "<table class=\"infotable\"><tbody>\n" );
		tcp_writestr(&tcpbuf, sock, "<tr><th colspan=2>Additional Informations</th></tr>\n" );
		while (info) {
			sprintf( http_buf,"<tr><td class=left>%s</td><td class=right>%s</td></tr>\n",info->name,info->value);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			info = info->next;
		}
		tcp_writestr(&tcpbuf, sock, "</tbody></table><br>\n" );
	}

	// Ecm Stat
	tcp_writestr(&tcpbuf, sock, "<table class=\"infotable\"><tbody>\n" );
	tcp_writestr(&tcpbuf, sock, "<tr><th colspan=2>ECM Statistics</th></tr>\n" );
	int ecmaccepted = cli->ecmnb-cli->ecmdenied;
	sprintf( http_buf, "<tr><td class=left>Total ECM requests</td><td class=right>%d</td></tr>\n", cli->ecmnb);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf, "<tr><td class=left>Accepted ECM requests</td><td class=right>%d</td></tr>\n", ecmaccepted);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf, "<tr><td class=left>Good ECM answer</td><td class=right>%d</td></tr>\n", cli->ecmok);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	//Ecm Time
	if (cli->ecmok) {
		sprintf( http_buf,"<tr><td class=left>Average Time</td><td class=right>%d ms</td></tr>\n",(cli->ecmoktime/cli->ecmok) );
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}
//#ifdef SRV_CSCACHE
//	sprintf( http_buf, "<tr><td class=left>Cached CW</td><td class=right>%d</td></tr>\n", cli->cachedcw);
//	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
//#endif
	// Freeze
	sprintf( http_buf,"<tr><td class=left>Total Freeze</td><td class=right>%d</td></tr>\n", cli->freeze);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	tcp_writestr(&tcpbuf, sock, "</tbody></table><br>\n" );


	tcp_writestr(&tcpbuf, sock, "</td><td style=\"vertical-align:top;\">\n" );

	//Last Used Share
	if ( cli->lastecm.caid ) {
		tcp_writestr(&tcpbuf, sock, "<table class=\"infotable\"><tbody>\n" );
		tcp_writestr(&tcpbuf, sock, "<tr><th>Last Used share</th></tr>\n");
		// Decode Status
		if (cli->lastecm.status)
			sprintf( http_buf,"<tr><td>Decode success</td></tr>\n");
		else
			sprintf( http_buf,"<tr><td>Decode failed</td></tr>\n");
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		// Channel
		sprintf( http_buf,"<tr><td>Channel %s (%dms) %s</td></tr>\n", getchname(cli->lastecm.caid, cli->lastecm.prov, cli->lastecm.sid) , cli->lastecm.decodetime, str_laststatus[cli->lastecm.status] );
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

		// Server
		if ( (GetTickCount()-cli->ecm.recvtime) < 20000 ) {
			// From ???
			if (cli->lastecm.status) {
				tcp_writestr(&tcpbuf, sock, "<tr><td>From ");
				src2string(cli->lastecm.dcwsrctype, cli->lastecm.dcwsrcid, http_buf );
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				tcp_writestr(&tcpbuf, sock, "</td></tr>");
			}
			// Last ECM
			ECM_DATA *ecm = cli->lastecm.request;
			// ECM
			sprintf( http_buf,"<tr><td>ECM(%d): ", ecm->ecmlen); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			array2hex( ecm->ecm, http_buf, ecm->ecmlen );	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			sprintf( http_buf,"</td></tr>\n"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			// DCW
			if (cli->lastecm.status) {
				sprintf( http_buf,"<tr><td>CW: ");	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				array2hex( ecm->cw, http_buf, 16 );	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				sprintf( http_buf,"</td></tr>\n"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			}
#ifdef CHECK_NEXTDCW
			if ( ecm->lastdecode.ecm && (ecm->lastdecode.counter>0) ) {
				sprintf( http_buf,"<tr><td>Previous CW: "); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				array2hex( ecm->lastdecode.dcw, http_buf, 16 ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				tcp_writestr(&tcpbuf, sock, "</td></tr>\n");
				if (ecm->lastdecode.error) {
					sprintf( http_buf,"<tr><td>Errors = %d</td></tr>\n", ecm->lastdecode.error);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				}
				sprintf( http_buf,"<tr><td>Total Cycles = %d</td></tr>\n<tr><td>ECM Interval = %ds</td></tr>\n", ecm->lastdecode.counter, ecm->lastdecode.dcwchangetime/1000);
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			}
#endif
			//
			if (ecm->server[0].srvid) {
				sprintf( http_buf, "<tr><td><table class='infotable'><tbody><tr><th width='30px'>ID</th><th width='250px'>Server</th><th width='50px'>Status</th><th width='70px'>Start time</th><th width='70px'>End time</th><th width='90px'>Elapsed time</th><th>CW</th></tr></tbody>");
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				int i;
				for(i=0; i<20; i++) {
					if (!ecm->server[i].srvid) break;
					char* str_srvstatus[] = { "WAIT", "OK", "NOK", "BUSY" };
					struct server_data *srv = getsrvbyid(ecm->server[i].srvid);
					if (srv) {
						sprintf( http_buf,"<tr><td>%d</td><td>%s:%d</td><td>%s</td><td>%dms</td>", i+1, srv->host->name, srv->port, str_srvstatus[ecm->server[i].flag], ecm->server[i].sendtime - ecm->recvtime );
						tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
						// Recv Time
						if (ecm->server[i].statustime>ecm->server[i].sendtime)
							sprintf( http_buf,"<td>%dms</td><td>%dms</td>", ecm->server[i].statustime - ecm->recvtime, ecm->server[i].statustime-ecm->server[i].sendtime );
						else
							sprintf( http_buf,"<td>--</td><td>--</td>");
						tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
						// DCW
						if (ecm->server[i].flag==ECM_SRV_REPLY_GOOD) {
							sprintf( http_buf,"<td>"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
							array2hex( ecm->server[i].dcw, http_buf, 16 );	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
							sprintf( http_buf,"</td>"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
						}
						else {
							sprintf( http_buf,"<td>--</td>");
							tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
						}
						sprintf( http_buf,"</tr>");
						tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					}
				}
				tcp_writestr(&tcpbuf, sock, "</tbody></table></td></tr>\n" );
			}
		}
		tcp_writestr(&tcpbuf, sock, "</tbody></table><br>\n" );
	}

	// Current Busy Ecm
	if (cli->ecm.busy) {
		ECM_DATA *ecm = cli->ecm.request;
		if (ecm) http_send_ecmstatus(&tcpbuf, sock, ecm);
	}

	tcp_writestr(&tcpbuf, sock, "</td></tr></tbody></table>" );

	if (get_action==ACTION_PAGE) {
		tcp_writestr(&tcpbuf, sock, "</div>");
		tcp_writestr(&tcpbuf, sock, "</body></html>");
	}
	tcp_flush(&tcpbuf, sock);
}

#endif


















#ifdef CACHEEX

void cacheex_server_cells(struct server_data *srv, char cell[10][2048] )
{
	char temp[2048];
	unsigned int ticks = GetTickCount();
	uint32_t d;

	memset(cell, 0, 10*2048);
	if (
		(srv->type!=TYPE_CCCAM)
#ifdef CAMD35_CLI
		&&(srv->type!=TYPE_CAMD35)
#endif
#ifdef CS378X_CLI
		&&(srv->type!=TYPE_CS378X) 
#endif
	) return;
	if (!srv->cacheex_mode) return;
	// CELL0
	sprintf( cell[0],"%s:%d",srv->host->name,srv->port);
	// CELL1*IP
	if (!srv->host->ip && srv->host->clip)
		sprintf( temp,"0.0.0.0 (%s)",(char*)ip2string(srv->host->ip) );
	else {
		char *p = getcountrycodebyip(srv->host->ip);
		if (p) sprintf( temp,"<img src='/flag_%s.gif' title='%s'> %s", p, getcountryname(p), (char*)ip2string(srv->host->ip) );
		else sprintf( temp,"%s",(char*)ip2string(srv->host->ip) );
	}
	strcat( cell[1], temp );
	// CELL2
	if (srv->connection.status>0) {
		if (srv->type==TYPE_CCCAM) sprintf( cell[2],"mode%d (CCcam)", srv->cacheex_mode);
#ifdef CAMD35_CLI
		else if (srv->type==TYPE_CAMD35) sprintf( cell[2],"mode%d (camd35)", srv->cacheex_mode);
#endif
#ifdef CS378X_CLI
		else if (srv->type==TYPE_CS378X) sprintf( cell[2],"mode%d (cs378x)", srv->cacheex_mode);
#endif
		else sprintf( cell[2],"Unknown"); 
	}
	else sprintf( cell[2]," ");
	// CELL3
	if (srv->connection.status>0)
		sprintf( cell[3],"%02x%02x%02x%02x%02x%02x%02x%02x", srv->nodeid[0],srv->nodeid[1],srv->nodeid[2],srv->nodeid[3],srv->nodeid[4],srv->nodeid[5],srv->nodeid[6],srv->nodeid[7]);
	else sprintf( cell[3]," ");
	// CELL4
	if (srv->connection.status>0) {
		d = (ticks-srv->connection.time)/1000;
		sprintf( cell[4],"%02dd %02d:%02d:%02d", d/(3600*24),(d/3600)%24,(d/60)%60,d%60);
		sprintf( cell[9],"online");
	}
	else {
		sprintf( cell[9],"offline");
		if (srv->flags&FLAG_DELETE) sprintf( cell[4],"Removed");
		else if (srv->flags&FLAG_EXPIRED) sprintf( cell[4],"Expired");
		else if (srv->flags&FLAG_DISABLE) sprintf( cell[4],"Disabled");
		else sprintf( cell[4],"offline");
	}
	if ( (srv->cacheex_mode==2) && srv->csporthit[0].csid ) {
		strcat( cell[4], "<table class=\"connect_data\">" );
		strcat( cell[4], "<tr><td width=150px>Profile</td><td>Hits</td></tr>" );
		int i; char temp[512];
		for(i=0; i<10; i++) {
			if (!srv->csporthit[i].csid) break;
			struct cardserver_data *cs = getcsbyid(srv->csporthit[i].csid);
			if (!cs) continue;
			sprintf( temp,"<tr><td>%s</td><td>%d</td></tr>", cs->name,srv->csporthit[i].hits);
			strcat( cell[4], temp );
		}
		strcat( cell[4], "</table>");
	}

	// CELL5
	sprintf( cell[5], "%d",srv->cacheex.push[0]); // PUSH
	int i;
	for (i=1; i<10; i++ ) {
		if (srv->cacheex.push[i]>0) {
			sprintf( temp,"<br>[%d] %d", i, srv->cacheex.push[i]);
			strcat( cell[5], temp );
		}
	}

	// CELL6
	sprintf( cell[6], "%d",srv->cacheex.got[0]); // GOT
	for (i=1; i<10; i++ ) {
		if (srv->cacheex.got[i]>0) {
			sprintf( temp,"<br>[%d] %d", i, srv->cacheex.got[i]);
			strcat( cell[6], temp );
		}
	}

	// CELL7
	sprintf( cell[7], "%d",srv->cacheex.hits); // HIT
	if ( (srv->cacheex_mode==2) && srv->cacheex.badcw ) {
		sprintf( temp,"<br>bad=%d", srv->cacheex.badcw);
		strcat( cell[7], temp );
	}

	// CELL8
	if (srv->cacheex_mode==3) {
		if (srv->sharelimits[0].caid==0xffff) strcpy( cell[8], " ");
		else {
			sprintf( cell[8]," Shares = %04x:%x", srv->sharelimits[0].caid, srv->sharelimits[0].provid);
			int i;
			for (i=1; i<100; i++) {
				if (srv->sharelimits[i].caid==0xffff) break;
				sprintf( temp,", %04x:%x", srv->sharelimits[i].caid, srv->sharelimits[i].provid);
				strcat( cell[8], temp );
			}
		}
	}
	else if (srv->cacheex_mode==2) {
		if (srv->cacheex.lastcaid) {
			sprintf( cell[8],"ch %s (%dms)", getchname(srv->cacheex.lastcaid, srv->cacheex.lastprov, srv->cacheex.lastsid) , srv->cacheex.lastdecodetime );
		}
		else strcpy( cell[8], " ");
	}
}

void cacheex_cccamclient_cells(struct cc_client_data *cli, char cell[10][2048])
{
	char temp[2048];
	unsigned int ticks = GetTickCount();
	unsigned int d;
	memset(cell, 0, 10*2048);
	if (!cli->cacheex_mode) return;
	// CELL0 # NAME
	sprintf( cell[0],"%s",cli->user);
	// CELL1 # IP
	char *p = getcountrycodebyip(cli->ip);
	if (cli->host)
		if (p) sprintf( cell[1],"<img src='/flag_%s.gif' title='%s'> %s<br>%s", p, getcountryname(p), (char*)ip2string(cli->ip), cli->host->name ); else sprintf( cell[1],"%s<br>%s",(char*)ip2string(cli->ip), cli->host->name );
	else
		if (p) sprintf( cell[1],"<img src='/flag_%s.gif' title='%s'> %s", p, getcountryname(p), (char*)ip2string(cli->ip) ); else sprintf( cell[1],"%s",(char*)ip2string(cli->ip) );

	// CELL2 # VERSION
	sprintf( cell[2],"mode%d", cli->cacheex_mode);
	// CELL3 # nodeid
	if (strlen(cli->version)) sprintf( cell[3],"%02x%02x%02x%02x%02x%02x%02x%02x", cli->nodeid[0],cli->nodeid[1],cli->nodeid[2],cli->nodeid[3],cli->nodeid[4],cli->nodeid[5],cli->nodeid[6],cli->nodeid[7]);
	// CELL4 # Connection Time
	if (cli->connection.status>0) {
		sprintf( cell[9],"online");
		d = (ticks-cli->connection.time)/1000;
		sprintf( cell[4], "%02dd %02d:%02d:%02d", d/(3600*24), (d/3600)%24, (d/60)%60, d%60);
	}
	else {
		strcpy( cell[9], "offline" );
		if (cli->flags&FLAG_DELETE) sprintf( cell[4],"Removed");
		else if (cli->flags&FLAG_EXPIRED) sprintf( cell[4],"Expired");
		else if (cli->flags&FLAG_DISABLE) sprintf( cell[4],"Disabled");
		else sprintf( cell[4],"offline");
	}
	if (cli->csporthit[0].csid) {
		strcat( cell[4], "<table class=\"connect_data\">" );
		strcat( cell[4], "<tr><td width=150px>Profile</td><td>Hits</td></tr>" );
		int i; char temp[512];
		for(i=0; i<10; i++) {
			if (!cli->csporthit[i].csid) break;
			struct cardserver_data *cs = getcsbyid(cli->csporthit[i].csid);
			if (!cs) continue;
			sprintf( temp,"<tr><td>%s</td><td>%d</td></tr>", cs->name,cli->csporthit[i].hits);
			strcat( cell[4], temp );
		}
		strcat( cell[4], "</table>");
	}
	// CELL5
	sprintf( cell[5], "%d", cli->cacheex.push[0]);
	int i;
	for (i=1; i<10; i++ ) {
		if (cli->cacheex.push[i]>0) {
			sprintf( temp,"<br>[%d] %d", i, cli->cacheex.push[i]);
			strcat( cell[5], temp );
		}
	}

	// CELL6
	sprintf( cell[6], "%d", cli->cacheex.got[0]);
	for (i=1; i<10; i++ ) {
		if (cli->cacheex.got[i]>0) {
			sprintf( temp,"<br>[%d] %d", i, cli->cacheex.got[i]);
			strcat( cell[6], temp );
		}
	}

	// CELL7
	sprintf( cell[7], "%d", cli->cacheex.hits);
	if ( (cli->cacheex_mode==3) && cli->cacheex.badcw ) {
		sprintf( temp,"<br>bad=%d", cli->cacheex.badcw);
		strcat( cell[7], temp );
	}

	// CELL8
	if (cli->cacheex_mode==2) {
		if (cli->sharelimits[0].caid==0xffff) strcpy( cell[8], " ");
		else {
			sprintf( cell[8]," Shares = %04x:%x", cli->sharelimits[0].caid, cli->sharelimits[0].provid);
			int i;
			for (i=1; i<100; i++) {
				if (cli->sharelimits[i].caid==0xffff) break;
				sprintf( temp,", %04x:%x", cli->sharelimits[i].caid, cli->sharelimits[i].provid);
				strcat( cell[8], temp );
			}
		}
	}
	else if (cli->cacheex_mode==3) {
		if (cli->cacheex.lastcaid) {
			sprintf( cell[8],"ch %s (%dms)", getchname(cli->cacheex.lastcaid, cli->cacheex.lastprov, cli->cacheex.lastsid) , cli->cacheex.lastdecodetime );
		}
		else strcpy( cell[8], " ");
	}
}

#if defined(CAMD35_SRV) || defined(CS378X_SRV)

void cacheex_camd35client_cells(struct camd35_client_data *cli, char cell[10][2048])
{
	char temp[2048];
	unsigned int ticks = GetTickCount();
	unsigned int d;
	memset(cell, 0, 10*2048);
	if (!cli->cacheex_mode) return;
	// CELL0 # NAME
	sprintf( cell[0],"%s",cli->user);
	// CELL1 # IP
	char *p = getcountrycodebyip(cli->ip);
	if (p) sprintf( cell[1],"<img src='/flag_%s.gif' title='%s'> %s", p, getcountryname(p), (char*)ip2string(cli->ip) );
	else sprintf( cell[1],"%s",(char*)ip2string(cli->ip) );

	// CELL2 # VERSION
	sprintf( cell[2],"mode%d", cli->cacheex_mode);
	// CELL3 # nodeid
	sprintf( cell[3],"%02x%02x%02x%02x%02x%02x%02x%02x", cli->nodeid[0],cli->nodeid[1],cli->nodeid[2],cli->nodeid[3],cli->nodeid[4],cli->nodeid[5],cli->nodeid[6],cli->nodeid[7]);
	// CELL4 # Connection Time
	if (cli->connection.status>0) {
		sprintf( cell[9],"online");
		d = (ticks-cli->connection.time)/1000;
		sprintf( cell[4], "%02dd %02d:%02d:%02d", d/(3600*24), (d/3600)%24, (d/60)%60, d%60);
	}
	else {
		strcpy( cell[9], "offline" );
		if (cli->flags&FLAG_DELETE) sprintf( cell[4],"Removed");
		else if (cli->flags&FLAG_EXPIRED) sprintf( cell[4],"Expired");
		else if (cli->flags&FLAG_DISABLE) sprintf( cell[4],"Disabled");
		else sprintf( cell[4],"offline");
	}
	if (cli->csporthit[0].csid) {
		strcat( cell[4], "<table class=\"connect_data\">" );
		strcat( cell[4], "<tr><td width=150px>Profile</td><td>Hits</td></tr>" );
		int i; char temp[512];
		for(i=0; i<10; i++) {
			if (!cli->csporthit[i].csid) break;
			struct cardserver_data *cs = getcsbyid(cli->csporthit[i].csid);
			if (!cs) continue;
			sprintf( temp,"<tr><td>%s</td><td>%d</td></tr>", cs->name,cli->csporthit[i].hits);
			strcat( cell[4], temp );
		}
		strcat( cell[4], "</table>");
	}

	// CELL5
	sprintf( cell[5], "%d", cli->cacheex.push[0]); // sent
	int i;
	for (i=1; i<10; i++ ) {
		if (cli->cacheex.push[i]>0) {
			sprintf( temp,"<br>[%d] %d", i, cli->cacheex.push[i]);
			strcat( cell[5], temp );
		}
	}

	// CELL6
	sprintf( cell[6], "%d", cli->cacheex.got[0]); // received
	for (i=1; i<10; i++ ) {
		if (cli->cacheex.got[i]>0) {
			sprintf( temp,"<br>[%d] %d", i, cli->cacheex.got[i]);
			strcat( cell[6], temp );
		}
	}

	// CELL7
	sprintf( cell[7], "%d", cli->cacheex.hits);
	if ( (cli->cacheex_mode==3) && cli->cacheex.badcw ) {
		sprintf( temp,"<br>bad=%d", cli->cacheex.badcw);
		strcat( cell[7], temp );
	}

	// CELL8
	if (cli->cacheex_mode==2) {
		if (cli->sharelimits[0].caid==0xffff) strcpy( cell[8], " ");
		else {
			sprintf( cell[8]," Shares = %04x:%x", cli->sharelimits[0].caid, cli->sharelimits[0].provid);
			int i;
			for (i=1; i<100; i++) {
				if (cli->sharelimits[i].caid==0xffff) break;
				sprintf( temp,", %04x:%x", cli->sharelimits[i].caid, cli->sharelimits[i].provid);
				strcat( cell[8], temp );
			}
		}
	}
	else if (cli->cacheex_mode==3) {
		if (cli->cacheex.lastcaid) {
			sprintf( cell[8],"ch %s (%dms)", getchname(cli->cacheex.lastcaid, cli->cacheex.lastprov, cli->cacheex.lastsid) , cli->cacheex.lastdecodetime );
		}
		else strcpy( cell[8], " ");
	}
}

#endif

void http_send_cacheex(int sock, http_request *req)
{
	char http_buf[4096];
	struct tcp_buffer_data tcpbuf;
	char cell[10][2048];

	// Get Params
	char *str_action = isset_get( req, "action");
	// Param 'action'
	int get_action;
	if (str_action) {
		if (!strcmp(str_action,"div")) get_action = ACTION_DIV;
		else str_action = NULL;
	}
	if (!str_action) { str_action = "page"; get_action = ACTION_PAGE; }

	char *id = isset_get( req, "id");
	if (id) {
		int i = atoi(id);
		if ( (i>>16)==1 ) { // CCcam Clients
			struct cccam_server_data *cccam = cfg.cccam.server;
			while (cccam) {
				if (!(cccam->flags&FLAG_DELETE)) {
					struct cc_client_data *cli = cccam->cacheexclient;
					while (cli) {
						if ( !(cli->flags&FLAG_DELETE) && cli->id==(i&0xffff) ) {
			                cacheex_cccamclient_cells(cli,cell);
			                for(i=0; i<10; i++) xmlescape( cell[i] );
			                sprintf( http_buf, "<cacheex>\n<c0>%s</c0>\n<c1>%s</c1>\n<c2>%s</c2>\n<c3>%s</c3>\n<c4_c>%s</c4_c>\n<c4>%s</c4>\n<c5>%s</c5>\n<c6>%s</c6><c7>%s</c7><c8>%s</c8>\n</cacheex>\n",cell[0],cell[1],cell[2],cell[3],cell[9],cell[4],cell[5],cell[6],cell[7],cell[8] );
			                http_send_xml( sock, req, http_buf, strlen(http_buf));
							return;
						}
						cli = cli->next;
					}
				}
				cccam = cccam->next;
			}
		}
		else if ( (i>>16)==2 ) { // camd35 Clients
			struct camd35_server_data *camd35 = cfg.camd35.server;
			while (camd35) {
				if (!(camd35->flags&FLAG_DELETE)) {
					struct camd35_client_data *cli = camd35->cacheexclient;
					while (cli) {
						if ( !(cli->flags&FLAG_DELETE) && cli->id==(i&0xffff) ) {
			                cacheex_camd35client_cells(cli,cell);
			                for(i=0; i<10; i++) xmlescape( cell[i] );
			                sprintf( http_buf, "<cacheex>\n<c0>%s</c0>\n<c1>%s</c1>\n<c2>%s</c2>\n<c3>%s</c3>\n<c4_c>%s</c4_c>\n<c4>%s</c4>\n<c5>%s</c5>\n<c6>%s</c6><c7>%s</c7><c8>%s</c8>\n</cacheex>\n",cell[0],cell[1],cell[2],cell[3],cell[9],cell[4],cell[5],cell[6],cell[7],cell[8] );
			                http_send_xml( sock, req, http_buf, strlen(http_buf));
							return;
						}
						cli = cli->next;
					}
				}
				camd35 = camd35->next;
			}
		}
		else if ( (i>>16)==3 ) { // cs378x Clients
			struct camd35_server_data *cs378x = cfg.cs378x.server;
			while (cs378x) {
				if (!(cs378x->flags&FLAG_DELETE)) {
					struct camd35_client_data *cli = cs378x->cacheexclient;
					while (cli) {
						if ( !(cli->flags&FLAG_DELETE) && cli->id==(i&0xffff) ) {
			                cacheex_camd35client_cells(cli,cell);
			                for(i=0; i<10; i++) xmlescape( cell[i] );
			                sprintf( http_buf, "<cacheex>\n<c0>%s</c0>\n<c1>%s</c1>\n<c2>%s</c2>\n<c3>%s</c3>\n<c4_c>%s</c4_c>\n<c4>%s</c4>\n<c5>%s</c5>\n<c6>%s</c6><c7>%s</c7><c8>%s</c8>\n</cacheex>\n",cell[0],cell[1],cell[2],cell[3],cell[9],cell[4],cell[5],cell[6],cell[7],cell[8] );
			                http_send_xml( sock, req, http_buf, strlen(http_buf));
							return;
						}
						cli = cli->next;
					}
				}
				cs378x = cs378x->next;
			}
		}
		else if ( (i>>16)==4 ) { // Server
			struct server_data *srv = cfg.cacheexserver;
			while (srv) {
				if ( !(srv->flags&FLAG_DELETE) && srv->id==(i&0xffff) ) {
					cacheex_server_cells(srv,cell);
					for(i=0; i<10; i++) xmlescape( cell[i] );
					sprintf( http_buf, "<cacheex>\n<c0>%s</c0>\n<c1>%s</c1>\n<c2>%s</c2>\n<c3>%s</c3>\n<c4_c>%s</c4_c>\n<c4>%s</c4>\n<c5>%s</c5>\n<c6>%s</c6><c7>%s</c7><c8>%s</c8>\n</cacheex>\n",cell[0],cell[1],cell[2],cell[3],cell[9],cell[4],cell[5],cell[6],cell[7],cell[8] );
					http_send_xml( sock, req, http_buf, strlen(http_buf));
					return;
				}
				srv = srv->next;
			}
		}
		return;
	}

	/////////////////////////////////////////////
	struct cccam_server_data *cccam = NULL;
	tcp_init(&tcpbuf);
	tcp_write(&tcpbuf, sock, http_replyok, strlen(http_replyok) );
	if (get_action==ACTION_PAGE) {
		tcp_write(&tcpbuf, sock, http_html, strlen(http_html) );
		tcp_write(&tcpbuf, sock, http_head, strlen(http_head) );
		sprintf( http_buf, html_title, cfg.http.title, "CacheEX"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		tcp_write(&tcpbuf, sock, http_link, strlen(http_link) );
		tcp_write(&tcpbuf, sock, http_style, strlen(http_style) );
		// JS
        tcp_write(&tcpbuf, sock, http_javascript, strlen(http_javascript) );
		tcp_writestr(&tcpbuf, sock, "\n<script type='text/javascript'>");
		// ACTIONS REQUEST
		tcp_writestr(&tcpbuf, sock, "\nfunction imgrequest( url, el )\n{\n	var httpRequest;\n	try { httpRequest = new XMLHttpRequest(); }\n	catch (trymicrosoft) { try { httpRequest = new ActiveXObject('Msxml2.XMLHTTP'); } catch (oldermicrosoft) { try { httpRequest = new ActiveXObject('Microsoft.XMLHTTP'); } catch(failed) { httpRequest = false; } } }\n	if (!httpRequest) { alert('Your browser does not support Ajax.'); return false; }\n	if ( typeof(el)!='undefined' ) {\n		el.onclick = null;\n		el.style.opacity = '0.7';\n		httpRequest.onreadystatechange = function()\n		{\n			if (httpRequest.readyState == 4) if (httpRequest.status == 200) el.style.opacity = '0.3';\n		}\n	}\n	httpRequest.open('GET', url, true);\n	httpRequest.send(null);\n}\n");
		// UPD ROW
		tcp_writestr(&tcpbuf, sock, "\nfunction xmlupdateRow( xmlDoc, id )\n{\n	var row = document.getElementById(id);\n	row.cells.item(0).innerHTML = xmlDoc.getElementsByTagName('c0')[0].childNodes[0].nodeValue;\n	row.cells.item(1).innerHTML = xmlDoc.getElementsByTagName('c1')[0].childNodes[0].nodeValue;\n	row.cells.item(2).innerHTML = xmlDoc.getElementsByTagName('c2')[0].childNodes[0].nodeValue;\n	row.cells.item(3).innerHTML = xmlDoc.getElementsByTagName('c3')[0].childNodes[0].nodeValue;\n	row.cells.item(4).className = xmlDoc.getElementsByTagName('c4_c')[0].childNodes[0].nodeValue;\n	row.cells.item(4).innerHTML = xmlDoc.getElementsByTagName('c4')[0].childNodes[0].nodeValue;\n	row.cells.item(5).innerHTML = xmlDoc.getElementsByTagName('c5')[0].childNodes[0].nodeValue;\n	row.cells.item(6).innerHTML = xmlDoc.getElementsByTagName('c6')[0].childNodes[0].nodeValue;\n	row.cells.item(7).innerHTML = xmlDoc.getElementsByTagName('c7')[0].childNodes[0].nodeValue;\n	row.cells.item(8).innerHTML = xmlDoc.getElementsByTagName('c8')[0].childNodes[0].nodeValue;\n}\n");
		char url[256];
		sprintf( url, "'/cacheex?action=row&id='+idx");
		sprintf( http_buf, HTTP_UPDATE_ROW, url);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		// UPD DIV
		sprintf( url, "/cacheex?action=div");
		sprintf( http_buf, HTTP_UPDATE_DIV, cfg.http.autorefresh*1000, url);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		//
		tcp_writestr(&tcpbuf, sock, "\nfunction start()\n{\n	setautorefresh(autorefresh);\n}");
		tcp_writestr(&tcpbuf, sock, "\n</script>\n");
		tcp_write(&tcpbuf, sock, http_head_, strlen(http_head_) );
		tcp_writestr(&tcpbuf, sock, "<body onload=\"start();\">");
		tcp_write_menu(&tcpbuf, sock,PAGE_CACHEEX);
		// DIV
		tcp_writestr(&tcpbuf, sock, "\n<div id='mainDiv'>");
	}

	sprintf( http_buf,"<br> * Total Replies = %d</td>",cfg.cacheex.rep); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf,"<br> * Total Hits = %d</td>",cfg.cacheex.hits); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

	// TABLE
	tcp_writestr(&tcpbuf,sock, "\n<br><table class=maintable width=100%>");
	tcp_writestr(&tcpbuf,sock, "\n<tr><th width=170px>Name / Host</th><th width=120px>ip</th><th width=80px>Mode</th><th width=100px>NodeID</th><th width=110px>Connected</th><th width=80px>Push</th><th width=80px>Got</th><th width=80px>Hits</th><th>Last CacheEX Hit</th></tr>");
	int alt=0;

	// CCcam Clients
	cccam = cfg.cccam.server;
	while (cccam) {
		// Count Clients
		int counter = 0;
		struct cc_client_data *cli = cccam->cacheexclient;
		while (cli) {
			if (cli->cacheex_mode) counter++;
			cli = cli->next;
		}
		// test
		if (counter) {
			sprintf( http_buf,"\n<tr><td class=alt3 colspan=9> CCcam %d (%d)</td></tr>", cccam->id, counter); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			struct cc_client_data *cli = cccam->cacheexclient;
			while (cli) {
				if (cli->cacheex_mode) {
					if (alt==1) alt=2; else alt=1;
					cacheex_cccamclient_cells(cli,cell);
					sprintf( http_buf,"\n<tr class=alt%d id=\"Row%d\" onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class=\"%s\">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",alt,(cli->id+0x10000),(cli->id+0x10000),cell[0],cell[1],cell[2],cell[3],cell[9],cell[4],cell[5],cell[6],cell[7],cell[8]);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				}
				cli = cli->next;
			}
		}
		cccam = cccam->next;
	}

#ifdef CAMD35_SRV
	// CAMD35 CLIENTS
	struct camd35_server_data *camd35 = cfg.camd35.server;
	while (camd35) {
		struct camd35_client_data *cli = camd35->cacheexclient;
		// Count Clients
		int counter = 0;
		while (cli) {
			if (cli->cacheex_mode) counter++;
			cli = cli->next;
		}
		if (counter) {
			sprintf( http_buf,"\n<tr><td class=alt3 colspan=9> Camd35 %d (%d)</td></tr>", camd35->id, counter); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			cli = camd35->cacheexclient;
			while (cli) {
				if (cli->cacheex_mode) {
					if (alt==1) alt=2; else alt=1;
					cacheex_camd35client_cells(cli,cell);
					sprintf( http_buf,"\n<tr class=alt%d id=\"Row%d\" onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class=\"%s\">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",alt,(cli->id+0x20000),(cli->id+0x20000),cell[0],cell[1],cell[2],cell[3],cell[9],cell[4],cell[5],cell[6],cell[7],cell[8]);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				}
				cli = cli->next;
			}
		}
		camd35 = camd35->next;
	}
#endif

#ifdef CS378X_SRV
	// cs378x CLIENTS
	struct camd35_server_data *cs378x = cfg.cs378x.server;
	while (cs378x) {
		struct camd35_client_data *cli = cs378x->cacheexclient;
		// Count Clients
		int counter = 0;
		while (cli) {
			if (cli->cacheex_mode) counter++;
			cli = cli->next;
		}
		if (counter) {
			sprintf( http_buf,"\n<tr><td class=alt3 colspan=9> cs378x %d (%d)</td></tr>", cs378x->id, counter); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			cli = cs378x->cacheexclient;
			while (cli) {
				if (cli->cacheex_mode) {
					if (alt==1) alt=2; else alt=1;
					cacheex_camd35client_cells(cli,cell);
					sprintf( http_buf,"\n<tr class=alt%d id=\"Row%d\" onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class=\"%s\">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",alt,(cli->id+0x30000),(cli->id+0x30000),cell[0],cell[1],cell[2],cell[3],cell[9],cell[4],cell[5],cell[6],cell[7],cell[8]);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				}
				cli = cli->next;
			}
		}
		cs378x = cs378x->next;
	}
#endif

	// CACHEEX Servers
	int counter = 0;
	struct server_data *srv = cfg.cacheexserver;
	while (srv) {
		if (!(srv->flags&FLAG_DELETE))
		if ( (srv->type==TYPE_CCCAM)
#ifdef CAMD35_CLI
			||(srv->type==TYPE_CAMD35)
#endif
#ifdef CS378X_CLI
			||(srv->type==TYPE_CS378X)
#endif
		)
		if (srv->cacheex_mode) counter++;
		srv = srv->next;
	}
	// test
	if (counter) {
		sprintf( http_buf,"\n<tr><td class=alt3 colspan=9> Servers (%d)</td></tr>", counter); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		struct server_data *srv = cfg.cacheexserver;
		while (srv) {
			if (!(srv->flags&FLAG_DELETE))
			if ( (srv->type==TYPE_CCCAM)
#ifdef CAMD35_CLI
				||(srv->type==TYPE_CAMD35)
#endif
#ifdef CS378X_CLI
				||(srv->type==TYPE_CS378X)
#endif
			)
			if (srv->cacheex_mode) {
				if (alt==1) alt=2; else alt=1;
				cacheex_server_cells(srv,cell);
				sprintf( http_buf,"<tr class=alt%d id=\"Row%d\" onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class=\"%s\">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",alt,(srv->id+0x40000),(srv->id+0x40000),cell[0],cell[1],cell[2],cell[3],cell[9],cell[4],cell[5],cell[6],cell[7],cell[8]);
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			}
			srv = srv->next;
		}
	}

	//
	sprintf( http_buf, "</table>");
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

	//
	if (get_action==ACTION_PAGE) {
		tcp_writestr(&tcpbuf, sock, "</div>");
		tcp_writestr(&tcpbuf, sock, "</body></html>");
	}
	tcp_flush(&tcpbuf, sock);
}

#endif

///////////////////////////////////////////////////////////////////////////////

void http_send_cccam_client(int sock, http_request *req)
{
	char http_buf[2048];
	struct tcp_buffer_data tcpbuf;


	// Get Params
	char *str_action = isset_get( req, "action");
	char *str_id = isset_get( req, "id"); // Client ID
	char *str_name = isset_get( req, "name"); // Client NAME
	char *str_srvid = isset_get( req, "srvid"); // CCcam Server ID

	// Param 'action'
	int get_action;
	if (str_action) {
		if (!strcmp(str_action,"div")) get_action = ACTION_DIV;
#ifndef PUBLIC
		else if (!strcmp(str_action,"xml")) get_action = ACTION_XML; // Get Clients info in xml
#endif
		else if (!strcmp(str_action,"disable")) get_action = ACTION_DISABLE;
		else if (!strcmp(str_action,"enable")) get_action = ACTION_ENABLE;
		else if (!strcmp(str_action,"status")) get_action = ACTION_STATUS;
		else if (!strcmp(str_action,"debug")) get_action = ACTION_DEBUG;
		else if (!strcmp(str_action,"update")) get_action = ACTION_UPDATE;
		else str_action = NULL;
	}
	if (!str_action) { str_action = "page"; get_action = ACTION_PAGE; }

	/////////////////////////////////////////////

	// GET CLIENT
	struct cc_client_data *cli = NULL;
	if (str_id) cli = getcccamclientbyid( atoi(str_id) );
	else if (str_srvid && str_name) {
		struct cccam_server_data *cccam = getcccamserverbyid( atoi(str_srvid) );
		if (cccam) cli = getcccamclientbyname( cccam, str_name );
	}
	if (!cli) return;
	//

	if (get_action==ACTION_XML) {
		tcp_init(&tcpbuf);
		tcp_writestr(&tcpbuf, sock, "HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n");
		tcp_writestr(&tcpbuf, sock, "<client>");
		uint32_t ticks = GetTickCount();
		sprintf(http_buf, "<id>%d</id>", cli->id); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		sprintf(http_buf, "<name>%s</name>", cli->user); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		if (cli->connection.status>0) {
			tcp_writestr(&tcpbuf, sock, "<status>1</status>");
			sprintf( http_buf,"<ip>%s</ip>", (char*)ip2string(cli->ip) ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			char *p = getcountrycodebyip(cli->ip);
			if (p) sprintf(http_buf, "<country>%s</country>", p); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			uint32_t d = (ticks - cli->connection.time)/1000;
			sprintf(http_buf, "<connected>%02dd %02d:%02d:%02d</connected>", d/(3600*24), (d/3600)%24, (d/60)%60, d%60); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			sprintf( http_buf,"<version>%s</version>", cli->version ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			sprintf( http_buf,"<busy>%d</busy>", cli->ecm.busy ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			d = (ticks - cli->lastactivity)/1000;
			sprintf(http_buf, "<lastactivity>%02dd %02d:%02d:%02d</lastactivity>", d/(3600*24), (d/3600)%24, (d/60)%60, d%60); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			if ( cli->lastecm.caid ) {
				sprintf(http_buf, "<lastshare>%04x:%06x:%04x</lastshare>",cli->lastecm.caid,cli->lastecm.prov,cli->lastecm.sid); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				sprintf(http_buf, "<lastsharestatus>%d</lastsharestatus>",cli->lastecm.status); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			}
		}
		else {
			sprintf(http_buf, "<status>%d</status>",cli->flags&0x0E);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		}
		sprintf(http_buf, "<ecmnb>%d</ecmnb>", cli->ecmnb); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		sprintf(http_buf, "<ecmaccepted>%d</ecmaccepted>", cli->ecmnb-cli->ecmdenied); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		sprintf(http_buf, "<ecmok>%d</ecmok>", cli->ecmok); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		tcp_writestr(&tcpbuf, sock, "\n</client>");
		tcp_flush(&tcpbuf, sock);
		return;
	}
	else if (get_action==ACTION_DISABLE) {
		cli->flags |= FLAG_DISABLE;
		if (cli->connection.status>0) cc_disconnect_cli(cli);
		http_send_ok(sock);
		return;
	}
	else if (get_action==ACTION_ENABLE) {
		cli->flags &= ~FLAG_DISABLE;
		http_send_ok(sock);
		return;
	}
	else if (get_action==ACTION_DEBUG) {
		flagdebug = getdbgflag( DBG_CCCAM, cli->parent->id, cli->id);
		http_send_ok(sock);
		return;
	}
	else if (get_action==ACTION_STATUS) {
		if (cli->connection.status>0) http_send_text(sock,"connected"); else http_send_text(sock,"disconnected");
		return;
	}
	else if (get_action==ACTION_UPDATE) {
		char *str = isset_get( req, "expire"); // Client ID
		if (str) {
			if ( (str[4]=='-')&&(str[7]=='-') ) strptime(  str, "%Y-%m-%d %H", &cli->enddate);
			else if ( (str[2]=='-')&&(str[5]=='-') ) strptime(  str, "%d-%m-%Y %H", &cli->enddate);
		}
		str = isset_get( req, "active"); // Client ID
		if (str) {
			if (str[0]=='0') {
				cli->flags |= FLAG_DISABLE;
				if (cli->connection.status>0) cc_disconnect_cli(cli);
			}
			else cli->flags &= ~FLAG_DISABLE;
		}
		http_send_text(sock, "OK");
		return;
	}

	tcp_init(&tcpbuf);
	if (get_action==0) {
		tcp_write(&tcpbuf, sock, http_replyok, strlen(http_replyok) );
		tcp_write(&tcpbuf, sock, http_html, strlen(http_html) );
		tcp_write(&tcpbuf, sock, http_head, strlen(http_head) );
		sprintf( http_buf, html_title, cfg.http.title, "CCcam Client"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		tcp_write(&tcpbuf, sock, http_link, strlen(http_link) );
		tcp_write(&tcpbuf, sock, http_style, strlen(http_style) );
		// JS
        tcp_write(&tcpbuf, sock, http_javascript, strlen(http_javascript) );
		tcp_writestr(&tcpbuf, sock, "\n<script type='text/javascript'>");
		// UPD DIV
		char url[256];
		sprintf( url, "/cccamclient?action=div&id=%d", cli->id);
		sprintf( http_buf, HTTP_UPDATE_DIV, cfg.http.autorefresh*1000, url);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		//
		tcp_writestr(&tcpbuf, sock, "\nfunction start()\n{\n	setautorefresh(autorefresh);\n}");
		tcp_writestr(&tcpbuf, sock, "\n</script>\n");
		tcp_write(&tcpbuf, sock, http_head_, strlen(http_head_) );
		tcp_writestr(&tcpbuf, sock, "<body onload=\"start();\">");
		tcp_write_menu(&tcpbuf, sock,0);
		// DIV
		tcp_writestr(&tcpbuf, sock, "<div id='mainDiv'>");
	}

	tcp_writestr(&tcpbuf, sock, "<br><table style=\"padding:0px; margin:0px;\" width=\"100%%\"><tbody>\n" );
	tcp_writestr(&tcpbuf, sock, "<tr><td style=\"vertical-align:top; width:400px;\">\n" );


	tcp_writestr(&tcpbuf, sock, "<table class=infotable><tbody>\n<tr><th colspan=2>Client Informations</th></tr>\n" );
	// NAME
	sprintf( http_buf,"<tr><td class=left>User name</td><td class=right>%s</td></tr>\n",cli->user);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	// Connection Time
	if (cli->connection.status>0) {
		tcp_writestr(&tcpbuf, sock, "<tr><td class=left>Status</td><td class=right>Connected</td></tr>\n");
		uint32_t d = (GetTickCount()-cli->connection.time)/1000;
		sprintf( http_buf,"<tr><td class=left>Connection time</td><td class=right>%02dd %02d:%02d:%02d</td></tr>\n", d/(3600*24), (d/3600)%24, (d/60)%60, d%60);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		// IP
		sprintf( http_buf,"<tr><td class=left>IP Address</td><td class=right>%s</td></tr>\n",(char*)ip2string(cli->ip) );
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		// fd
		sprintf( http_buf,"<tr><td class=left>File Descriptor</td><td class=right>%d</td></tr>\n", cli->handle );
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		// CCcam Version
		sprintf( http_buf,"<tr><td class=left>CCcam Version</td><td class=right>%s</td></tr>",cli->version );
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}
	else {
		tcp_writestr(&tcpbuf, sock, "<tr><td class=left>Status</td><td class=right>Disconnected</td></tr>\n");
		if (cli->connection.lastseen) {
			uint32_t d = (GetTickCount()-cli->connection.lastseen)/1000;
			sprintf( http_buf,"<tr><td class=left>Last Seen</td><td class=right>%02dd %02d:%02d:%02d</td></tr>\n", d/(3600*24),(d/3600)%24,(d/60)%60,d%60);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		}
	}
	// UPTIME
	if ( cli->connection.uptime || (cli->connection.status>0) ) {
		uint32_t uptime;
		if (cli->connection.status>0) uptime = (GetTickCount()-cli->connection.time)+cli->connection.uptime; else uptime = cli->connection.uptime;
		uptime /= 1000;
		sprintf( http_buf,"<tr><td class=left>Uptime</td><td class=right>%02dd %02d:%02d:%02d</td></tr>",uptime/(3600*24),(uptime/3600)%24,(uptime/60)%60,uptime%60);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}
#ifdef CHECK_NEXTDCW
	sprintf( http_buf,"<tr><td class=left>DCW CHECK</td><td class=right>%s</td></tr>", yesno(cli->dcwcheck) );
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
#endif
/*
	if (cli->option.nodeid[0]) {
		sprintf( http_buf,"<tr><td class=left>NodeID</td><td class=right>%lx</td></tr>", cli->option.nodeid);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}
*/
	tcp_writestr(&tcpbuf, sock, "</tbody></table><br>\n" );


	// INFO
	struct client_info_data *info = cli->info;
	if (info) {
		tcp_writestr(&tcpbuf, sock, "<table class=\"infotable\"><tbody>\n" );
		tcp_writestr(&tcpbuf, sock, "<tr><th colspan=2>Additional Informations</th></tr>\n" );
		while (info) {
			sprintf( http_buf,"<tr><td class=left>%s</td><td class=right>%s</td></tr>\n",info->name,info->value);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			info = info->next;
		}
		tcp_writestr(&tcpbuf, sock, "</tbody></table><br>\n" );
	}

	// Ecm Stat
	tcp_writestr(&tcpbuf, sock, "<table class=\"infotable\"><tbody>\n" );
	tcp_writestr(&tcpbuf, sock, "<tr><th colspan=2>ECM Statistics</th></tr>\n" );
	int ecmaccepted = cli->ecmnb-cli->ecmdenied;
	sprintf( http_buf, "<tr><td class=left>Total ECM requests</td><td class=right>%d</td></tr>\n", cli->ecmnb);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf, "<tr><td class=left>Accepted ECM requests</td><td class=right>%d</td></tr>\n", ecmaccepted);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf, "<tr><td class=left>Good ECM answer</td><td class=right>%d</td></tr>\n", cli->ecmok);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	//Ecm Time
	if (cli->ecmok) {
		sprintf( http_buf,"<tr><td class=left>Average Time</td><td class=right>%d ms</td></tr>\n",(cli->ecmoktime/cli->ecmok) );
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}
	// Freeze
	sprintf( http_buf,"<tr><td class=left>Total Freeze</td><td class=right>%d</td></tr>\n", cli->freeze);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

	sprintf( http_buf,"<tr><td class=left>Total Zap</td><td class=right>%d</td></tr>\n", cli->zap);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

	sprintf( http_buf,"<tr><td class=left>Total Logins</td><td class=right>%d</td></tr>\n", cli->nblogin);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

	sprintf( http_buf,"<tr><td class=left>Total Bad Logins</td><td class=right>%d</td></tr>\n", cli->nbloginerror);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

	sprintf( http_buf,"<tr><td class=left>Total differents ip logins</td><td class=right>%d</td></tr>\n", cli->nbdiffip);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

	sprintf( http_buf,"<tr><td class=left>Total DCW client Errors</td><td class=right>%d</td></tr>\n", cli->nbdcwerr);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

	tcp_writestr(&tcpbuf, sock, "</tbody></table><br>\n" );


	tcp_writestr(&tcpbuf, sock, "</td><td style=\"vertical-align:top;\">\n" );

	//Last Used Share
	if ( cli->lastecm.caid ) {
		tcp_writestr(&tcpbuf, sock, "<table class=\"infotable\"><tbody>\n" );
		tcp_writestr(&tcpbuf, sock, "<tr><th>Last Used share</th></tr>\n");
		// Decode Status
		if (cli->lastecm.status)
			sprintf( http_buf,"<tr><td>Decode success</td></tr>\n");
		else
			sprintf( http_buf,"<tr><td>Decode failed</td></tr>\n");
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		// Channel
		sprintf( http_buf,"<tr><td>Channel %s (%dms) %s</td></tr>\n", getchname(cli->lastecm.caid, cli->lastecm.prov, cli->lastecm.sid) , cli->lastecm.decodetime, str_laststatus[cli->lastecm.status] );
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

		// Server
		if ( (GetTickCount()-cli->ecm.recvtime) < 20000 ) {
			// From ???
			if (cli->lastecm.status) {
				tcp_writestr(&tcpbuf, sock, "<tr><td>From ");
				src2string(cli->lastecm.dcwsrctype, cli->lastecm.dcwsrcid, http_buf );
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				tcp_writestr(&tcpbuf, sock, "</td></tr>");
			}
			// Last ECM
			ECM_DATA *ecm = cli->lastecm.request;
			// ECM
			sprintf( http_buf,"<tr><td>ECM(%d): ", ecm->ecmlen); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			array2hex( ecm->ecm, http_buf, ecm->ecmlen );	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			sprintf( http_buf,"</td></tr>\n"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			// DCW
			if (cli->lastecm.status) {
				sprintf( http_buf,"<tr><td>CW: ");	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				array2hex( ecm->cw, http_buf, 16 );	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				sprintf( http_buf,"</td></tr>\n"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			}
#ifdef CHECK_NEXTDCW
			if ( ecm->lastdecode.ecm && (ecm->lastdecode.counter>0) ) {
				sprintf( http_buf,"<tr><td>Previous CW: "); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				array2hex( ecm->lastdecode.dcw, http_buf, 16 ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				tcp_writestr(&tcpbuf, sock, "</td></tr>\n");
				if (ecm->lastdecode.error) {
					sprintf( http_buf,"<tr><td>Errors = %d</td></tr>\n", ecm->lastdecode.error);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				}
				sprintf( http_buf,"<tr><td>Total Cycles = %d</td></tr>\n<tr><td>ECM Interval = %ds</td></tr>\n", ecm->lastdecode.counter, ecm->lastdecode.dcwchangetime/1000);
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			}
#endif

			//
			if (ecm->server[0].srvid) {
				sprintf( http_buf, "<tr><td><table class='infotable'><tbody><tr><th width='30px'>ID</th><th width='250px'>Server</th><th width='50px'>Status</th><th width='70px'>Start time</th><th width='70px'>End time</th><th width='90px'>Elapsed time</th><th>CW</th></tr></tbody>");
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				int i;
				for(i=0; i<20; i++) {
					if (!ecm->server[i].srvid) break;
					char* str_srvstatus[] = { "WAIT", "OK", "NOK", "BUSY" };
					struct server_data *srv = getsrvbyid(ecm->server[i].srvid);
					if (srv) {
						sprintf( http_buf,"<tr><td>%d</td><td>%s:%d</td><td>%s</td><td>%dms</td>", i+1, srv->host->name, srv->port, str_srvstatus[ecm->server[i].flag], ecm->server[i].sendtime - ecm->recvtime );
						tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
						// Recv Time
						if (ecm->server[i].statustime>ecm->server[i].sendtime)
							sprintf( http_buf,"<td>%dms</td><td>%dms</td>", ecm->server[i].statustime - ecm->recvtime, ecm->server[i].statustime-ecm->server[i].sendtime );
						else
							sprintf( http_buf,"<td>--</td><td>--</td>");
						tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
						// DCW
						if (ecm->server[i].flag==ECM_SRV_REPLY_GOOD) {
							sprintf( http_buf,"<td>"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
							array2hex( ecm->server[i].dcw, http_buf, 16 );	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
							sprintf( http_buf,"</td>"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
						}
						else {
							sprintf( http_buf,"<td>--</td>");
							tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
						}
						sprintf( http_buf,"</tr>");
						tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					}
				}
				tcp_writestr(&tcpbuf, sock, "</tbody></table></td></tr>\n" );
			}
		}
		tcp_writestr(&tcpbuf, sock, "</tbody></table><br>\n" );
	}

	// Current Busy Ecm
	if (cli->ecm.busy) {
		ECM_DATA *ecm = cli->ecm.request;
		if (ecm) http_send_ecmstatus(&tcpbuf, sock, ecm);
	}

	tcp_writestr(&tcpbuf, sock, "</td></tr></tbody></table>" );

	if (get_action==0) {
		tcp_writestr(&tcpbuf, sock, "</div>");
		tcp_writestr(&tcpbuf, sock, "</body></html>");
	}
	tcp_flush(&tcpbuf, sock);
}


#ifdef FREECCCAM_SRV

int freecccam_connectedclients()
{
	int nb=0;
	struct cc_client_data *cli=cfg.freecccam.server.client;
	while (cli) {
		if (cli->connection.status>0) nb++;
		cli=cli->next;
	}
	return nb;
}


void http_send_freecccam(int sock, http_request *req)
{
	char http_buf[4096];
	struct tcp_buffer_data tcpbuf;
	char cell[10][2048];

	char *str_clid = isset_get( req, "clid"); // Client ID
	if (str_clid) {
		int id = atoi(str_clid);
		struct cc_client_data *cli = cfg.freecccam.server.client;
		while (cli) {
			if ( cli->id==id ) {
				// Send XML CELLS
				getcccamcells(cli,cell);
				int i; for(i=0; i<10; i++) xmlescape( cell[i] );
				sprintf( http_buf, "<cccam>\n<c0>%s</c0>\n<c1>%s</c1>\n<c2_c>%s</c2_c>\n<c2>%s</c2>\n<c3>%s</c3>\n<c4>%s</c4>\n<c5>%s</c5>\n<c6>%s</c6>\n<c7>%s</c7>\n</cccam>\n",cell[2],cell[1],cell[9],cell[3],cell[4],cell[5],cell[6],cell[7],cell[8] );
				http_send_xml( sock, req, http_buf, strlen(http_buf));
				return;
			}			
			cli = cli->next;
		}
		return;
	}

	tcp_init(&tcpbuf);
	tcp_write(&tcpbuf, sock, http_replyok, strlen(http_replyok) );
	tcp_write(&tcpbuf, sock, http_html, strlen(http_html) );
	tcp_write(&tcpbuf, sock, http_head, strlen(http_head) );
	sprintf( http_buf, html_title, cfg.http.title, "FreeCCcam"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	tcp_write(&tcpbuf, sock, http_link, strlen(http_link) );
	tcp_write(&tcpbuf, sock, http_style, strlen(http_style) );
	// JS
    tcp_write(&tcpbuf, sock, http_javascript, strlen(http_javascript) );
	tcp_writestr(&tcpbuf, sock, "\n<script type='text/javascript'>");
	// UPD ROW
	tcp_writestr(&tcpbuf, sock, "\nfunction xmlupdateRow( xmlDoc, id )\n{\n	var row = document.getElementById(id);\n	row.cells.item(0).innerHTML = xmlDoc.getElementsByTagName('c0')[0].childNodes[0].nodeValue;\n	row.cells.item(1).innerHTML = xmlDoc.getElementsByTagName('c1')[0].childNodes[0].nodeValue;\n	row.cells.item(2).className = xmlDoc.getElementsByTagName('c2_c')[0].childNodes[0].nodeValue;\n	row.cells.item(2).innerHTML = xmlDoc.getElementsByTagName('c2')[0].childNodes[0].nodeValue;\n	row.cells.item(3).innerHTML = xmlDoc.getElementsByTagName('c3')[0].childNodes[0].nodeValue;\n	row.cells.item(4).innerHTML = xmlDoc.getElementsByTagName('c4')[0].childNodes[0].nodeValue;\n	row.cells.item(5).innerHTML = xmlDoc.getElementsByTagName('c5')[0].childNodes[0].nodeValue;\n	row.cells.item(6).innerHTML = xmlDoc.getElementsByTagName('c6')[0].childNodes[0].nodeValue;\n	row.cells.item(7).innerHTML = xmlDoc.getElementsByTagName('c7')[0].childNodes[0].nodeValue;\n}\n");
	char url[256];
	sprintf( url, "'/freecccam?action=row&clid='+idx");
	sprintf( http_buf, HTTP_UPDATE_ROW, url);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	//
	tcp_writestr(&tcpbuf, sock, "\n</script>\n");

	tcp_write(&tcpbuf, sock, http_head_, strlen(http_head_) );
	tcp_write(&tcpbuf, sock, http_body, strlen(http_body) );
	tcp_write_menu(&tcpbuf, sock,PAGE_FREECCCAM);

	if (cfg.freecccam.server.handle>0) { sprintf( http_buf, "FreeCCcam Server [<font color=#00ff00>ENABLED</font>]");tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) ); }
	else {
		sprintf( http_buf, "FreeCCcam Server [<font color=#ff0000>DISABLED</font>]");
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		tcp_flush(&tcpbuf, sock);
		return;
	}

	sprintf( http_buf, "<br>Port = %d<br>Connected Clients: %d<br><center><table class=maintable width=100%%><tr><th width=200px>Client ip</th><th width=70px>version</th><th width=110px>connected</th><th width=60px>TotalEcm</th><th width=90px>AcceptedEcm</th><th width=90px>EcmOK</th><th width=50px>EcmTime</th><th>Last used share</th></tr>", cfg.freecccam.server.port, freecccam_connectedclients());
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

	int alt=0;
	struct cc_client_data *cli = cfg.freecccam.server.client;

	while (cli) {
		if (cli->connection.status>0) {
			if (alt==1) alt=2; else alt=1;
			getcccamcells( cli,cell);
			sprintf( http_buf,"\n<tr class=alt%d id=\"Row%d\" onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td class=\"%s\">%s</td><td align=center>%s</td><td>%s</td><td>%s</td><td align=center>%s</td><td>%s</td></tr>\n",alt,cli->id,cli->id,cell[2],cell[1],cell[9],cell[3],cell[4],cell[5],cell[6],cell[7],cell[8]);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		}
		cli = cli->next;
	}

	sprintf( http_buf, "</table></center>");
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

	tcp_flush(&tcpbuf, sock);
}

#endif

#endif




#ifdef MGCAMD_SRV

void getmgcamdcells(struct mg_client_data *cli, char cell[10][2048])
{
	char temp[2048];
	unsigned int ticks = GetTickCount();
	unsigned int d;

	// CELL0 # NAME
	if (cli->realname)
		sprintf( cell[0],"<a href='/mgcamdclient?id=%d'>%s<br>%s</a>",cli->id,cli->user,cli->realname);
	else
		sprintf( cell[0],"<a href='/mgcamdclient?id=%d'>%s</a>",cli->id,cli->user);
	// CELL1 # PROGRAM ID
	if (cli->connection.status>0)
		sprintf( cell[1],"<span title='%04x'>%s</span>", cli->progid, programid(cli->progid));
	else strcpy( cell[1], " ");
	// CELL2 # IP
	if ( cli->ip ) { // Get Last IP
		char *p = getcountrycodebyip(cli->ip);
		if (cli->host)
			if (p) sprintf( cell[2],"<img src='/flag_%s.gif' title='%s'> %s<br>%s", p, getcountryname(p), (char*)ip2string(cli->ip), cli->host->name ); else sprintf( cell[2],"%s<br>%s",(char*)ip2string(cli->ip), cli->host->name );
		else
			if (p) sprintf( cell[2],"<img src='/flag_%s.gif' title='%s'> %s", p, getcountryname(p), (char*)ip2string(cli->ip) ); else sprintf( cell[2],"%s",(char*)ip2string(cli->ip) );
	}
	else strcpy( cell[2], " ");
	// CELL3 # Connection Time
	if (cli->connection.status>0) {
		if (cli->ecm.busy) sprintf( cell[9],"busy"); else sprintf( cell[9],"online");
		uint d = (GetTickCount()-cli->connection.time)/1000;
		sprintf( cell[3], "%02dd %02d:%02d:%02d", d/(3600*24), (d/3600)%24, (d/60)%60, d%60);
	}
	else {
		sprintf( cell[9],"offline");
		if (cli->flags&FLAG_DELETE) sprintf( cell[3],"Removed");
		else if (cli->flags&FLAG_EXPIRED) sprintf( cell[3],"Expired");
		else if (cli->flags&FLAG_DISABLE) sprintf( cell[3],"Disabled");
		else sprintf( cell[3],"offline");
	}
#ifdef EXPIREDATE
	if (cli->enddate.tm_year) {
		sprintf( temp,"<br>Expire: %d-%02d-%02d", 1900+cli->enddate.tm_year, cli->enddate.tm_mon+1, cli->enddate.tm_mday);
		strcat( cell[3], temp );
	}
#endif
	sprintf( temp, "<table class=\"connect_data\"><tr><td>Successful Login: %d</td><td>Aborted Connections: %d</td><td>Total Zapping: %d</td><td>Channel Freeze: %d</td></tr></table>", cli->nblogin, cli->nbloginerror, cli->zap, cli->freeze );
	strcat( cell[3], temp );
	// CELL4+5+6 # ECM STAT: TOTAL/ACCEPTED/OK
	// ECM STAT

#ifdef SRV_CSCACHE
	if (cli->cachedcw) sprintf( cell[4], "%d [%d]", cli->ecmnb, cli->cachedcw); else sprintf( cell[4], "%d", cli->ecmnb );
#else
	sprintf( cell[4], "%d", cli->ecmnb );
#endif

	int ecmaccepted = cli->ecmnb-cli->ecmdenied;
	getstatcell( ecmaccepted, cli->ecmnb, cell[5]);
	getstatcell( cli->ecmok, ecmaccepted, cell[6]);

	// CELL7 # Ecm Time
	if (cli->ecmok) sprintf( cell[7],"%d ms",(cli->ecmoktime/cli->ecmok) ); else sprintf( cell[7],"-- ms");

	// CELL8 # Last Used Share
        if ( cli->connection.status<=0 && cli->connection.lastseen) {
                d = (ticks-cli->connection.lastseen)/1000;
                sprintf( cell[8],"Last Seen %02dd %02d:%02d:%02d", d/(3600*24),(d/3600)%24,(d/60)%60,d%60);
        }
	else if ( cli->lastecm.caid ) {
		if (cli->lastecm.status)  strcpy( cell[8],"<span class=success"); else strcpy( cell[8],"<span class=failed");
		sprintf( temp," title='%04x:%06x:%04x'>ch %s (%dms) %s ",cli->lastecm.caid, cli->lastecm.prov, cli->lastecm.sid, getchname(cli->lastecm.caid, cli->lastecm.prov, cli->lastecm.sid) , cli->lastecm.decodetime, str_laststatus[cli->lastecm.status] );
		strcat( cell[8], temp );
		if ( (GetTickCount()-cli->ecm.recvtime) < 20000 ) {
			// From ???
			if (cli->lastecm.status) {
				strcat( cell[8], " / from ");
				src2string(cli->lastecm.dcwsrctype, cli->lastecm.dcwsrcid, temp);
				strcat( cell[8], temp);
			}
		}
		strcat( cell[8], "</span>" );
	}
	else strcpy( cell[8], " ");

	strcat( cell[8], "<span style='float:right;'>");
	if ( !(cli->flags&(FLAG_DELETE|FLAG_EXPIRED)) ) {
		if (cli->flags&FLAG_DISABLE) {
			sprintf( temp," <img title='Enable' src='enable.png' OnClick=\"imgrequest('/mgcamdclient?id=%d&action=enable',this);\">",cli->id);
			strcat( cell[8], temp );
		}
		else {
			sprintf( temp," <img title='disable' src='disable.png' OnClick=\"imgrequest('/mgcamdclient?id=%d&action=disable',this);\">",cli->id);
			strcat( cell[8], temp );
		}
	}
	sprintf( temp," <img title='Debug' src='debug.png' OnClick=\"imgrequest('/mgcamdclient?id=%d&action=debug',this);\">",cli->id);
	strcat( cell[8], temp );
	strcat( cell[8], "</span>");

}


int total_mgcamd_servers()
{
	int count=0;
	struct mgcamdserver_data *srv = cfg.mgcamd.server;
	while (srv) {
		count++;
		srv = srv->next;
	}
	return count;
}	

void mgcamd_clients( struct mgcamdserver_data *mgcamd, int *total, int *connected, int *active )
{
	*total = 0;
	*connected = 0;
	*active = 0;
	struct mg_client_data *cli = mgcamd->client;
	while (cli) {
		(*total)++;
		if (cli->connection.status>0) {
			(*connected)++;
			if ( (GetTickCount()-cli->lastecmtime) < 20000 ) (*active)++;
		}
		cli=cli->next;
	}
}

void total_mgcamd_clients( int *total, int *connected, int *active )
{
	*total = 0;
	*connected = 0;
	*active = 0;
	struct mgcamdserver_data *mgcamd = cfg.mgcamd.server;
	while (mgcamd) {
		struct mg_client_data *cli = mgcamd->client;
		while (cli) {
			(*total)++;
			if (cli->connection.status>0) {
				(*connected)++;
				if ( (GetTickCount()-cli->lastecmtime) < 20000 ) (*active)++;
			}
			cli=cli->next;
		}
		mgcamd = mgcamd->next;
	}
}


void http_send_mgcamd(int sock, http_request *req)
{
	char http_buf[2048];
	struct tcp_buffer_data tcpbuf;
	char cell[10][2048];

	// Get Params
	char *str_action = isset_get( req, "action");
	char *str_list = isset_get( req, "list");
	char *str_id = isset_get( req, "id"); // server ID
	char *str_clid = isset_get( req, "clid"); // Client ID
#ifndef PUBLIC
	char *str_clname = isset_get( req, "clname"); // Client NAME
#endif
	// Param 'action'
	int get_action;
	if (str_action) {
		if (!strcmp(str_action,"div")) get_action = ACTION_DIV;
		else if (!strcmp(str_action,"row")) get_action = ACTION_ROW;
#ifndef PUBLIC
		else if (!strcmp(str_action,"xml")) get_action = ACTION_XML; // Get Clients info in xml
#endif
		else if (!strcmp(str_action,"disable")) get_action = ACTION_DISABLE;
		else if (!strcmp(str_action,"enable")) get_action = ACTION_ENABLE;
		else if (!strcmp(str_action,"status")) get_action = ACTION_STATUS;
		else if (!strcmp(str_action,"debug")) get_action = ACTION_DEBUG;
		else str_action = NULL;
	}
	if (!str_action) { str_action = "page"; get_action = ACTION_PAGE; }

	/////////////////////////////////////////////

	if (get_action==ACTION_ROW) {
		// Check for XML ROW
		struct mg_client_data *cli = NULL;
		if (str_clid) {
			cli = getmgcamdclientbyid( atoi(str_clid) );
			if (!cli) return;
		}
#ifndef PUBLIC
		else {
			if (str_id && str_clname) {
				struct mgcamdserver_data *mgcamd = getmgcamdserverbyid( atoi(str_id) );
				if (!mgcamd) return;
				cli = getmgcamdclientbyname( mgcamd, str_clname );
				if (!cli) return;
			}
			else return;
		}
#else
		else return;
#endif
		// Send XML CELLS
		getmgcamdcells(cli,cell);
		int i; for(i=0; i<10; i++) xmlescape( cell[i] );
		char buf[5000] = "";
		sprintf( buf, "<mgcamd>\n<c0>%s</c0>\n<c1>%s</c1>\n<c2>%s</c2>\n<c3_c>%s</c3_c>\n<c3>%s</c3>\n<c4>%s</c4>\n<c5>%s</c5>\n<c6>%s</c6>\n<c7>%s</c7>\n<c8>%s</c8>\n</mgcamd>\n",cell[0],cell[1],cell[2],cell[9],cell[3],cell[4],cell[5],cell[6],cell[7],cell[8] );
		http_send_xml( sock, req, buf, strlen(buf));
		return;
	}			
	else if (get_action==ACTION_XML) {
		struct mgcamdserver_data *mgcamd = NULL;
		if (str_id) mgcamd = getmgcamdserverbyid( atoi(str_id) );
		tcp_init(&tcpbuf);
		tcp_writestr(&tcpbuf, sock, "HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n");

		tcp_writestr(&tcpbuf, sock, "<multics>");

		struct mgcamdserver_data *srv;
		if (mgcamd) srv = mgcamd; else srv = cfg.mgcamd.server;
		while (srv) {
			tcp_writestr(&tcpbuf, sock, "\n<mgcamd>");
			sprintf(http_buf, "<id>%d</id>", srv->id); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			sprintf(http_buf, "<port>%d</port>", srv->port); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			sprintf(http_buf, "<status>%d</status>", (srv->handle>0) ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			uint32_t ticks = GetTickCount();
			struct mg_client_data *cli = srv->client;
			while (cli) {
				tcp_writestr(&tcpbuf, sock, "<user>");
				sprintf(http_buf, "<name>%s</name>", cli->user); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				if (cli->connection.status>0) {
					tcp_writestr(&tcpbuf, sock, "<status>1</status>");
					sprintf( http_buf,"<ip>%s</ip>", (char*)ip2string(cli->ip) ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					char *p = getcountrycodebyip(cli->ip);
					if (p) sprintf(http_buf, "<country>%s</country>", p); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					uint32_t d = (ticks - cli->connection.time)/1000;
					sprintf(http_buf, "<connected>%02dd %02d:%02d:%02d</connected>", d/(3600*24), (d/3600)%24, (d/60)%60, d%60); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				}
				else {
					sprintf(http_buf, "<status>%d</status>",cli->flags&0x0E);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				}
				tcp_writestr(&tcpbuf, sock, "</user>");
				cli = cli->next;
			}
			tcp_writestr(&tcpbuf, sock, "\n</mgcamd>");

			if (mgcamd) break; else srv = srv->next;
		}
		tcp_writestr(&tcpbuf, sock, "\n</multics>");
		tcp_flush(&tcpbuf, sock);
		return;
	}


	// Param 'id'
	int get_id = 0;
	if (str_id)	get_id = atoi(str_id);
	// Param 'list'
	int get_list = LIST_ACTIVE;
	if (str_list) {
		if (!strcmp(str_list,"connected")) get_list = LIST_CONNECTED;
		else if (!strcmp(str_list,"all")) get_list = LIST_ALL;
		else str_list = NULL;
	}
	if (!str_list) str_list = "active";
	//
	struct mgcamdserver_data *mgcamd = NULL;
	if (get_id) {
		mgcamd = getmgcamdserverbyid(get_id);
		if (!mgcamd) return;
	}

	tcp_init(&tcpbuf);
	if (get_action==ACTION_PAGE) {
		tcp_write(&tcpbuf, sock, http_replyok, strlen(http_replyok) );
		tcp_write(&tcpbuf, sock, http_html, strlen(http_html) );
		tcp_write(&tcpbuf, sock, http_head, strlen(http_head) );
		sprintf( http_buf, html_title, cfg.http.title, "MGcamd"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		tcp_write(&tcpbuf, sock, http_link, strlen(http_link) );
		tcp_write(&tcpbuf, sock, http_style, strlen(http_style) );
		// JS
        tcp_write(&tcpbuf, sock, http_javascript, strlen(http_javascript) );
		tcp_writestr(&tcpbuf, sock, "\n<script type='text/javascript'>");
		// ACTIONS REQUEST
		tcp_writestr(&tcpbuf, sock, "\nfunction imgrequest( url, el )\n{\n	var httpRequest;\n	try { httpRequest = new XMLHttpRequest(); }\n	catch (trymicrosoft) { try { httpRequest = new ActiveXObject('Msxml2.XMLHTTP'); } catch (oldermicrosoft) { try { httpRequest = new ActiveXObject('Microsoft.XMLHTTP'); } catch(failed) { httpRequest = false; } } }\n	if (!httpRequest) { alert('Your browser does not support Ajax.'); return false; }\n	if ( typeof(el)!='undefined' ) {\n		el.onclick = null;\n		el.style.opacity = '0.7';\n		httpRequest.onreadystatechange = function()\n		{\n			if (httpRequest.readyState == 4) if (httpRequest.status == 200) el.style.opacity = '0.3';\n		}\n	}\n	httpRequest.open('GET', url, true);\n	httpRequest.send(null);\n}\n");
		// UPD ROW
		tcp_writestr(&tcpbuf, sock, "\nfunction xmlupdateRow( xmlDoc, id )\n{\n	var row = document.getElementById(id);\n	row.cells.item(0).innerHTML = xmlDoc.getElementsByTagName('c0')[0].childNodes[0].nodeValue;\n	row.cells.item(1).innerHTML = xmlDoc.getElementsByTagName('c1')[0].childNodes[0].nodeValue;\n	row.cells.item(2).innerHTML = xmlDoc.getElementsByTagName('c2')[0].childNodes[0].nodeValue;\n	row.cells.item(3).className = xmlDoc.getElementsByTagName('c3_c')[0].childNodes[0].nodeValue;\n	row.cells.item(3).innerHTML = xmlDoc.getElementsByTagName('c3')[0].childNodes[0].nodeValue;\n	row.cells.item(4).innerHTML = xmlDoc.getElementsByTagName('c4')[0].childNodes[0].nodeValue;\n	row.cells.item(5).innerHTML = xmlDoc.getElementsByTagName('c5')[0].childNodes[0].nodeValue;\n	row.cells.item(6).innerHTML = xmlDoc.getElementsByTagName('c6')[0].childNodes[0].nodeValue;\n	row.cells.item(7).innerHTML = xmlDoc.getElementsByTagName('c7')[0].childNodes[0].nodeValue;\n	row.cells.item(8).innerHTML = xmlDoc.getElementsByTagName('c8')[0].childNodes[0].nodeValue;\n}\n");
		char url[256];
		sprintf( url, "'/mgcamd?action=row&clid='+idx");
		sprintf( http_buf, HTTP_UPDATE_ROW, url);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		// UPD DIV
		sprintf( url, "/mgcamd?action=div&id=%d&list=%s", get_id, str_list);
		sprintf( http_buf, HTTP_UPDATE_DIV, cfg.http.autorefresh*1000, url);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		//
		tcp_writestr(&tcpbuf, sock, "\nfunction start()\n{\n	setautorefresh(autorefresh);\n}");
		tcp_writestr(&tcpbuf, sock, "\n</script>\n");
		tcp_write(&tcpbuf, sock, http_head_, strlen(http_head_) );
		tcp_writestr(&tcpbuf, sock, "<body onload=\"start();\">");
		tcp_write_menu(&tcpbuf, sock,PAGE_MGCAMD);
		// DIV
		tcp_writestr(&tcpbuf, sock, "<div id='mainDiv'>");
	}

	tcp_writestr(&tcpbuf, sock, "<table style=\"margin:0px; padding:0px; border-width:0px; border-spacing: 1px;\"><tr>");
	tcp_writestr(&tcpbuf, sock, "<td style=\"margin:0px; padding:0px;\"><a href='/mgcamd'><table border=1 width=200px>");
	// Total Servers
	sprintf( http_buf, "<tr><td>Total Mgcamd Servers: %d</td></tr>", total_mgcamd_servers() ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	int total, connected, active;
	total_mgcamd_clients( &total, &connected, &active );
	sprintf( http_buf, "<tr><td>Connected Clients: %d / %d</td></tr>", connected, total ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	tcp_writestr(&tcpbuf, sock, "</table></a></td>");
	// Servers
	if (cfg.mgcamd.server) {
		int counter = 0;
		struct mgcamdserver_data *mgcamd = cfg.mgcamd.server;
		while ( mgcamd && (counter<5) ) {
			sprintf( http_buf, "<td style=\"margin:0px; padding: 0px;\"><a href='/mgcamd?id=%d'><table border=1 width=150px>", mgcamd->id);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			if (mgcamd->handle>0) sprintf( http_buf, "<tr><td>mgcamd %d [<span class=success>%d</span>]</td></tr>", mgcamd->id, mgcamd->port);
			else sprintf( http_buf, "<tr><td>mgcamd %d [<span class=failed>%d</span>]</td></tr>", mgcamd->id, mgcamd->port);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			int total, connected, active;
			mgcamd_clients( mgcamd, &total, &connected, &active );
			sprintf( http_buf, "<tr><td>Connected: %d / %d</td></tr>", connected, total);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			tcp_writestr(&tcpbuf, sock, "</table></a></td>");
			counter++;
			mgcamd = mgcamd->next;
		}
	}
	// End of table
	tcp_writestr(&tcpbuf, sock, "</tr></table><br>");

	tcp_writestr(&tcpbuf, sock, "<select style=\"width:200px;\" onchange=\"parent.location.href='/mgcamd?id='+this.value\">");
	sprintf( http_buf, "<option value=0>ALL (%d)</option>", total_mgcamd_servers());
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	struct mgcamdserver_data *tmp = cfg.mgcamd.server;
	while (tmp) {
		if (get_id==tmp->id) sprintf( http_buf, "<option value=%d selected>[%d] mgcamd %d</option>",tmp->id,tmp->port, tmp->id );
		else sprintf( http_buf, "<option value=%d>[%d] mgcamd %d</option>",tmp->id,tmp->port, tmp->id );
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		tmp = tmp->next;
	}
	tcp_writestr(&tcpbuf, sock, "</select> ");
	//
	if (mgcamd) mgcamd_clients( mgcamd, &total, &connected, &active ); else total_mgcamd_clients( &total, &connected, &active );
	char *class1 = "button"; char *class2 = "sbutton";
	char *class;
	if (get_list==LIST_ACTIVE) class = class2; else class = class1;
	sprintf( http_buf, "<input type=button class=%s onclick=\"parent.location='/mgcamd?id=%d&amp;list=active'\" value='Active Clients (%d)'>", class, get_id, active);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	if (get_list==LIST_CONNECTED) class = class2; else class = class1;
	sprintf( http_buf, " <input type=button class=%s onclick=\"parent.location='/mgcamd?id=%d&amp;list=connected'\" value='Connected Clients (%d)'>", class, get_id, connected);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	if (get_list==LIST_ALL) class = class2; else class = class1;
	sprintf( http_buf, " <input type=button class=%s onclick=\"parent.location='/mgcamd?id=%d&amp;list=all'\" value='All Clients (%d)'>", class, get_id, total);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	//
	if (get_id) { // One Server Selected
		// Table
		sprintf( http_buf, "\n<table class=maintable width=100%%><tr><th width=100px>Client</th><th width=70px>version</th><th width=120px>ip</th><th width=110px>Connected</th><th width=60px>TotalEcm</th><th width=90px>AcceptedEcm</th><th width=90px>EcmOK</th><th width=50px>EcmTime</th><th>Last used share</th></tr>");
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		struct mg_client_data *cli = mgcamd->client;
		int alt=0;
		if (get_list==LIST_ACTIVE) {
			while (cli) {
				if ( (cli->connection.status>0)&&((GetTickCount()-cli->lastecmtime) < 20000) ) {
					if (alt==1) alt=2; else alt=1;
					getmgcamdcells(cli,cell);
					sprintf( http_buf,"\n<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td>%s</td><td class=\"%s\">%s</td><td align=center>%s</td><td>%s</td><td>%s</td><td align=center>%s</td><td>%s</td></tr>\n",cli->id,alt,cli->id,cell[0],cell[1],cell[2],cell[9],cell[3],cell[4],cell[5],cell[6],cell[7],cell[8]);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				}
				cli = cli->next;
			}
		}
		else if (get_list==LIST_CONNECTED) {
			while (cli) {
				if (cli->connection.status>0) {
					if (alt==1) alt=2; else alt=1;
					getmgcamdcells(cli,cell);
					sprintf( http_buf,"\n<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td>%s</td><td class=\"%s\">%s</td><td align=center>%s</td><td>%s</td><td>%s</td><td align=center>%s</td><td>%s</td></tr>\n",cli->id,alt,cli->id,cell[0],cell[1],cell[2],cell[9],cell[3],cell[4],cell[5],cell[6],cell[7],cell[8]);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				}
				cli = cli->next;
			}
		}
		else { // ALL
			while (cli) {
				if (alt==1) alt=2; else alt=1;
				getmgcamdcells(cli,cell);
				sprintf( http_buf,"\n<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td>%s</td><td class=\"%s\">%s</td><td align=center>%s</td><td>%s</td><td>%s</td><td align=center>%s</td><td>%s</td></tr>\n",cli->id,alt,cli->id,cell[0],cell[1],cell[2],cell[9],cell[3],cell[4],cell[5],cell[6],cell[7],cell[8]);
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				cli = cli->next;
			}
		}
		sprintf( http_buf, "\n</table>");
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}

	else {
		// Table
		tcp_writestr(&tcpbuf,sock, "\n<table class=maintable width=100%>");
		tcp_writestr(&tcpbuf,sock, "\n<tr><th width=100px>Client</th><th width=70px>version</th><th width=120px>ip</th><th width=110px>Connected</th><th width=60px>TotalEcm</th><th width=90px>AcceptedEcm</th><th width=90px>EcmOK</th><th width=50px>EcmTime</th><th>Last used share</th></tr>");
		int alt=0;
		mgcamd = cfg.mgcamd.server;
		while (mgcamd) {
			int total, connected, active;
			mgcamd_clients( mgcamd, &total, &connected, &active );
			if ( (get_list==LIST_ACTIVE) && active ) {
				sprintf( http_buf,"\n<tr><td class=alt3 colspan=9> mgcamd %d (%d)</td></tr>", mgcamd->id, active); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				struct mg_client_data *cli = mgcamd->client;
				while (cli) {
					if ( (cli->connection.status>0)&&((GetTickCount()-cli->lastecmtime) < 20000) ) {
						if (alt==1) alt=2; else alt=1;
						getmgcamdcells(cli,cell);
						sprintf( http_buf,"\n<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td>%s</td><td class=\"%s\">%s</td><td align=center>%s</td><td>%s</td><td>%s</td><td align=center>%s</td><td>%s</td></tr>\n",cli->id,alt,cli->id,cell[0],cell[1],cell[2],cell[9],cell[3],cell[4],cell[5],cell[6],cell[7],cell[8]);
						tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					}
					cli = cli->next;
				}
			}
			else if ( (get_list==LIST_ALL) && total ) {
				sprintf( http_buf,"\n<tr><td class=alt3 colspan=9> mgcamd %d (%d)</td></tr>", mgcamd->id, total); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				struct mg_client_data *cli = mgcamd->client;
				while (cli) {
					if (alt==1) alt=2; else alt=1;
					getmgcamdcells(cli,cell);
					sprintf( http_buf,"\n<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td>%s</td><td class=\"%s\">%s</td><td align=center>%s</td><td>%s</td><td>%s</td><td align=center>%s</td><td>%s</td></tr>\n",cli->id,alt,cli->id,cell[0],cell[1],cell[2],cell[9],cell[3],cell[4],cell[5],cell[6],cell[7],cell[8]);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					cli = cli->next;
				}
			}
			else if ( (get_list==LIST_CONNECTED) && connected ) {
				sprintf( http_buf,"\n<tr><td class=alt3 colspan=9> mgcamd %d (%d)</td></tr>", mgcamd->id, connected); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				struct mg_client_data *cli = mgcamd->client;
				while (cli) {
					if (cli->connection.status>0) {
						if (alt==1) alt=2; else alt=1;
						getmgcamdcells(cli,cell);
						sprintf( http_buf,"\n<tr id=\"Row%d\" class=alt%d onMouseOver='setupdateRow(%d)' onMouseOut='setupdateRow(0)'> <td>%s</td><td>%s</td><td>%s</td><td class=\"%s\">%s</td><td align=center>%s</td><td>%s</td><td>%s</td><td align=center>%s</td><td>%s</td></tr>\n",cli->id,alt,cli->id,cell[0],cell[1],cell[2],cell[9],cell[3],cell[4],cell[5],cell[6],cell[7],cell[8]);
						tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					}
					cli = cli->next;
				}
			}
			mgcamd = mgcamd->next;
		}
		sprintf( http_buf, "</table>");
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}
	if (get_action==ACTION_PAGE) {
		tcp_writestr(&tcpbuf, sock, "</div>");
		tcp_writestr(&tcpbuf, sock, "</body></html>");
	}

	tcp_flush(&tcpbuf, sock);
}


///////////////////////////////////////////////////////////////////////////////

void http_send_mgcamd_client(int sock, http_request *req)
{
	char http_buf[2048];
	struct tcp_buffer_data tcpbuf;

	// Get Params
	char *str_action = isset_get( req, "action");
	char *str_id = isset_get( req, "id"); // Client ID
	char *str_name = isset_get( req, "name"); // Client NAME
	char *str_srvid = isset_get( req, "srvid"); // CCcam Server ID

	// Action
	int get_action = ACTION_PAGE;
	if (str_action) {
		if (!strcmp(str_action,"div")) get_action = ACTION_DIV;
		else if (!strcmp(str_action,"row")) get_action = ACTION_ROW;
		else if (!strcmp(str_action,"disable")) get_action = ACTION_DISABLE;
		else if (!strcmp(str_action,"enable")) get_action = ACTION_ENABLE;
		else if (!strcmp(str_action,"status")) get_action = ACTION_STATUS;
		else if (!strcmp(str_action,"debug")) get_action = ACTION_DEBUG;
		else if (!strcmp(str_action,"update")) get_action = ACTION_UPDATE;
		else str_action = NULL;
	}
	if (!str_action) { str_action = "page"; get_action = ACTION_PAGE; }

	/////////////////////////////////////////////

	// GET CLIENT
	struct mg_client_data *cli = NULL;
	if (str_id) cli = getmgcamdclientbyid( atoi(str_id) );
	else if (str_srvid && str_name) {
		struct mgcamdserver_data *mgcamd = getmgcamdserverbyid( atoi(str_srvid) );
		if (mgcamd) cli = getmgcamdclientbyname( mgcamd, str_name );
	}
	if (!cli) return;
	//
	if (get_action==ACTION_DISABLE) {
		cli->flags |= FLAG_DISABLE;
		if (cli->connection.status>0) mg_disconnect_cli(cli);
		http_send_ok(sock);
		return;
	}
	else if (get_action==ACTION_ENABLE) {
		cli->flags &= ~FLAG_DISABLE;
		http_send_ok(sock);
		return;
	}
	else if (get_action==ACTION_STATUS) {
		if (cli->connection.status>0) http_send_text(sock,"connected"); else http_send_text(sock,"disconnected");
		return;
	}
	else if (get_action==ACTION_DEBUG) {
		flagdebug = getdbgflag( DBG_MGCAMD, 0, cli->id);
		http_send_ok(sock);
		return;
	}
	else if (get_action==ACTION_UPDATE) {
		char *str = isset_get( req, "expire"); // Client ID
		if (str) {
			if ( (str[4]=='-')&&(str[7]=='-') ) strptime(  str, "%Y-%m-%d %H", &cli->enddate);
			else if ( (str[2]=='-')&&(str[5]=='-') ) strptime(  str, "%d-%m-%Y %H", &cli->enddate);
		}
		str = isset_get( req, "active"); // Client ID
		if (str) {
			if (str[0]=='0') {
				cli->flags |= FLAG_DISABLE;
				if (cli->connection.status>0) mg_disconnect_cli(cli);
			}
			else cli->flags &= ~FLAG_DISABLE;
		}
		http_send_text(sock, "OK");
		return;
	}

	//
	tcp_init(&tcpbuf);
	if (get_action==ACTION_PAGE) {
		tcp_write(&tcpbuf, sock, http_replyok, strlen(http_replyok) );
		tcp_write(&tcpbuf, sock, http_html, strlen(http_html) );
		tcp_write(&tcpbuf, sock, http_head, strlen(http_head) );
		sprintf( http_buf, html_title, cfg.http.title, "Mgcamd Client"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		tcp_write(&tcpbuf, sock, http_link, strlen(http_link) );
		tcp_write(&tcpbuf, sock, http_style, strlen(http_style) );
		// JS
        tcp_write(&tcpbuf, sock, http_javascript, strlen(http_javascript) );
		tcp_writestr(&tcpbuf, sock, "\n<script type='text/javascript'>");
		// UPD DIV
		char url[256];
		sprintf( url, "/mgcamdclient?id=%d&action=div", cli->id);
		sprintf( http_buf, HTTP_UPDATE_DIV, cfg.http.autorefresh*1000, url);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		//
		tcp_writestr(&tcpbuf, sock, "\nfunction start()\n{\n	setautorefresh(autorefresh);\n}");
		tcp_writestr(&tcpbuf, sock, "\n</script>\n");
		tcp_write(&tcpbuf, sock, http_head_, strlen(http_head_) );
		tcp_writestr(&tcpbuf, sock, "<body onload=\"start();\">");
		tcp_write_menu(&tcpbuf, sock,0);
		// DIV
		tcp_writestr(&tcpbuf, sock, "<div id='mainDiv'>");
	}

	tcp_writestr(&tcpbuf, sock, "<table style=\"padding:0px; margin:0px;\" width=\"100%%\"><tbody>\n" );
	tcp_writestr(&tcpbuf, sock, "<tr><td style=\"vertical-align:top; width:400px;\">\n" );

	tcp_writestr(&tcpbuf, sock, "<table class=infotable><tbody>\n<tr><th colspan=2>Client Informations</th></tr>\n" );
	// NAME
	sprintf( http_buf,"<tr><td class=left>User name</td><td class=right>%s</td></tr>\n",cli->user);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	// Connection Time
	if (cli->connection.status>0) {
		tcp_writestr(&tcpbuf, sock, "<tr><td class=left>Status</td><td class=right>Connected</td></tr>\n");
		uint32_t d = (GetTickCount()-cli->connection.time)/1000;
		sprintf( http_buf,"<tr><td class=left>Connection time</td><td class=right>%02dd %02d:%02d:%02d</td></tr>\n", d/(3600*24), (d/3600)%24, (d/60)%60, d%60);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		// IP
		sprintf( http_buf,"<tr><td class=left>IP Address</td><td class=right>%s</td></tr>\n",(char*)ip2string(cli->ip) );
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		// Program ID
		sprintf( http_buf,"<tr><td class=left>Client Program</td><td class=right>%s(%04x)</td></tr>",programid(cli->progid), cli->progid );
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}
	else {
		tcp_writestr(&tcpbuf, sock, "<tr><td class=left>Status</td><td class=right>Disconnected</td></tr>\n");
		if ( cli->connection.lastseen ) {
			uint32_t d = (GetTickCount()-cli->connection.lastseen)/1000;
			sprintf( http_buf,"<tr><td class=left>Last Seen</td><td class=right>%02dd %02d:%02d:%02d</td></tr>\n", d/(3600*24),(d/3600)%24,(d/60)%60,d%60);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		}
	}
	// UPTIME
	if ( cli->connection.uptime || (cli->connection.status>0) ) {
		uint32_t uptime;
		if (cli->connection.status>0) uptime = (GetTickCount()-cli->connection.time)+cli->connection.uptime; else uptime = cli->connection.uptime;
		uptime /= 1000;
		sprintf( http_buf,"<tr><td class=left>Uptime</td><td class=right>%02dd %02d:%02d:%02d</td></tr>",uptime/(3600*24),(uptime/3600)%24,(uptime/60)%60,uptime%60);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}
#ifdef CHECK_NEXTDCW
	sprintf( http_buf,"<tr><td class=left>DCW CHECK</td><td class=right>%s</td></tr>", yesno(cli->dcwcheck) );
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
#endif
	tcp_writestr(&tcpbuf, sock, "</tbody></table><br>\n" );


	// INFO
	struct client_info_data *info = cli->info;
	if (info) {
		tcp_writestr(&tcpbuf, sock, "<table class=\"infotable\"><tbody>\n" );
		tcp_writestr(&tcpbuf, sock, "<tr><th colspan=2>Additional Informations</th></tr>\n" );
		while (info) {
			sprintf( http_buf,"<tr><td class=left>%s</td><td class=right>%s</td></tr>\n",info->name,info->value);
			tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			info = info->next;
		}
		tcp_writestr(&tcpbuf, sock, "</tbody></table><br>\n" );
	}

	// Ecm Stat
	tcp_writestr(&tcpbuf, sock, "<table class=\"infotable\"><tbody>\n" );
	tcp_writestr(&tcpbuf, sock, "<tr><th colspan=2>ECM Statistics</th></tr>\n" );
	int ecmaccepted = cli->ecmnb-cli->ecmdenied;
	sprintf( http_buf, "<tr><td class=left>Total ECM requests</td><td class=right>%d</td></tr>\n", cli->ecmnb);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf, "<tr><td class=left>Accepted ECM requests</td><td class=right>%d</td></tr>\n", ecmaccepted);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	sprintf( http_buf, "<tr><td class=left>Good ECM answer</td><td class=right>%d</td></tr>\n", cli->ecmok);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	//Ecm Time
	if (cli->ecmok) {
		sprintf( http_buf,"<tr><td class=left>Average Time</td><td class=right>%d ms</td></tr>\n",(cli->ecmoktime/cli->ecmok) );
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	}
#ifdef SRV_CSCACHE
	sprintf( http_buf, "<tr><td class=left>Cached CW</td><td class=right>%d</td></tr>\n", cli->cachedcw);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
#endif
	// Freeze
	sprintf( http_buf,"<tr><td class=left>Total Freeze</td><td class=right>%d</td></tr>\n", cli->freeze);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	tcp_writestr(&tcpbuf, sock, "</tbody></table><br>\n" );


	tcp_writestr(&tcpbuf, sock, "</td><td style=\"vertical-align:top;\">\n" );

	//Last Used Share
	if ( cli->lastecm.caid ) {
		tcp_writestr(&tcpbuf, sock, "<table class=\"infotable\"><tbody>\n" );
		tcp_writestr(&tcpbuf, sock, "<tr><th>Last Used share</th></tr>\n");
		// Decode Status
		if (cli->lastecm.status)
			sprintf( http_buf,"<tr><td>Decode success</td></tr>\n");
		else
			sprintf( http_buf,"<tr><td>Decode failed</td></tr>\n");
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		// Channel
		sprintf( http_buf,"<tr><td>Channel %s (%dms) %s</td></tr>\n", getchname(cli->lastecm.caid, cli->lastecm.prov, cli->lastecm.sid) , cli->lastecm.decodetime, str_laststatus[cli->lastecm.status] );
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

		// Server
		if ( (GetTickCount()-cli->ecm.recvtime) < 20000 ) {
			// From ???
			if (cli->lastecm.status) {
				tcp_writestr(&tcpbuf, sock, "<tr><td>From ");
				src2string(cli->lastecm.dcwsrctype, cli->lastecm.dcwsrcid, http_buf );
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				tcp_writestr(&tcpbuf, sock, "</td></tr>");
			}
			// Last ECM
			ECM_DATA *ecm = cli->lastecm.request;
			// ECM
			sprintf( http_buf,"<tr><td>ECM(%d): ", ecm->ecmlen); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			array2hex( ecm->ecm, http_buf, ecm->ecmlen );	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			sprintf( http_buf,"</td></tr>\n"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			// DCW
			if (cli->lastecm.status) {
				sprintf( http_buf,"<tr><td>CW: ");	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				array2hex( ecm->cw, http_buf, 16 );	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				sprintf( http_buf,"</td></tr>\n"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			}
#ifdef CHECK_NEXTDCW
			if ( ecm->lastdecode.ecm && (ecm->lastdecode.counter>0) ) {
				sprintf( http_buf,"<tr><td>Previous CW: "); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				array2hex( ecm->lastdecode.dcw, http_buf, 16 ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				tcp_writestr(&tcpbuf, sock, "</td></tr>\n");
				if (ecm->lastdecode.error) {
					sprintf( http_buf,"<tr><td>Errors = %d</td></tr>\n", ecm->lastdecode.error);
					tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				}
				sprintf( http_buf,"<tr><td>Total Cycles = %d</td></tr>\n<tr><td>ECM Interval = %ds</td></tr>\n", ecm->lastdecode.counter, ecm->lastdecode.dcwchangetime/1000);
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			}
#endif
			//
			if (ecm->server[0].srvid) {
				sprintf( http_buf, "<tr><td><table class='infotable'><tbody><tr><th width='30px'>ID</th><th width='250px'>Server</th><th width='50px'>Status</th><th width='70px'>Start time</th><th width='70px'>End time</th><th width='90px'>Elapsed time</th><th>CW</th></tr></tbody>");
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
				int i;
				for(i=0; i<20; i++) {
					if (!ecm->server[i].srvid) break;
					char* str_srvstatus[] = { "WAIT", "OK", "NOK", "BUSY" };
					struct server_data *srv = getsrvbyid(ecm->server[i].srvid);
					if (srv) {
						sprintf( http_buf,"<tr><td>%d</td><td>%s:%d</td><td>%s</td><td>%dms</td>", i+1, srv->host->name, srv->port, str_srvstatus[ecm->server[i].flag], ecm->server[i].sendtime - ecm->recvtime );
						tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
						// Recv Time
						if (ecm->server[i].statustime>ecm->server[i].sendtime)
							sprintf( http_buf,"<td>%dms</td><td>%dms</td>", ecm->server[i].statustime - ecm->recvtime, ecm->server[i].statustime-ecm->server[i].sendtime );
						else
							sprintf( http_buf,"<td>--</td><td>--</td>");
						tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
						// DCW
						if (ecm->server[i].flag==ECM_SRV_REPLY_GOOD) {
							sprintf( http_buf,"<td>"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
							array2hex( ecm->server[i].dcw, http_buf, 16 );	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
							sprintf( http_buf,"</td>"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
						}
						else {
							sprintf( http_buf,"<td>--</td>");
							tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
						}
						sprintf( http_buf,"</tr>");
						tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					}
				}
				tcp_writestr(&tcpbuf, sock, "</tbody></table></td></tr>\n" );
			}
		}
		tcp_writestr(&tcpbuf, sock, "</tbody></table><br>\n" );
	}

	// Current Busy Ecm
	if (cli->ecm.busy) {
		ECM_DATA *ecm = cli->ecm.request;
		if (ecm) http_send_ecmstatus(&tcpbuf, sock, ecm);
	}

	tcp_writestr(&tcpbuf, sock, "</td></tr></tbody></table>" );

	if (get_action==ACTION_PAGE) {
		tcp_writestr(&tcpbuf, sock, "</div>");
		tcp_writestr(&tcpbuf, sock, "</body></html>");
	}
	tcp_flush(&tcpbuf, sock);
}


#endif




#ifdef TESTCHANNEL

void http_send_testchannel(int sock, http_request *req)
{

	char *caid = isset_get( req, "caid");
	char *sid = isset_get( req, "sid");
	char *prid = isset_get( req, "prid");

	if (caid && sid && prid) {
		cfg.testchn.caid = hex2int( caid );
		cfg.testchn.provid = hex2int( prid );
		cfg.testchn.sid = hex2int( sid );
		unlink( debug_file );
	}
	
	char http_buf[2048];
	struct tcp_buffer_data tcpbuf;
	tcp_init(&tcpbuf);
	tcp_write(&tcpbuf, sock, http_replyok, strlen(http_replyok) );
	tcp_write(&tcpbuf, sock, http_html, strlen(http_html) );
	tcp_write(&tcpbuf, sock, http_head, strlen(http_head) );
	sprintf( http_buf, html_title, cfg.http.title, "testchannel"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	tcp_write(&tcpbuf, sock, http_link, strlen(http_link) );
	tcp_write(&tcpbuf, sock, http_style, strlen(http_style) );
	tcp_write(&tcpbuf, sock, http_head_, strlen(http_head_) );
	tcp_write(&tcpbuf, sock, http_body, strlen(http_body) );
	tcp_write_menu(&tcpbuf, sock,0);

	sprintf( http_buf,"<br> CAID = %04X<br>PROVIDER = %06X<br>SID = %04X<br>\n", cfg.testchn.caid, cfg.testchn.provid, cfg.testchn.sid);
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

	tcp_flush(&tcpbuf, sock);
}

#endif

void http_send_config(int sock, http_request *req)
{
	char *type = isset_get( req, "type");

	if ( !strcmp(type,"delay") ) {
		char *str = isset_get( req, "thread");
		if (str) {
			cfg.delay.thread = atoi( str );
		}
		str = isset_get( req, "connect");
		if (str) {
			cfg.delay.connect = atoi( str );
		}
	}

	struct tcp_buffer_data tcpbuf;
	tcp_init(&tcpbuf);
	tcp_write(&tcpbuf, sock, http_replyok, strlen(http_replyok) );
	tcp_flush(&tcpbuf, sock);
}

void http_send_host(int sock, http_request *req)
{
	char http_buf[2048];
	struct tcp_buffer_data tcpbuf;
	tcp_init(&tcpbuf);
	tcp_write(&tcpbuf, sock, http_replyok, strlen(http_replyok) );
	tcp_write(&tcpbuf, sock, http_html, strlen(http_html) );
	tcp_write(&tcpbuf, sock, http_head, strlen(http_head) );
	sprintf( http_buf, html_title, cfg.http.title, "Host"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	tcp_write(&tcpbuf, sock, http_link, strlen(http_link) );
	tcp_write(&tcpbuf, sock, http_style, strlen(http_style) );
	tcp_write(&tcpbuf, sock, http_head_, strlen(http_head_) );
	tcp_write(&tcpbuf, sock, http_body, strlen(http_body) );
	tcp_write_menu(&tcpbuf, sock,0);

	sprintf( http_buf, "<table class=maintable width=100%%><tr><th width=200px>HostName</th><th width=70px>IP</th><th width=100px>Check Time (sec)</th></tr>");
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

	struct host_data *host = cfg.host;
	int alt=0;
	while (host) {
		if (alt==1) alt=2; else alt=1;
		sprintf( http_buf,"<tr class=alt%d><td>%s</td><td>%s</td><td>%d</td>",alt, host->name, (char*)ip2string(host->ip), host->checkiptime-getseconds() );
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		host = host->next;
	}

	sprintf( http_buf, "</table>");
	tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

	tcp_flush(&tcpbuf, sock);
}


void http_send_threads(int sock, http_request *req)
{
        char http_buf[2048];
        struct tcp_buffer_data tcpbuf;
        tcp_init(&tcpbuf);
        tcp_write(&tcpbuf, sock, http_replyok, strlen(http_replyok) );
        tcp_write(&tcpbuf, sock, http_html, strlen(http_html) );
        tcp_write(&tcpbuf, sock, http_head, strlen(http_head) );
        sprintf( http_buf, html_title, cfg.http.title, "threads"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
        tcp_write(&tcpbuf, sock, http_link, strlen(http_link) );
        tcp_write(&tcpbuf, sock, http_style, strlen(http_style) );
        tcp_write(&tcpbuf, sock, http_head_, strlen(http_head_) );
        tcp_write(&tcpbuf, sock, http_body, strlen(http_body) );
		tcp_write_menu(&tcpbuf, sock,0);


		tcp_writestr(&tcpbuf, sock, "<br>Load Average = ");
		FILE *fp = fopen ("/proc/loadavg", "r");
		fgets(http_buf, sizeof(http_buf), fp);
		fclose(fp);
		tcp_writestr(&tcpbuf, sock, http_buf);

		// /proc/meminfo 
		fp = fopen ("/proc/meminfo", "r");
		fgets(http_buf, sizeof(http_buf), fp); tcp_writestr(&tcpbuf, sock, http_buf);
		fgets(http_buf, sizeof(http_buf), fp); tcp_writestr(&tcpbuf, sock, http_buf);
		fclose(fp);

		sprintf( http_buf, "<br>THREADID Main = %d",prg.pid_main ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		sprintf( http_buf, "<br>THREADID Config = %d",prg.pid_cfg ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		sprintf( http_buf, "<br> THREADID DNS = %d",prg.pid_dns ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		sprintf( http_buf, "<br> THREADID Servers Connections = %d",prg.pid_srv ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		sprintf( http_buf, "<br> THREADID Recv Messages = %d",prg.pid_msg ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		sprintf( http_buf, "<br> THREADID SET DCW = %d",prg.pid_setdcw ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		sprintf( http_buf, "<br> THREADID Cache = %d",prg.pid_cache ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		sprintf( http_buf, "<br> THREADID Date = %d",prg.pid_date ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

		sprintf( http_buf, "<br> THREADID Connect Clients = %d",prg.pid_connect ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

		sprintf( http_buf, "<br> THREADID Newcamd messages = %d",prg.pid_cs_msg ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		sprintf( http_buf, "<br> THREADID Mgcamd messages = %d",cfg.mgcamd.pid_recvmsg ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		sprintf( http_buf, "<br> THREADID CCcam messages = %d",cfg.cccam.pid_recvmsg ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
#ifdef CS378X_SRV
		sprintf( http_buf, "<br> THREADID CS378X messages = %d",cfg.cs378x.pid_recvmsg ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
#endif
#ifdef CACHEEX
        sprintf( http_buf, "<br> THREADID Ccacheex messages = %d",prg.pid_ccex_msg ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
#endif

		// CACHEEX Servers
#ifdef CACHEEX
		struct server_data *srv = cfg.server;
		while (srv) {
			if ( !(srv->flags&FLAG_DELETE) && (srv->cacheex_mode==2) ) {
		        sprintf( http_buf, "<br> THREADID Cacheex Server (%s:%d) =  %d", srv->host->name, srv->port, srv->pid );
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			}
			srv = srv->next;
		}
#endif
		sprintf( http_buf, "<br><br> TOTAL ECM REQUESTS = %d",totalecm ); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
		tcp_flush(&tcpbuf, sock);
}




#include "bmsearch.c"

void http_send_editor(int sock, http_request *req, int index)
{
	char http_buf[2048];
	struct tcp_buffer_data tcpbuf;
	tcp_init(&tcpbuf);
	tcp_write(&tcpbuf, sock, http_replyok, strlen(http_replyok) );
	tcp_write(&tcpbuf, sock, http_html, strlen(http_html) );
	tcp_write(&tcpbuf, sock, http_head, strlen(http_head) );
	sprintf( http_buf, html_title, cfg.http.title, "Editor"); tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
	tcp_write(&tcpbuf, sock, http_link, strlen(http_link) );
	tcp_write(&tcpbuf, sock, http_style, strlen(http_style) );
	tcp_write(&tcpbuf, sock, http_head_, strlen(http_head_) );
	tcp_writestr(&tcpbuf, sock, "<body onload=\"document.getElementById('submitbutton').disabled=false;\">");
	tcp_write_menu(&tcpbuf, sock,PAGE_EDITOR);
	//
	int i;
	struct filename_data *fs = cfg.files;
	for( i =0; i<index; i++) {
		if (!fs) break;
		fs = fs->next;
	}
	if ( (i!=index)||(!fs) ) return;
	char *fname = fs->name;
	int noeditor = fs->noeditor;
	//
	if ( (req->type==HTTP_POST) && !noeditor ) {
		// Check Content-Type
		char *content = isset_header(req, "Content-Type");
		if (!content) {
			mlogf(LOGERROR,getdbgflag(DBG_HTTP,0,0)," Invalid form\n");
			return;
		}
		// Parse Content-type
		if ( memcmp(content,"multipart/form-data",19) ) {
			mlogf(LOGERROR,getdbgflag(DBG_HTTP,0,0)," Invalid Content-type\n");
			return;
		}
		// Get ';'
		while (*content!=';') {
			if (*content==0)  {
				mlogf(LOGERROR,getdbgflag(DBG_HTTP,0,0)," Invalid header data\n");
				return;
			}
			content++;
		}
		content++;
		// Skip Spaces
		while (*content==' ') content++;
		// Get Boundry
		if ( memcmp(content,"boundary",8) ) {
			mlogf(LOGERROR,getdbgflag(DBG_HTTP,0,0)," Invalid Content-type\n");
			return;
		}
		// Get '='
		while (*content!='=') {
			if (*content==0)  {
				mlogf(LOGERROR,getdbgflag(DBG_HTTP,0,0)," Invalid header data\n");
				return;
			}
			content++;
		}
		content++;
		// Skip Spaces
		while (*content==' ') content++;
		// Get Boundary Value
		char boundary[255];
		sprintf( boundary, "\r\n--%s", content);
		printf(" boundary: '%s'\n", boundary);

		// search for boundary in file
		content = req->dbf.data;

		while (content) {
			content = (char*) boyermoore_horspool_memmem( (uint8_t*)content, req->dbf.datasize-(content-(char*)req->dbf.data), (uint8_t*)boundary, strlen(boundary) );
			if (content) {
				content += strlen(boundary);
				if ( *content=='\r' && *(content+1)=='\n' ) {
					content+=2;
					// Get Content-Disposition
					// Content-Disposition: form-data; name="textedit"
					char *p = content;
					while (*p!='\r') p++;
					if ( *p=='\r' && *(p+1)=='\n' && *(p+2)=='\r' && *(p+3)=='\n' ) { // Good
						*p=0;
						printf(" Content: '%s'\n", content);
						char *pdata = p+4;
						// search for newt boundary
						content = (char*)boyermoore_horspool_memmem( (uint8_t*)content, req->dbf.datasize-(content-(char*)req->dbf.data), (uint8_t*)boundary, strlen(boundary) );
						*content = 0;
						printf(" the file is:\n-------------\n%s\n-------------\n", pdata); 
						// save
						FILE *cfgfd = fopen( fname, "w");
						if (!cfgfd) {
							sprintf( http_buf, "<h2>Error opening file '%s'</h2>", fname);
						}
						else {
							int k;
							for (k=0;k<content-pdata;k++)
							{
								if ( ( *(pdata+k)=='\r' ) && ( (k+1) < (content-pdata) ) ) {
									if ( *(pdata+k+1) =='\n' ) {
										k++;
									}
								}
								fwrite( pdata+k,1,1,cfgfd);
							}
							fclose(cfgfd);
							sprintf( http_buf, "<script type=\"text/JavaScript\"><!--\nsetTimeout(\"location.href = '/editor%d';\",5000);\n--></script>\n<h3><center>file '%s' is Successfully Saved</center></h3>", index, fname);
						}
						tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
					}
				}
			}
		}
		tcp_flush(&tcpbuf, sock);
	}
	else {

		tcp_writestr(&tcpbuf, sock, "<form enctype=\"multipart/form-data\" method=\"post\">");

		tcp_writestr(&tcpbuf, sock, "<span style='float:right'><select onchange=\"window.location=this.value\" style='width:250px;'>");
		struct filename_data *fs = cfg.files;
		int i =0;
		while (fs) {
			if (!fs->noeditor) {
				if (i==index) sprintf( http_buf, "<option value=\"/editor%d\" selected>%s</option>",i, fs->name);
				else sprintf( http_buf, "<option value=\"/editor%d\">%s</option>",i, fs->name);
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			}
			i++;
			fs = fs->next;
		}
		tcp_writestr(&tcpbuf, sock, "</select></span>");

		sprintf( http_buf, "<input type=submit id='submitbutton' value=\"Save '%s'\" disabled><br>",fname);
		tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );

		if (!noeditor) {
			FILE *fd = fopen(fname, "r");
			if (fd) {
				tcp_writestr(&tcpbuf, sock, "<center><textarea cols=\"40\" wrap=\"off\" rows=\"9\" spellcheck=\"false\" name=\"textedit\">");
				while( !feof(fd) ) {
					int len = fread(http_buf, 1, sizeof(http_buf), fd);
					if (len<=0) break;
					tcp_write(&tcpbuf, sock, http_buf, len );
				}
				fclose(fd);
				sprintf( http_buf, "</textarea></center></form>");
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			}
			else {
				sprintf( http_buf, "<br>Cant open file '%s'", fname);
				tcp_write(&tcpbuf, sock, http_buf, strlen(http_buf) );
			}
		}
		tcp_flush(&tcpbuf, sock);
	}
}


int atoint(char *index)
{
  int n=0;
  while (*index)
  { 
    if ( (*index<'0')||(*index>'9') ) return n;
    else n = n*10 + (*index - '0');
    index++;
  }
  return n;
}

#include "base64.c"

struct connect_data {
	int sock;
	uint32_t ip;
};

void *gererClient(struct connect_data *param)
{
	int sock = param->sock;
	uint32_t ip = param->ip;
	free(param);

	http_request req;

	struct pollfd pfd;
	pfd.fd = sock;
	pfd.events = POLLIN | POLLPRI;
	int retval = poll(&pfd, 1, 2000);

	//printf("\n*Connexion de %s(%d)\n", tt, sock); // print pid
	dynbuf_init(&req.dbf, 1024);

	if ( retval>0 )
	if ( pfd.revents & (POLLIN|POLLPRI) ) 
	if ( parse_http_request(sock, &req) ) {

		int auth=0;
		if ( (req.type==HTTP_GET)||(req.type==HTTP_POST) ) {
			// check for auth
			if (!cfg.http.user[0] || !cfg.http.user[0]) auth = 1;
			else {
				int i;
				for(i=0; i<req.hdrcount; i++) {
					if( !strncmp(req.headers[i].name,"Authorization", 1024) ) {
						//printf("Authorization: %s\n", req.headers[i].value);
						//get auth type
						if (!memcmp(req.headers[i].value, "Basic ",6)) {
							// get encrypted login
							char pass[256];
							char realpass[256];
							base64_pdecode( &req.headers[i].value[6], pass);

							//mlogf(LOGDEBUG,0,"[ADMIN] Login Successful!");

							sprintf(realpass,"%s:%s", cfg.http.user, cfg.http.pass);
							if (!strncmp(pass,realpass,256)) auth=1;
						}
						break;
					}
				}
			}
			if ( auth ) {
				req.sock = sock;
				req.ip = ip;
				if (strcmp(req.path,"/")==0) http_send_index(sock,&req);
				else if (strcmp(req.path,"/debug")==0) {
					if (!cfg.http.show.nodebug) http_send_debug(sock,&req);
				}
				else if (strcmp(req.path,"/profiles")==0) {
					if (!cfg.http.show.noprofiles) http_send_profiles(sock,&req);
				}
				else if (strcmp(req.path,"/profile")==0) {
					if (!cfg.http.show.noprofiles) http_send_profile(sock,&req);
				}
				else if (strcmp(req.path,"/newcamd")==0) {
					if (!cfg.http.show.nonewcamd) http_send_newcamd(sock,&req);
				}
				else if (strcmp(req.path,"/newcamdclient")==0) {
					if (!cfg.http.show.nonewcamd) http_send_newcamd_client(sock,&req);
				}
				else if (strcmp(req.path,"/servers")==0) {
					if (!cfg.http.show.noservers) http_send_servers(sock,&req);
				}
				else if (strcmp(req.path,"/server")==0) {
					if (!cfg.http.show.noservers) http_send_server(sock,&req);
				}
				else if (strcmp(req.path,"/cache")==0) {
					if (!cfg.http.show.nocache) http_send_cache(sock,&req);
				}
				else if (strcmp(req.path,"/cachepeer")==0) {
					if (!cfg.http.show.nocache) http_send_cache_peer(sock,&req);
				}
#ifdef CCCAM_SRV
				else if (strcmp(req.path,"/cccam")==0) {
					if (!cfg.http.show.nocccam) http_send_cccam(sock,&req);
				}
				else if (strcmp(req.path,"/cccamclient")==0) {
					if (!cfg.http.show.nocccam) http_send_cccam_client(sock,&req);
				}
#endif
#ifdef CS378X_SRV
				else if (strcmp(req.path,"/cs378x")==0) {
					http_send_cs378x(sock,&req);
				}
				else if (strcmp(req.path,"/cs378xclient")==0) {
					http_send_cs378x_client(sock,&req);
				}
#endif
#ifdef CAMD35_SRV
				else if (strcmp(req.path,"/camd35")==0) {
					http_send_camd35(sock,&req);
				}
				else if (strcmp(req.path,"/camd35client")==0) {
					http_send_camd35_client(sock,&req);
				}
#endif
#ifdef CACHEEX
				else if (strcmp(req.path,"/cacheex")==0) {
					http_send_cacheex(sock,&req);
				}
#endif
#ifdef FREECCCAM_SRV
				else if (strcmp(req.path,"/freecccam")==0) {
					http_send_freecccam(sock,&req);
				}
#endif
#ifdef MGCAMD_SRV
				else if (strcmp(req.path,"/mgcamd")==0) {
					if (!cfg.http.show.nomgcamd) http_send_mgcamd(sock,&req);
				}
				else if (strcmp(req.path,"/mgcamdclient")==0) {
					if (!cfg.http.show.nomgcamd) http_send_mgcamd_client(sock,&req);
				}
#endif
				else if (strcmp(req.path,"/restart")==0) {
					if (!cfg.http.show.norestart) http_send_restart(sock,&req);
				}
				else if ( !memcmp(req.path,"/editor",7) )  {
					if (!cfg.http.show.noeditor) {
						int index=0;
						if ( (req.path[7]>='0')&&(req.path[7]<='9') ) index = req.path[7] - '0';
						if ( (req.path[8]>='0')&&(req.path[8]<='9') ) index = (index*10) + (req.path[8]-'0');
						http_send_editor(sock,&req, index);
					}
				}
				else if (strcmp(req.path,"/style.css")==0) {
					if (strlen(cfg.stylesheet_file)) {
						http_send_file(sock, &req, "text/css", cfg.stylesheet_file);
					}
					else http_send_answer(sock, &req, "text/css", style_css, strlen(style_css));
				}                
                else if (strcmp(req.path,"/customjs.js")==0) {
					if (strlen(cfg.javascript_file)) {
						mlogf(LOGDEBUG,DBG_HTTP," http: send file %s\n",cfg.javascript_file);
						http_send_file(sock, &req, "text/javascript", cfg.javascript_file);
					}
					else {
						mlogf(LOGDEBUG,DBG_HTTP," http: send answer %s\n",java_file);
						http_send_answer(sock, &req, "text/javascript", java_file, strlen(java_file));
					}
				}                
				else if (strcmp(req.path,"/connect.png")==0) {
					http_send_image(sock, &req, connect_png, sizeof(connect_png), "png");
				}
				else if (strcmp(req.path,"/disconnect.png")==0) {
					http_send_image(sock, &req, disconnect_png, sizeof(disconnect_png), "png");
				}
				else if (strcmp(req.path,"/enable.png")==0) {
					http_send_image(sock, &req, enable_png, sizeof(enable_png), "png");
				}
				else if (strcmp(req.path,"/disable.png")==0) {
					http_send_image(sock, &req, disable_png, sizeof(disable_png), "png");
				}
				else if (strcmp(req.path,"/debug.png")==0) {
					http_send_image(sock, &req, debug_png, sizeof(debug_png), "png");
				}
				else if (strcmp(req.path,"/refresh.png")==0) {
					http_send_image(sock, &req, refresh_png, sizeof(refresh_png), "png");
				}
				else if (strcmp(req.path,"/sms_new.gif")==0) {
					http_send_image(sock, &req, sms_new_gif, sizeof(sms_new_gif), "gif");
				}
				else if (strcmp(req.path,"/sms_old.gif")==0) {
					http_send_image(sock, &req, sms_old_gif, sizeof(sms_old_gif), "gif");
				}
				else if (strcmp(req.path,"/host")==0) {
					http_send_host(sock,&req);
				}
				else if (strcmp(req.path,"/threads")==0) {
					http_send_threads(sock,&req);
				}

#ifdef TESTCHANNEL
				else if (!strcmp(req.path,"/testchannel")) {
					http_send_testchannel(sock,&req);
				}
#endif
				else if ( !memcmp(req.path,"/flag_",6) && !memcmp(req.path+8,".gif",4) ) {
					// check for code
					char code[3];
					code[0] = req.path[6];
					code[1] = req.path[7];
					code[2] = 0;
					int i;
					for(i=0; i<MAX_COUNTRY_IMAGES; i++) {
						if ( !strcmp(country_images[i].code, code) ) {
							http_send_image(sock, &req, country_images[i].data, country_images[i].len, "gif");
							break;
						}
					}
					if (i>=MAX_COUNTRY_IMAGES) http_send_image(sock, &req, country_images[0].data, country_images[0].len, "gif");
				}

				else {
					struct http_file_data *file = cfg.http.files;
					while (file) {
						if ( !strcmp(req.path,file->url) ) {
							http_send_file( sock, &req, file->mime, file->path);
							break;
						}
						file = file->next;
					}
				}
			}
			else { // send( client_sock, (char*)data, strlen(data),0);
				//printf("%s\n", http_buf);
				struct tcp_buffer_data tcpbuf;
				char auth[1024];
				tcp_init(&tcpbuf);
				sprintf( auth, "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"%s\"\r\nVary: Accept-Encoding\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n<HTML><HEAD><TITLE>%s</TITLE></HEAD><BODY><H2>Access forbidden, authorization required</H2></BODY></HTML>", cfg.http.title, cfg.http.title);
				tcp_write(&tcpbuf, sock, auth, strlen(auth) );
				tcp_flush(&tcpbuf, sock);
				//return;
			}
		}
	}

	dynbuf_free(&req.dbf);

	//printf("*Deconnexion de %s(%d)\n", tt, sock);

	if ( close(sock) ) mlogf(LOGERROR,getdbgflag(DBG_HTTP,0,0)," HTTP Server: socket close failed(%d)\n",sock);

	return NULL;
}



void *http_thread(void *param)
{
	int clientsock;
	struct sockaddr_in client_addr;
	socklen_t socklen = sizeof(client_addr);

	prctl(PR_SET_NAME,"HTTP Server",0,0,0);

	while (!prg.restart) {
		if (cfg.http.handle>0) {
			//pthread_mutex_lock(&prg.lockhttp);

			struct pollfd pfd;
			pfd.fd = cfg.http.handle;
			pfd.events = POLLIN | POLLPRI;
			int retval = poll(&pfd, 1, 3002);
			if ( retval>0 ) {
				if ( pfd.revents & (POLLIN|POLLPRI) ) {
					clientsock = accept(cfg.http.handle, (struct sockaddr*)&client_addr, /*(socklen_t*)*/&socklen);
					if ( clientsock<0 ) {
						mlogf(LOGERROR,getdbgflag(DBG_HTTP,0,0)," HTTP Server: Accept Error\n");
						break;
					}
					else {
						//SetSocketNoDelay(clientsock);
						pthread_t cli_tid;
						struct connect_data *newdata = malloc( sizeof(struct connect_data) );
						newdata->sock = clientsock; 
						newdata->ip = client_addr.sin_addr.s_addr;
						if (!create_thread(&cli_tid, (threadfn)gererClient, newdata)) {
							close(clientsock);
							free( newdata );
						}
					}
				}
			}
			else if (retval<0) {
				mlogf(LOGERROR,getdbgflag(DBG_HTTP,0,0)," THREAD HTTP: poll error %d(errno=%d)\n", retval, errno);
				usleep(99000);
			}
			//pthread_mutex_unlock(&prg.lockhttp);
			//usleep(10);
		} else usleep(100000);
	}// While

	mlogf(LOGINFO,getdbgflag(DBG_HTTP,0,0),"Exiting HTTP Thread\n");
	return NULL;
}

pthread_t http_tid;
int start_thread_http()
{
	create_thread(&http_tid, http_thread, NULL);
	return 0;
}

