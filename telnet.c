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

#include "telnet.h"
#include "main.h"
#include "parser.h"
#include "httpserver.h"

int writes( int fd, char *str )
{
	return write(fd, str, strlen(str) );
}

char *getcountrycodebyip(uint32_t ip);

void *telnetprocess(int *param )
{
	int fd = *param;
	free(param);

	char buf[4096];
	char str[256];
	char wbuf[4096];
	int len;
	//
	writes(fd, "Welcome to Telnet Server\r\n\r\nLogin: ");

	len = recv( fd, buf, sizeof(buf), MSG_NOSIGNAL);
	if (len<=0) { close(fd); return NULL; }
	//printf(" Received(%d): '%s'\r\n", len, buf);
	if ( (buf[len-2]!='\r')||(buf[len-1]!='\n') )  { close(fd); return NULL; }
	buf[len-2] = 0;
	if ( strcmp(buf, cfg.telnet.user) ) { 
		writes(fd, "wrong username, bye.\r\n");
		close(fd);
		return NULL;
	}
	//
	writes(fd, "Password: ");
	len = recv( fd, buf, sizeof(buf), MSG_NOSIGNAL);
	if (len<=0) { close(fd); return NULL; }
	//printf(" Received(%d): '%s'\r\n", len, buf);
	if ( (buf[len-2]!='\r')||(buf[len-1]!='\n') )  { close(fd); return NULL; }
	buf[len-2] = 0;
	if ( strcmp(buf, cfg.telnet.pass) ) {
		writes(fd, "wrong password, bye.\r\n");
		close(fd);
		return NULL;
	}
	strcpy(buf, "\r\n\r\ntype 'help' for command list\r\n");write(fd, buf, strlen(buf) );

	while ( 1 ) {
		writes(fd, "\r\n[command]: ");
		len = recv( fd, buf, sizeof(buf), MSG_NOSIGNAL);
		if (len<=0) { close(fd); return NULL; }
		//printf(" Received(%d): %s", len, buf);
		if ( (buf[len-2]!='\r')||(buf[len-1]!='\n') )  { close(fd); return NULL; }
		buf[len-2] = 0;

		iparser = buf;
		parse_spaces();
		if (*iparser==0) continue;
		if (!parse_name(str)) continue;
		uppercase(str);

		if ( !strcmp(str, "EXIT") || !strcmp(str, "QUIT") ) {
			writes(fd, "bye.\r\n");
			break;
		}
		else if ( !strcmp(str, "UPTIME") ) {
			unsigned int d= GetTickCount()/1000;
			sprintf( wbuf,"Uptime: %02dd %02d:%02d:%02d\r\n", d/(3600*24), (d/3600)%24, (d/60)%60, d%60);
			writes(fd, wbuf);
		}
		else if ( !strcmp(str, "STAT") ) {
			sprintf( wbuf,"Total Profiles: %d\r\nTotal Servers: %d\r\nTotal Cache Servers: %d\r\nTotal CCcam Servers: %d\r\n", cfg.totalprofiles, cfg.totalservers, cfg.cache.totalservers, cfg.cccam.totalservers);
			writes(fd, wbuf);
		}
		else if ( !strcmp(str, "DEBUG") ) {
			int i=idbgline;
			do {
				sprintf( wbuf, "%s", dbgline[i] );
				writes(fd, wbuf);
				i++;
				if (i>=MAX_DBGLINES) i=0;
			} while (i!=idbgline);
		}
		else if ( !strcmp(str, "LOADAVG") ) {
			FILE *fp = fopen ("/proc/loadavg", "r");
			if ( fgets(wbuf, sizeof(wbuf), fp) ) writes(fd, wbuf);
			fclose(fp);
		}
		else if ( !strcmp(str, "MEMINFO") ) {
			FILE *fp = fopen ("/proc/meminfo", "r");
			if ( fgets(wbuf, sizeof(wbuf), fp) ) writes(fd, wbuf);
			if ( fgets(wbuf, sizeof(wbuf), fp) ) writes(fd, wbuf);
			fclose(fp);
		}
		else if ( !strcmp(str, "CPUINFO") ) {
			FILE *fp = fopen ("/proc/cpuinfo", "r");
			while ( fgets(wbuf, sizeof(wbuf), fp) ) writes(fd, wbuf);
			fclose(fp);
		}
#ifndef PUBLIC
		else if ( !strcmp(str, "SCHED") ) {
			if (parse_name(str)) {
				uppercase(str);
				if ( !strcmp(str, "CCCAM") ) {
					sprintf( str, "/proc/%d/sched", prg.pid_cc_msg);
					FILE *fp = fopen ( str, "r");
					while ( fgets(wbuf, sizeof(wbuf), fp) ) writes(fd, wbuf);
					fclose(fp);
				}
				else if ( !strcmp(str, "NEWCAMD") ) {
					sprintf( str, "/proc/%d/sched", prg.pid_cs_msg);
					FILE *fp = fopen ( str, "r");
					while ( fgets(wbuf, sizeof(wbuf), fp) ) writes(fd, wbuf);
					fclose(fp);
				}
				else if ( !strcmp(str, "ECM") ) {
					sprintf( str, "/proc/%d/sched", prg.pid_msg);
					FILE *fp = fopen ( str, "r");
					while ( fgets(wbuf, sizeof(wbuf), fp) ) writes(fd, wbuf);
					fclose(fp);
				}
				else if ( !strcmp(str, "MGCAMD") ) {
					sprintf( str, "/proc/%d/sched", prg.pid_mg_msg);
					FILE *fp = fopen ( str, "r");
					while ( fgets(wbuf, sizeof(wbuf), fp) ) writes(fd, wbuf);
					fclose(fp);
				}
#ifdef CACHEEX
				else if ( !strcmp(str, "CACHEEX") ) {
					sprintf( str, "/proc/%d/sched", prg.pid_ccex_msg);
					FILE *fp = fopen ( str, "r");
					while ( fgets(wbuf, sizeof(wbuf), fp) ) writes(fd, wbuf);
					fclose(fp);
				}
#endif
				else if ( !strcmp(str, "CACHE") ) {
					sprintf( str, "/proc/%d/sched", prg.pid_cache);
					FILE *fp = fopen ( str, "r");
					while ( fgets(wbuf, sizeof(wbuf), fp) ) writes(fd, wbuf);
					fclose(fp);
				}
			}
			else {
				sprintf( str, "/proc/%d/sched", prg.pid_main);
				FILE *fp = fopen ( str, "r");
				while ( fgets(wbuf, sizeof(wbuf), fp) ) writes(fd, wbuf);
				fclose(fp);
			}
		}
#endif
		else if ( !strcmp(str, "HELP") ) {
			writes(fd, " Commands: help - uptime - stat - cccam - mgcamd - debug - loadavg - cpuinfo - meminfo - exit/quit\r\n");
		}
		else if (!strcmp(str,"CCCAM")) {
			if (!parse_int(str)) {
				int index = 0;
				struct cccam_server_data *srv = cfg.cccam.server;
				while (srv) {
					index++;
					sprintf( wbuf, "id:%d  Port:%d", srv->id, srv->port);
					if (srv->handle>0) strcat( wbuf, " Status:ON "); else strcat( wbuf, " Status:OFF");
					int total, connected, active;
					cccam_clients( srv, &total, &connected, &active );
					sprintf( str, "Clients Total:%d, Connected:%d, Active:%d", total, connected, active );
					strcat( wbuf, str );
					strcat( wbuf, "\r\n");
					writes(fd, wbuf);
					srv = srv->next;
				}
				sprintf(wbuf, "Total CCcam servers = %d\r\n", index);
				writes(fd, wbuf);
			}
			else { // cccam <cientname>
				struct cccam_server_data *cccam = getcccamserverbyid( atoi(str) );
				if (!cccam) continue;
				if (!parse_name(str)) continue;
				struct cc_client_data *cli = getcccamclientbyname( cccam, str );
				if (!cli) continue;
				if (cli->connection.status>0) {
					char *p = getcountrycodebyip(cli->ip);
					if (p) 
						sprintf(wbuf, "<tr><td>%s</td><td>%s</td><td class=online>Connected</td><td>[%s] %s</td>", cfg.http.title, cli->user, p, ip2string(cli->ip) );
					else
						sprintf(wbuf, "<tr><td>%s</td><td>%s</td><td class=online>Connected</td><td>%s</td>", cfg.http.title, cli->user, ip2string(cli->ip) );
					//Last Used Share
					if ( cli->lastecm.caid ) {
						char tmp[512];
						if (cli->lastecm.status)
							sprintf( tmp,"<td class=success>channel %s (%dms) OK</td>", getchname(cli->lastecm.caid, cli->lastecm.prov, cli->lastecm.sid) , cli->lastecm.decodetime );
						else
							sprintf( tmp,"<td class=failed>channel %s (%dms) NOK</td>", getchname(cli->lastecm.caid, cli->lastecm.prov, cli->lastecm.sid) , cli->lastecm.decodetime );
						strcat( wbuf, tmp);
						// last time
						unsigned int d= (GetTickCount()-cli->ecm.recvtime)/1000;
						sprintf( tmp,"<td>%02dd %02d:%02d:%02d</td></tr>\r\n", d/(3600*24), (d/3600)%24, (d/60)%60, d%60);
						strcat( wbuf, tmp);
					} else strcat( wbuf, "<td> </td><td> </td></tr>\r\n");
				}
				else {
					if (cli->connection.lastseen) {
						uint32_t d = (GetTickCount()-cli->connection.lastseen)/1000;
						sprintf( wbuf,"<tr><td>%s</td><td>%s</td><td class=offline>Disconnected</td><td>Last Seen</td><td>%02dd %02d:%02d:%02d</td></tr>\r\n", cfg.http.title, cli->user, d/(3600*24),(d/3600)%24,(d/60)%60,d%60);
					}
					else sprintf(wbuf, "<tr><td>%s</td><td>%s</td><td class=offline>Disconnected</td><td> </td><td> </td></tr>\r\n", cfg.http.title, cli->user );
				}
				writes(fd, wbuf);
			}
		}
		else if (!strcmp(str,"MGCAMD")) {
			if (!parse_int(str)) {
				int index = 0;
				struct mgcamdserver_data *srv = cfg.mgcamd.server;
				while (srv) {
					index++;
					sprintf( wbuf, "id:%d  Port:%d", srv->id, srv->port);
					if (srv->handle>0) strcat( wbuf, " Status:ON "); else strcat( wbuf, " Status:OFF");
					int total, connected, active;
					mgcamd_clients( srv, &total, &connected, &active );
					sprintf( str, "Clients Total:%d, Connected:%d, Active:%d", total, connected, active );
					strcat( wbuf, str );
					strcat( wbuf, "\r\n");
					writes(fd, wbuf);
					srv = srv->next;
				}
				sprintf(wbuf, "Total Mgcamd servers = %d\r\n", index);
				writes(fd, wbuf);
			}
			else { // mgcamd <cientname>
				struct mgcamdserver_data *srv = getmgcamdserverbyid( atoi(str) );
				if (!srv) continue;
				if (!parse_name(str)) continue;
				struct mg_client_data *cli = getmgcamdclientbyname( srv, str );
				if (!cli) continue;
				if (cli->handle>0) {
					char *p = getcountrycodebyip(cli->ip);
					if (p) 
						sprintf(wbuf, "<tr><td>%s</td><td>%s</td><td class=online>Connected</td><td>[%s] %s</td>", cfg.http.title, cli->user, p, ip2string(cli->ip) );
					else
						sprintf(wbuf, "<tr><td>%s</td><td>%s</td><td class=online>Connected</td><td>%s</td>", cfg.http.title, cli->user, ip2string(cli->ip) );
					//Last Used Share
					if ( cli->lastecm.caid ) {
						char tmp[512];
						if (cli->lastecm.status)
							sprintf( tmp,"<td class=success>channel %s (%dms) OK</td>", getchname(cli->lastecm.caid, cli->lastecm.prov, cli->lastecm.sid) , cli->lastecm.decodetime );
						else
							sprintf( tmp,"<td class=failed>channel %s (%dms) NOK</td>", getchname(cli->lastecm.caid, cli->lastecm.prov, cli->lastecm.sid) , cli->lastecm.decodetime );
						strcat( wbuf, tmp);
						// last time
						unsigned int d= (GetTickCount()-cli->ecm.recvtime)/1000;
						sprintf( tmp,"<td>%02dd %02d:%02d:%02d</td></tr>\r\n", d/(3600*24), (d/3600)%24, (d/60)%60, d%60);
						strcat( wbuf, tmp);
					} else strcat( wbuf, "<td> </td><td> </td></tr>\r\n");
				}
				else sprintf(wbuf, "<tr><td>%s</td><td>%s</td><td class=offline>Disconnected</td><td> </td><td> </td></tr>\r\n", cfg.http.title, cli->user );
				writes(fd, wbuf);
			}
		}
		else if (!strcmp(str,"UPDATE")) {
			if (parse_name(str)) {
				uppercase(str);
				if ( !strcmp(str, "CCCAM") ) {
					if (parse_int(str)) {
						struct cccam_server_data *cccam = getcccamserverbyid( atoi(str) );
						if (!cccam) continue;
						// user
						if (!parse_str(str)) continue;
						struct cc_client_data *cli = getcccamclientbyname( cccam, str );
						if (!cli) continue;
						// pass
						if (!parse_str(str)) continue;
						if ( strcmp(str, "*") ) {
							if ( strcmp(cli->pass, str) ) {
								strcpy(cli->pass, str);
								// disconnect
								if (cli->connection.status>0) cc_disconnect_cli(cli);
							}
						}
						// date
						if (!parse_str(str)) continue;
						if ( strcmp(str, "*") ) {
							if ( (str[4]=='-')&&(str[7]=='-') ) strptime(  str, "%Y-%m-%d %H", &cli->enddate);
							else if ( (str[2]=='-')&&(str[5]=='-') ) strptime(  str, "%d-%m-%Y %H", &cli->enddate);
						}
						//
						if (parse_int(str)) {
							if (str[0]=='1') cli->flags &= ~FLAG_DISABLE; 
							else {
								cli->flags |= FLAG_DISABLE;
								if (cli->connection.status>0) cc_disconnect_cli(cli);
							}
						}
						sprintf(wbuf, "CCcam Client '%s' Updated\r\n", cli->user);
						writes(fd, wbuf);
					} else writes(fd, "update cccam <server id> <client name> <password> <expire-date> <1:enable/0:disable>\r\n");
				}
				else
				if ( !strcmp(str, "MGCAMD") ) {
					if (parse_int(str)) {
						struct mgcamdserver_data *mgcamd = getmgcamdserverbyid( atoi(str) );
						if (!mgcamd) continue;
						// user
						if (!parse_str(str)) continue;
						struct mg_client_data *cli = getmgcamdclientbyname( mgcamd, str );
						if (!cli) continue;
						// pass
						if (!parse_str(str)) continue;
						if ( strcmp(str, "*") ) {
							if ( strcmp(cli->pass, str) ) {
								strcpy(cli->pass, str);
								// disconnect
								if (cli->connection.status>0) mg_disconnect_cli(cli);
							}
						}
						// date
						if (!parse_name(str)) continue;
						if ( strcmp(str, "*") ) {
							if ( (str[4]=='-')&&(str[7]=='-') ) strptime(  str, "%Y-%m-%d %H", &cli->enddate);
							else if ( (str[2]=='-')&&(str[5]=='-') ) strptime(  str, "%d-%m-%Y %H", &cli->enddate);
						}
						//
						if (parse_int(str)) {
							if (str[0]=='1') cli->flags &= ~FLAG_DISABLE;
							else {
								cli->flags |= FLAG_DISABLE;
								if (cli->connection.status>0) mg_disconnect_cli(cli);
							}
						}
						sprintf(wbuf, "mgcamd Client '%s' Updated\r\n", cli->user);
						writes(fd, wbuf);
					} else writes(fd, "update mgcamd <server id> <client name> <password> <expire-date> <1:enable/0:disable>\r\n");
				}

			}
		}
		else {
			writes(fd, "unknown command.\r\n");
		}

	}

	close(fd);
	return NULL;
}




void *telnet_thread(void *param)
{
	int clientsock;
	struct sockaddr_in client_addr;
	socklen_t socklen = sizeof(client_addr);
#ifndef PUBLIC
	prctl(PR_SET_NAME,"Telnet",0,0,0);
#endif
	while(1) {
		if (cfg.telnet.handle>0) {
			struct pollfd pfd;
			pfd.fd = cfg.telnet.handle;
			pfd.events = POLLIN | POLLPRI;
			int retval = poll(&pfd, 1, 3002);
			if ( retval>0 ) {
				if ( pfd.revents & (POLLIN|POLLPRI) ) {
					clientsock = accept(cfg.telnet.handle, (struct sockaddr*)&client_addr, /*(socklen_t*)*/&socklen);
					if ( clientsock<0 ) {
						mlogf(LOGERROR,getdbgflag(DBG_HTTP,0,0)," telnet Server: Accept Error\n");
						break;
					}
					else {
						//SetSocketNoDelay(clientsock);
						pthread_t cli_tid;
						int *param = malloc( sizeof(int) );
						*param = clientsock;
						if ( !create_thread(&cli_tid, (threadfn)telnetprocess,param) ) {
							free( param );
							close( clientsock );
						}
					}
				}
			}
			else if (retval<0) {
				mlogf(LOGERROR,getdbgflag(DBG_HTTP,0,0)," THREAD telnet: poll error %d(errno=%d)\n", retval, errno);
				usleep(50000);
			}
		} else usleep(100000);
	}// While

	mlogf(LOGERROR,getdbgflag(DBG_HTTP,0,0),"Exiting telnet Thread\n");
	return NULL;
}

pthread_t telnet_tid;
int start_thread_telnet()
{
	create_thread(&telnet_tid, telnet_thread, NULL); // Priority
	return 0;
}

