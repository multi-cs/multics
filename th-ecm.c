
void clients_check_sendcw(ECM_DATA *ecm)
{
#ifdef TESTCHANNEL
	int testchannel = ( (ecm->caid==cfg.testchn.caid) && (ecm->provid==cfg.testchn.provid) && (ecm->sid==cfg.testchn.sid) );
	if (testchannel) {
		char dump[64];
		array2hex( ecm->cw, dump, 16);
		mlogf(LOGINFO,0," Send DCW to clients ch %04x:%06x:%04x/%02x:%08x => %s\n", ecm->caid, ecm->provid, ecm->sid, ecm->ecm[0], ecm->hash, dump);
	}
#endif

	cs_check_sendcw(ecm);
#ifdef MGCAMD_SRV
	mg_check_sendcw(ecm);
#endif
#ifdef CCCAM_SRV
	cc_check_sendcw(ecm);
#endif
#ifdef FREECCCAM_SRV
	freecccam_check_sendcw(ecm);
#endif
#ifdef CS378X_SRV
	cs378x_check_sendcw(ecm);
#endif
#ifdef CAMD35_SRV
	camd35_check_sendcw(ecm);
#endif
}


#include "loadbalance.c"
#include "setdcw.c"

///////////////////////////////////////////////////////////////////////////////
// Check sending ecm to servers
///////////////////////////////////////////////////////////////////////////////

void wakeup_sendecm() // not needed in mono-thread
{
	pipe_wakeup( prg.pipe.ecm[1] );
}

void ecm_faileddcw( ECM_DATA *ecm )
{
	ecm->dcwstatus = STAT_DCW_FAILED;
	ecm->checktime = 0;
	ecm->waitserver = 0;
	sid_newecm(ecm);
	clients_check_sendcw(ecm); // send decode failed to clients
#ifdef TESTCHANNEL
	int testchannel = ( (ecm->caid==cfg.testchn.caid) && (ecm->provid==cfg.testchn.provid) && (ecm->sid==cfg.testchn.sid) );
	if (testchannel) {
		mlogf(LOGINFO,0," <Decode_Failed> ch %04x:%06x:%04x/%02x:%08x (%s)\n", ecm->caid, ecm->provid, ecm->sid, ecm->ecm[0], ecm->hash, ecm->statusmsg);
	}
#endif
}

void check_ecm(ECM_DATA *ecm, uint32_t ticks)
{
	ecm->checktime = 0; // invalid
	ecm->waitserver = 0;

	// CACHE(fallowcache = 1)
	if (ecm->dcwstatus==STAT_DCW_WAITCACHE) {
		struct cardserver_data *cs = ecm->cs;
		if (!cs) {
			ecm->statusmsg = "Invalid profile id";
			ecm_faileddcw( ecm );
			return;
		}
		if (cs->option.fallowcache) {
			if (!ecm->waitcache) { // Not done
				if (cs->option.fallowcache) {
					pipe_cache_find(ecm, cs);
					ecm->waitcache = 1;
					ecm->checktime = ecm->recvtime + cs->option.cachetimeout; // wait for cache
				}
				else ecm->dcwstatus = STAT_DCW_WAIT;
			}
			else {
				if ( ( (ecm->recvtime+cs->option.cachetimeout)<=ticks ) ) ecm->dcwstatus = STAT_DCW_WAIT;
				else {
					//mlogf(LOGDEBUG,0," Wait for cache\n");
					ecm->checktime = ecm->recvtime+cs->option.cachetimeout;
				}
			}
		}
		else ecm->dcwstatus = STAT_DCW_WAIT;
	}

	// SEND ECM
	if ( (ecm->dcwstatus==STAT_DCW_WAIT) ) {
		// Check Profile
		struct cardserver_data *cs = ecm->cs;
		if (!cs) {
			ecm->statusmsg = "Invalid profile id";
			ecm_faileddcw( ecm );
			return;
		}
		//check for decode failed
		// Check for Max used Servers
		if ( (cs->option.server.max>0) && (ecm->server_totalsent>=cs->option.server.max) ) {
			if (!ecm->server_totalwait) {
				ecm->statusmsg = "Decode failed, max servers is reached and no more servers to wait";
				ecm_faileddcw( ecm );
				// Send DCW to Cache if not sent
				if ( cs->option.fallowcache && cs->option.cachesendrep && (ecm->cachestatus!=ECM_CACHE_REP) ) {
					//pipe_send_cache_reply(ecm,cs); // Send failed Cache Reply
					ecm->cachestatus = ECM_CACHE_REP;
				}
			}
			else ecm->checktime = ecm->recvtime + cs->option.dcw.timeout*ecm->period;
		}
		// Check for ECM TimeOut
		else if ( (ticks-ecm->recvtime) >= cs->option.dcw.timeout*ecm->period ) {
			ecm->statusmsg = "Decode failed, dcw timeout";
			ecm_faileddcw( ecm );
			// Send DCW to Cache if not sent
			if ( cs->option.fallowcache && cs->option.cachesendrep && (ecm->cachestatus!=ECM_CACHE_REP) ) {
				//pipe_send_cache_reply(ecm,cs); // Send failed Cache Reply
				ecm->cachestatus = ECM_CACHE_REP;
			}
		}
		// Check for ECM sending
		else if ( (ticks-ecm->recvtime) <= (cs->option.server.timeout*ecm->period) ) { // ~ cfg.cardserver.option.dcw.timeout*2/3 is the cardserver timeout
			// Check for cache request
			if ( (ecm->cachestatus==ECM_CACHE_NONE) && cs->option.fallowcache && cs->option.cachesendreq ) {
				pipe_cache_request(ecm,cs);
				ecm->cachestatus = ECM_CACHE_REQ;
			}
			// check for decode failed with no remaining server to wait, send to new cardserver
			if ( !ecm->server_totalwait
				|| (cs->option.server.first>ecm->server_totalsent)
				|| ((ticks-ecm->lastsendtime)>=cs->option.server.interval)
			) {
				//mlogf(LOGDEBUG,0," check_sendecm[%s] ch %04x:%06x:%04x\n", cs->name,ecm->caid,ecm->provid,ecm->sid);
				struct server_data *newsrv = NULL;
				if ( srvtab_arrange(cs, ecm, ecm->server_totalsent > 0 )==-1 ) { // No more servers to decode
					//mlogf(LOGDEBUG,0," sendecm: no servers found to decode\n");
/*#ifdef PUBLIC
					if (!ecm->server_totalwait) {
						ecm->statusmsg = "Decode failed, No servers found to decode";
						ecm_faileddcw( ecm );
						// Send DCW to Cache if not sent
						if ( cs->option.fallowcache && cs->option.cachesendrep && (ecm->cachestatus!=ECM_CACHE_REP) ) {
							//pipe_send_cache_reply(ecm,cs); //Send Failed Cache Reply
							ecm->cachestatus=ECM_CACHE_REP;
						}
					}
					else
#endif   */
					ecm->checktime = ecm->recvtime + cs->option.dcw.timeout*ecm->period;
					return;
				}
				else if (psrvlist[0] && psrvlist[0]->srv) {
					// SEND ECM
					newsrv = psrvlist[0]->srv;
					newsrv->busycard = psrvlist[0]->card; // dont save pointers!!!
					newsrv->busycardid = psrvlist[0]->shareid;
					//mlogf(LOGDEBUG,0," sendecm: selected server to decode (%s:%d)\n", newsrv->host->name, newsrv->port);
					if (newsrv->type==TYPE_NEWCAMD) {
						if (cs_sendecm_srv(cs, newsrv, ecm)>0) {
							ecm->lastsendtime = ticks;
							mlogf(LOGINFO,getdbgflagpro(DBG_SERVER,0,newsrv->id,cs->id)," -> ecm to Newcamd server%d (%s:%d) ch %04x:%06x:%04x:%08x\n",(1+ecm->server_totalsent),newsrv->host->name,newsrv->port,ecm->caid,ecm->provid,ecm->sid,ecm->hash);
							newsrv->lastecmtime = ticks;
							newsrv->ecmnb++;
							newsrv->busy=1;
							newsrv->ecm.request = ecm;
							newsrv->ecm.hash = ecm->hash;
							newsrv->retry=0;
							ecm_addsrv(ecm, newsrv->id);
							ecm_addsrvip(ecm, newsrv->host->ip);
						}
					}
#ifdef CCCAM_CLI
					else if (newsrv->type==TYPE_CCCAM) {
						if (cc_sendecm_srv(newsrv, ecm)>0) {
							ecm->lastsendtime = ticks;
							mlogf(LOGINFO,getdbgflagpro(DBG_SERVER,0,newsrv->id,cs->id)," -> ecm to CCcam server%d (%s:%d) ch %04x:%06x:%04x:%08x\n",(1+ecm->server_totalsent),newsrv->host->name,newsrv->port,ecm->caid,ecm->provid,ecm->sid,ecm->hash);
							newsrv->lastecmtime = ticks;
							newsrv->ecmnb++;
							struct cs_card_data *card = cc_getcardbyid( newsrv, newsrv->busycardid );
							if (card) card->ecmnb++;
							newsrv->busy=1;
							newsrv->ecm.request = ecm;
							newsrv->ecm.hash = ecm->hash;
							newsrv->retry=0;
							ecm_addsrv(ecm, newsrv->id);
							ecm_addsrvip(ecm, newsrv->host->ip);
						}
					}
#endif

#ifdef RADEGAST_CLI
					else if (newsrv->type==TYPE_RADEGAST) {
						if (rdgd_sendecm_srv(newsrv, ecm)>0) {
							ecm->lastsendtime = ticks;
							mlogf(LOGINFO,getdbgflagpro(DBG_SERVER,0,newsrv->id,cs->id)," -> ecm to Radegast server%d (%s:%d) ch %04x:%06x:%04x:%08x\n",(1+ecm->server_totalsent),newsrv->host->name,newsrv->port,ecm->caid,ecm->provid,ecm->sid,ecm->hash);
							newsrv->lastecmtime = ticks;
							newsrv->ecmnb++;
							newsrv->busy=1;
							newsrv->ecm.request = ecm;
							newsrv->ecm.hash = ecm->hash;
							newsrv->retry=0;
							ecm_addsrv(ecm, newsrv->id);
							ecm_addsrvip(ecm, newsrv->host->ip);
						}
					}
#endif
#ifdef CAMD35_CLI
					else if (newsrv->type==TYPE_CAMD35) {
						if (camd35_sendecm_srv(newsrv, ecm)>0) {
							ecm->lastsendtime = ticks;
							mlogf(LOGINFO,getdbgflagpro(DBG_SERVER,0,newsrv->id,cs->id)," -> ecm to camd35 server%d (%s:%d) ch %04x:%06x:%04x:%08x\n",(1+ecm->server_totalsent),newsrv->host->name,newsrv->port,ecm->caid,ecm->provid,ecm->sid,ecm->hash);
							newsrv->lastecmtime = ticks;
							newsrv->ecmnb++;
							newsrv->busy=1;
							newsrv->ecm.request = ecm;
							newsrv->ecm.hash = ecm->hash;
							newsrv->retry=0;
							ecm_addsrv(ecm, newsrv->id);
							ecm_addsrvip(ecm, newsrv->host->ip);
						}
					}
#endif
#ifdef CS378X_CLI
					else if (newsrv->type==TYPE_CS378X) {
						if (cs378x_sendecm_srv(newsrv, ecm)>0) {
							ecm->lastsendtime = ticks;
							mlogf(LOGINFO,getdbgflagpro(DBG_SERVER,0,newsrv->id,cs->id)," -> ecm to cs378x server%d (%s:%d) ch %04x:%06x:%04x:%08x\n",(1+ecm->server_totalsent),newsrv->host->name,newsrv->port,ecm->caid,ecm->provid,ecm->sid,ecm->hash);

							newsrv->lastecmtime = ticks;
							newsrv->ecmnb++;
							newsrv->busy=1;
							newsrv->ecm.request = ecm;
							newsrv->ecm.hash = ecm->hash;
							newsrv->retry=0;
							ecm_addsrv(ecm, newsrv->id);
							ecm_addsrvip(ecm, newsrv->host->ip);
						}
					}
#endif
					ecm->statusmsg = "Waiting for servers...";
					if ( cs->option.server.first > (ecm->server_totalsent+1) ) ecm->checktime = ticks + 10;
					else {
						ecm->checktime = ticks + cs->option.server.interval;
						if ( (ecm->checktime-ecm->recvtime) > (cs->option.server.timeout*ecm->period) ) ecm->checktime = ecm->recvtime + cs->option.dcw.timeout*ecm->period;
					}
				}
				else {
					ecm->statusmsg = "Wait for available servers";

					//mlogf(LOGDEBUG, getdbgflag(DBG_NEWCAMD,cs->id,0), " check_sendecm[%s] ch %04x:%06x:%04x, Wait for available server...\n", cs->name,ecm->caid,ecm->provid,ecm->sid);

					// PROBLEM HERE ??????
					ecm->waitserver = 1; // XXX
					ecm->checktime = ecm->recvtime + cs->option.dcw.timeout*ecm->period; // till the end if there is no server

#ifdef BUSY_SERVER
					if (!ecm->server_totalwait && !ecm->server_totalsent) {
						ecm->statusmsg = "Decode failed, no free server";
						ecm_faileddcw( ecm );
						cs->ecmbusysrv++;
					}
#endif
					return;
				}
			}
			else {
				ecm->checktime = ecm->lastsendtime + cs->option.server.interval;
				if ( (ecm->checktime-ecm->recvtime) > (cs->option.server.timeout*ecm->period) ) ecm->checktime = ecm->recvtime + cs->option.dcw.timeout*ecm->period;
			}
		}
#ifndef PUBLIC
		else if (!ecm->server_totalwait) {
			ecm->statusmsg = "Decode failed, no server open this channel";
			ecm_faileddcw( ecm );
			// Send DCW to Cache if not sent
			if ( cs->option.fallowcache && cs->option.cachesendrep && (ecm->cachestatus!=ECM_CACHE_REP) ) {
				//pipe_send_cache_reply(ecm,cs); //Send Failed Cache Reply
				ecm->cachestatus = ECM_CACHE_REP;
			}
		}
		else if ( cs->option.fallowcache && cs->option.cacheresendreq && (ecm->cachestatus==ECM_CACHE_REQ) ) {
			pipe_cache_resendreq(ecm, cs);
			ecm->cachestatus = ECM_CACHE_REQ2;
			ecm->checktime = ecm->recvtime + cs->option.dcw.timeout*ecm->period;
		}
#endif
		else ecm->checktime = ecm->recvtime + cs->option.dcw.timeout*ecm->period;
	}
}

inline void check_sendecm(int newserver)
{
	uint32_t ticks = GetTickCount();
	struct ecm_request *req = ecmdata;
	while (req) {
		if ( (req->recvtime+TIME_ECMALIVE) < ticks ) break;

		if (req->checktime) { // (checktime==0) --> do nothing
			if ( (req->checktime < ticks) || (req->waitserver && newserver) ) {
				check_ecm(req, ticks);
				ticks = GetTickCount();
			}
		}

		req = req->next;
		if (req==ecmdata) break;
	}
}

/// recalculate ecmcheck wakeup time
uint32_t getecmwakeuptime()
{
	uint32_t ticks = GetTickCount();
	uint32_t waketime = ticks+10000;
	struct ecm_request *req = ecmdata;
	while (req) {
		if ( (req->recvtime+TIME_ECMALIVE) < ticks ) break;

		if ( req->checktime )
		if ( waketime > req->checktime ) waketime = req->checktime;

		req = req->next;
		if (req==ecmdata) break;
	}
	return waketime;
}


///////////////////////////////////////////////////////////////////////////////
// CACHE PIPE RECV MESSAGES
///////////////////////////////////////////////////////////////////////////////
int newserver = 0;

void recv_ecm_pipe()
{
	uint8_t buf[1024];
	struct cache_data req;
	uint8_t cw[16];
	int peerid;

	ECM_DATA *ecm;
	struct pollfd pfd;

	do {
		int len = pipe_recv( prg.pipe.ecm[0], buf);
		if (len>0) {
			switch(buf[0]) {

				case PIPE_WAKEUP:
					break;

				case PIPE_LOCK:
					pthread_mutex_lock(&prg.lockmain);
					pthread_mutex_unlock(&prg.lockmain);
					break;

				case PIPE_CACHE_FIND_FAILED:
					get_cache2ecm(buf, &req, NULL);
					pthread_mutex_lock(&prg.lockecm);
					ecm = req.ecm; //search_ecmdata_byhash( req.caid, req.sid, req.hash );
					if (ecm) {
						if ( (ecm->caid==req.caid)&&(ecm->hash==req.hash)&&(ecm->sid==req.sid)&&(ecm->dcwstatus==STAT_DCW_WAITCACHE) ) {
#ifndef PUBLIC
							struct cardserver_data *cs = ecm->cs;
							if ( cs && (!cs->option.cachestatic) )
#endif
							ecm->dcwstatus = STAT_DCW_WAIT;
							ecm->checktime = ecm->recvtime;
						}
					}
					pthread_mutex_unlock(&prg.lockecm);
					break;

				case PIPE_CACHE_FIND_SUCCESS:  // SET DCW
					peerid = get_cache2ecm(buf, &req, cw);
					pthread_mutex_lock(&prg.lockecm);
					ecm = req.ecm; //search_ecmdata_byhash( req.caid, req.sid, req.hash );
					if (ecm) {
						if ( (ecm->caid==req.caid)&&(ecm->hash==req.hash)&&(ecm->sid==req.sid) ) {
							struct cardserver_data *cs = ecm->cs;
							if (cs && cs->option.fallowcache) {
                                        			int isnanoe0=ecm_isnanoe0(ecm->ecm,ecm->caid);
                                        			if (!acceptDCW(cw, isnanoe0)) {
                                                			mlogf(LOGDEBUG,0," [!] dcw error from cachepeer %d, bad dcw!!! ch %04x:%06x:%04x nanoe0=%d\n",peerid,ecm->caid, ecm->provid, ecm->sid, isnanoe0);
								}
								else
									ecm_setdcw( ecm, cw, DCW_SOURCE_CACHE, peerid );
							}
						}
					}
					pthread_mutex_unlock(&prg.lockecm); 
					break;

				case PIPE_SRV_CONNECTED:
					newserver = 1;
#ifdef EPOLL_ECM
					struct server_data *srv;
					memcpy( &srv, buf+1, sizeof(void*) );
					// Add to events
					struct epoll_event ev; // epoll event
					ev.events = EPOLLIN;
					ev.data.fd = srv->handle;
					ev.data.ptr = srv;
					if ( epoll_ctl(prg.epoll.ecm, EPOLL_CTL_ADD, srv->handle, &ev) == -1 ) mlogf(LOGERROR,DBG_ERROR,"Err! EPOLL_CTL_ADD %s (%d)\n", srv->user, srv->handle);
					//else mlogf(LOGDEBUG,0,"EPOLL_CTL_ADD %s (%d)\n", cli->user, cli->handle);
#endif
					break;

				case PIPE_SRV_AVAILABLE:
					newserver = 1;
					break;
			}
		}

		pfd.fd = prg.pipe.ecm[0];
		pfd.events = POLLIN | POLLPRI;
	} while ( poll(&pfd, 1, 0)>0 );
}


///////////////////////////////////////////////////////////////////////////////
// RECEIVE MESSAGES THREAD
///////////////////////////////////////////////////////////////////////////////


inline void srv_recvmsg( struct server_data *srv )
{
	if (srv->type==TYPE_NEWCAMD) cs_srv_recvmsg(srv);
#ifdef CCCAM_CLI
	else if (srv->type==TYPE_CCCAM) cc_srv_recvmsg(srv);
#endif
#ifdef RADEGAST_CLI
	else if (srv->type==TYPE_RADEGAST) rdgd_srv_recvmsg(srv);
#endif
#ifdef CAMD35_CLI
	else if (srv->type==TYPE_CAMD35) camd35_srv_recvmsg(srv);
#endif
#ifdef CS378X_CLI
	else if (srv->type==TYPE_CS378X) cs378x_srv_recvmsg(srv);
#endif
}


#ifdef EPOLL_ECM

void *recv_msg_thread(void *param)
{
#ifndef PUBLIC
	prg.pid_msg = syscall(SYS_gettid);
	prg.tid_msg = pthread_self();
	prctl(PR_SET_NAME,"ECM Thread",0,0,0);
#endif

	struct epoll_event evlist[MAX_EPOLL_EVENTS]; // epoll recv events
	prg.epoll.ecm = epoll_create( MAX_EPOLL_EVENTS );

	// Add PIPE
	struct epoll_event ev; // epoll event
	ev.events = EPOLLIN | EPOLLPRI | EPOLLRDHUP;
	ev.data.ptr = NULL;
	if ( epoll_ctl( prg.epoll.ecm, EPOLL_CTL_ADD, prg.pipe.ecm[0], &ev) == -1 ) mlogf(LOGERROR,0,"epoll_ctl ecm recv_msg_thread error -1\n");

	while (!prg.restart) {
		newserver = 0;
		// getmintime
		uint32_t mintime = ecm_check_time;
		uint32_t ticks = GetTickCount();
		uint32_t ms;
		if (mintime>(ticks+10)) ms = mintime-ticks; else ms = 10;

		int ready = epoll_wait( prg.epoll.ecm, evlist, MAX_EPOLL_EVENTS, ms);
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

		int i;
		for (i=0; i < ready; i++) {
			if ( evlist[i].events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR) ) { // EPOLLRDHUP
				if (evlist[i].data.ptr == NULL) mlogf(LOGERROR,DBG_ERROR,"Err! epoll_wait() pipe\n"); // error !!!
				else disconnect_srv(evlist[i].data.ptr);
			}
			else if ( evlist[i].events & (EPOLLIN|EPOLLPRI) ) {
				if (evlist[i].data.ptr == NULL) recv_ecm_pipe();
				else {
					pthread_mutex_lock(&prg.locksrv);
					srv_recvmsg(evlist[i].data.ptr);
					pthread_mutex_unlock(&prg.locksrv);
				}
			}
		}

		pthread_mutex_lock(&prg.locksrv);
		pthread_mutex_lock(&prg.lockecm);
		check_sendecm( newserver );
		ecm_check_time = getecmwakeuptime();
		pthread_mutex_unlock(&prg.lockecm);
		pthread_mutex_unlock(&prg.locksrv);

		usleep(cfg.delay.thread);
	}
	return NULL;
}

#else

void *recv_msg_thread(void *param)
{
	struct pollfd pfd[MAX_PFD];
	int pfdcount;

#ifndef PUBLIC
	prg.pid_msg = syscall(SYS_gettid);
	prg.tid_msg = pthread_self();
	prctl(PR_SET_NAME,"ECM Thread",0,0,0);
#endif

	while (!prg.restart) {
		// getmintime
		uint32_t mintime = ecm_check_time;
		newserver = 0;

		uint32_t ticks = GetTickCount();
		uint32_t ms;
		if (mintime>(ticks+10)) ms = mintime-ticks; else ms = 10;

		pfdcount = 0;

		// Cache Data// Clients/Servers WakeUP
		pfd[pfdcount].fd = prg.pipe.ecm[0];
		pfd[pfdcount++].events = POLLIN | POLLPRI;

		//Servers
		struct server_data *srv = cfg.server;
		while (srv && (pfdcount<SERVER_MAX_PFD)) {
			if ( !IS_DISABLED(srv->flags)&&(srv->handle>0) ) {
				srv->ipoll = pfdcount;
				pfd[pfdcount].fd = srv->handle;
				pfd[pfdcount++].events = POLLIN | POLLPRI;
			} else srv->ipoll = -1;
			srv = srv->next;
		}

		int retval = poll(pfd, pfdcount, ms);


		if ( retval>0 ) {
			/// SERVERS
			pthread_mutex_lock(&prg.locksrv);
			struct server_data *srv = cfg.server;
			while (srv) {
				if ( !IS_DISABLED(srv->flags)&&(srv->handle>0)&&(srv->ipoll>=0)&&(srv->handle==pfd[srv->ipoll].fd) ) {
					if ( pfd[srv->ipoll].revents & (POLLHUP|POLLNVAL) ) disconnect_srv(srv);
					else if ( pfd[srv->ipoll].revents & (POLLIN|POLLPRI) ) srv_recvmsg(srv);
				}
				srv = srv->next;
			}
			pthread_mutex_unlock(&prg.locksrv);
			//
			if ( pfd[0].revents & (POLLIN|POLLPRI) ) recv_ecm_pipe();
		}
		else if ( (retval<0) && (errno!=EINTR) ) {
			mlogf(LOGERROR,0," thread receive messages: poll error %d(errno=%d)\n", retval, errno);
			usleep(91000);
		}

		pthread_mutex_lock(&prg.locksrv);
		pthread_mutex_lock(&prg.lockecm);
		check_sendecm( newserver );
		ecm_check_time = getecmwakeuptime();
		pthread_mutex_unlock(&prg.lockecm);
		pthread_mutex_unlock(&prg.locksrv);

		usleep(cfg.delay.thread*2);
	}
	return NULL;
}

#endif


// Check for keepalive with servers/clients
void *thread_keepalive(void *param)
{
	while (1) {
		sleep(5);
		uint32_t ticks = GetTickCount();


		// Check Servers
		struct server_data *srv = cfg.server;
		while (srv) {
			if ( !IS_DISABLED(srv->flags)&&(srv->connection.status>0) ) {
				if (srv->type==TYPE_NEWCAMD) cs_check_keepalive(srv);

				else if (srv->type==TYPE_CCCAM) {
					if ( !srv->keepalive.status && ((srv->keepalive.time+75000)<ticks) ) {
						srv->keepalive.status = 1; // Sent and waiting for reply
						srv->keepalive.time = ticks;
						if ( !cc_msg_send( srv->handle, &srv->sendblock, CC_MSG_KEEPALIVE, 0, NULL) ) disconnect_srv( srv );
					}
				}

#ifdef CAMD35_CLI
				else if (srv->type==TYPE_CAMD35) {
					if ( !srv->keepalive.status && ((srv->keepalive.time+30000)<ticks) ) {
						camd35_send_keepalive(srv);
						srv->keepalive.status = 1; // Sent and waiting for reply
						srv->keepalive.time = ticks;
					}
					else if ( (srv->keepalive.status==1) && ((srv->keepalive.time+10000)<ticks) ) {
						camd35_send_keepalive(srv);
						srv->keepalive.status = 2;
						srv->keepalive.time = ticks;
					}
					else if ( (srv->keepalive.status>1) && ((srv->keepalive.time+10000)<ticks) ) {
						mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," ??? no keepalive response from camd35 server (%s:%d)\n",srv->host->name,srv->port);
						disconnect_srv( srv );
					}
				}
#endif
			}
			srv = srv->next;
		}


		// Check Cacheex Servers
		srv = cfg.cacheexserver;
		while (srv) {
			if ( !IS_DISABLED(srv->flags)&&(srv->connection.status>0) ) {
				if (srv->type==TYPE_CCCAM) {
					if ( !srv->keepalive.status && ((srv->keepalive.time+75000)<ticks) ) {
						srv->keepalive.status = 1; // Sent and waiting for reply
						srv->keepalive.time = ticks;
						if ( !cc_msg_send( srv->handle, &srv->sendblock, CC_MSG_KEEPALIVE, 0, NULL) ) disconnect_srv( srv );
					}
				}

#ifdef CAMD35_CLI
				else if (srv->type==TYPE_CAMD35) {
					if ( !srv->keepalive.status && ((srv->keepalive.time+30000)<ticks) ) {
						camd35_send_keepalive(srv);
						srv->keepalive.status = 1; // Sent and waiting for reply
						srv->keepalive.time = ticks;
					}
					else if ( (srv->keepalive.status==1) && ((srv->keepalive.time+10000)<ticks) ) {
						camd35_send_keepalive(srv);
						srv->keepalive.status = 2;
						srv->keepalive.time = ticks;
					}
					else if ( (srv->keepalive.status>1) && ((srv->keepalive.time+10000)<ticks) ) {
						mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," ??? no keepalive response from camd35 server (%s:%d)\n",srv->host->name,srv->port);
						disconnect_srv( srv );
					}
				}
#endif
			}
			srv = srv->next;
		}


#ifdef CAMD35_SRV
		sleep(1);
		// Check camd35 Clients
		ticks = GetTickCount();
		struct camd35_server_data *camd35 = cfg.camd35.server;
		while (camd35) {
			struct camd35_client_data *cli = camd35->client;
			while (cli) {
				if (cli->connection.status>0) {
					if ( (cli->lastactivity+300000) < ticks) {
						camd35_disconnect_cli(cli);
					}
				}
				cli = cli->next;
			}
			camd35 = camd35->next;
		}
#endif

	}
}


int start_thread_recv_msg()
{
	create_thread(&prg.tid_msg, (threadfn)recv_msg_thread,NULL);
	create_thread(&prg.tid_msg, (threadfn)thread_keepalive,NULL);
#ifdef THREAD_DCW
	create_thread(&prg.tid_msg, (threadfn)setdcw_thread,NULL);
#endif
	return 0;
}

