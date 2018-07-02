
///////////////////////////////////////////////////////////////////////////////
// TOOL
///////////////////////////////////////////////////////////////////////////////


inline int acceptshare( struct sharelimit_data sharelimits[100], uint16_t caid, uint32_t provid)
{
	int i;
	if (sharelimits[0].caid==0xffff) return 1;
	for (i=0; i<100; i++) {
		if (sharelimits[i].caid==0xffff) break;
		if (sharelimits[i].caid==caid) {
			if (sharelimits[i].provid==provid) return 1;
			else if (sharelimits[i].provid==0xFFFFFF) return 1;
		}
	}
	return 0;
}


///////////////////////////////////////////////////////////////////////////////
// TOOL
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// pipe --> cacheex
///////////////////////////////////////////////////////////////////////////////

int pipe_send_cacheex_push_out(ECM_DATA *ecm)
{
	uint8_t buf[128];
	buf[0] = PIPE_CACHEEX_PUSH_LOCAL;
	buf[1] = (ecm->caid)>>8; buf[2] = (ecm->caid)&0xff;
	buf[3] = ecm->ecm[0];
	buf[4] = ecm->provid>>16; buf[5] = ecm->provid>>8; buf[6] = ecm->provid & 0xff;
	buf[7] = (ecm->sid)>>8; buf[8] = (ecm->sid)&0xff;
	buf[9] = ecm->hash>>24; buf[10] = ecm->hash>>16; buf[11] = ecm->hash>>8; buf[12] = ecm->hash & 0xff;
	memcpy(buf+13, ecm->ecmd5, 16);
	memcpy(buf+29, ecm->cw, 16);
	pipe_send( prg.pipe.cacheex[1], buf, 45);
	return 1;
}

int pipe_send_cacheex_push_cache(struct cache_data *pcache, uint8_t *cw, uint8_t *nodeid)
{
	uint8_t buf[128];
	buf[0] = PIPE_CACHEEX_PUSH_REMOTE;
	buf[1] = (pcache->caid)>>8; buf[2] = (pcache->caid)&0xff;
	buf[3] = pcache->tag;
	buf[4] = pcache->provid>>16; buf[5] = pcache->provid>>8; buf[6] = pcache->provid & 0xff;
	buf[7] = (pcache->sid)>>8; buf[8] = (pcache->sid)&0xff;
	buf[9] = pcache->hash>>24; buf[10] = pcache->hash>>16; buf[11] = pcache->hash>>8; buf[12] = pcache->hash & 0xff;
	memcpy(buf+13, pcache->ecmd5, 16);
	memcpy(buf+29, cw, 16);
	memcpy( buf+29+16, nodeid, 8);
	pipe_send( prg.pipe.cacheex[1], buf, 29+16+8);
	return 1;
}

int pipe_send_cacheex_push_in(struct cache_data *pcache, uint8_t cw[16], int clid, int hop)
{
	uint8_t buf[128];
	buf[0] = PIPE_CACHEEX_PUSH_IN;
	buf[1] = (pcache->caid)>>8; buf[2] = (pcache->caid)&0xff;
	buf[3] = pcache->tag;
	buf[4] = pcache->provid>>16; buf[5] = pcache->provid>>8; buf[6] = pcache->provid & 0xff;
	buf[7] = (pcache->sid)>>8; buf[8] = (pcache->sid)&0xff;
	buf[9] = pcache->hash>>24; buf[10] = pcache->hash>>16; buf[11] = pcache->hash>>8; buf[12] = pcache->hash & 0xff;
	memcpy(buf+13, pcache->ecmd5, 16);
	memcpy(buf+29, cw, 16);
	buf[45] = clid>>8;
	buf[46] = clid;
	buf[47] = hop;
	pipe_send( prg.pipe.cacheex[1], buf, 48);
	return 1;
}

///////////////////////////////////////////////////////////////////////////////
// PUSH OUT 
///////////////////////////////////////////////////////////////////////////////

inline int get_cccam_cacheex_push(struct cache_data *pcache, uint8_t cw[16], uint8_t *buf, uint8_t *nodeid )
{
	memset(buf, 0, 57+8 );

	buf[0] = pcache->caid>>8;
	buf[1] = pcache->caid;

	buf[2] = pcache->provid>>24;
	buf[3] = pcache->provid>>16;
	buf[4] = pcache->provid>>8;
	buf[5] = pcache->provid;

	buf[10] = pcache->sid>>8;
	buf[11] = pcache->sid;

	buf[12] = 0x24; // ( 16 + 4 + 16 )
	buf[13] = 0;

	buf[14] = 0;

	buf[19] = pcache->tag;

	memcpy(buf+20, pcache->ecmd5, 16);
	buf[36] = pcache->hash;
	buf[37] = pcache->hash >> 8;
	buf[38] = pcache->hash >> 16;
	buf[39] = pcache->hash >> 24; 
	memcpy(buf+40, cw, 16);
	if (nodeid) {
		buf[56] = 2;
		memcpy(buf+57, cfg.nodeid, 8 );
		memcpy(buf+57+8, nodeid, 8 );
		return 57+8+8;
	}
	buf[56] = 1; // Uphops = 1 (local)
	memcpy(buf+57, cfg.nodeid, 8 );
	return 57+8;
}

inline int get_camd35_cacheex_push(struct cache_data *pcache, uint8_t cw[16], uint8_t *buf, uint8_t *nodeid )
{
	memset(buf, 0, 57+8 );
	buf[0] = 0x3F;
	buf[1] = 57+8-20;

	buf[8] = pcache->sid>>8;
	buf[9] = pcache->sid;

	buf[10] = pcache->caid>>8;
	buf[11] = pcache->caid;

	buf[12] = pcache->provid>>24;
	buf[13] = pcache->provid>>16;
	buf[14] = pcache->provid>>8;
	buf[15] = pcache->provid;

	buf[19] = pcache->tag;

	memcpy(buf+20, pcache->ecmd5, 16);
	buf[36] = pcache->hash;
	buf[37] = pcache->hash >> 8;
	buf[38] = pcache->hash >> 16;
	buf[39] = pcache->hash >> 24; 
	memcpy(buf+40, cw, 16);
	if (nodeid) {
		buf[1] += 8;
		buf[56] = 2;
		memcpy(buf+57, cfg.nodeid, 8 );
		memcpy(buf+57+8, nodeid, 8 );
		return 57+8+8;
	}
	buf[56] = 1; // Uphops = 1 (local)
	memcpy(buf+57, cfg.nodeid, 8 );
	return 57+8;
}

inline void cacheex_push(struct cache_data *pcache, uint8_t cw[16], uint8_t *nodeid )
{
	uint8_t camd35buf[128];
	int camd35len = get_camd35_cacheex_push( pcache, cw, camd35buf, nodeid );
	uint8_t cccambuf[128];
	int cccamlen = get_cccam_cacheex_push( pcache, cw, cccambuf, nodeid );

	// PUSH TO SERVERS cacheex=3
	struct server_data *srv = cfg.cacheexserver;
	while (srv) {
		//mlogf(LOGDEBUG,getdbgflag(DBG_CACHEEX, 0, 0)," CACHEEX PUSH to server (%s:%d) %04x:%06x:%04x:%08x\n",srv->host->name, srv->port,pcache->caid,pcache->provid,pcache->sid,pcache->hash); debughex(cw,16);
		if ( (srv->cacheex_mode==3) && (srv->connection.status>0) )
		if ( acceptshare(srv->sharelimits, pcache->caid, pcache->provid) ) {
			if (srv->type==TYPE_CCCAM) {
				if ( !cc_msg_send( srv->handle, &srv->sendblock, CC_MSG_CACHE_PUSH, cccamlen, cccambuf) ) disconnect_srv(srv);
			}
#ifdef CAMD35_CLI
			else if (srv->type==TYPE_CAMD35) camd35_sendto( srv->handle, srv->host->ip, srv->port, &srv->encryptkey, srv->ucrc, camd35buf, camd35len);
#endif
#ifdef CS378X_CLI
			else if (srv->type==TYPE_CS378X) {
				if ( !cs378x_send( srv->handle, &srv->encryptkey, srv->ucrc, camd35buf, camd35len) )  disconnect_srv(srv);
			}
#endif
			srv->cacheex.push[0]++;
			if (nodeid) srv->cacheex.push[2]++; else srv->cacheex.push[1]++;
		}
		srv = srv->next;
	}

#ifdef CCCAM_SRV
	// PUSH TO CCCAM CLIENTS cacheex=2
	struct cccam_server_data *cccam = cfg.cccam.server;
	while (cccam) {
		struct cc_client_data *cli = cccam->cacheexclient;
		while (cli) {
			if ( (cli->cacheex_mode==2) && (cli->connection.status>0) )
			if ( acceptshare(cli->sharelimits, pcache->caid, pcache->provid) ) {
				if ( !cc_msg_send( cli->handle, &cli->sendblock, CC_MSG_CACHE_PUSH, cccamlen, cccambuf) ) cc_disconnect_cli(cli);
				cli->cacheex.push[0]++;
				if (nodeid) cli->cacheex.push[2]++; else cli->cacheex.push[1]++;
				//mlogf(LOGDEBUG,getdbgflag(DBG_CACHEEX, 0, 0)," CACHEEX PUSH to client %04x:%06x:%04x:%08x\n",pcache->caid,pcache->provid,pcache->sid,pcache->hash);// debughex(req.cw,16);
			}
			cli = cli->next;
		}
		cccam = cccam->next;
	}
#endif

#ifdef CAMD35_SRV
	// PUSH TO CAMD35 CLIENTS cacheex=2
	struct camd35_server_data *camd35 = cfg.camd35.server;
	while (camd35) {
		struct camd35_client_data *cli = camd35->cacheexclient;
		while (cli) {
			if ( (cli->cacheex_mode==2) && (cli->connection.status>0) )
			if ( !nodeid || memcmp(nodeid, cli->nodeid, 8) )
			if ( acceptshare(cli->sharelimits, pcache->caid, pcache->provid) ) {
				camd35_sendto( camd35->handle, cli->ip, cli->port, &cli->encryptkey, cli->ucrc, camd35buf, camd35len);
				cli->cacheex.push[0]++;
				if (nodeid) cli->cacheex.push[2]++; else cli->cacheex.push[1]++;
				//mlogf(LOGDEBUG,getdbgflag(DBG_CACHEEX, 0, 0)," CACHEEX PUSH to client %04x:%06x:%04x:%08x\n",pcache->caid,pcache->provid,pcache->sid,pcache->hash);// debughex(req.cw,16);
			}
			cli = cli->next;
		}
		camd35 = camd35->next;
	}
#endif

#ifdef CS378X_SRV
	// PUSH TO CS378X CLIENTS cacheex=2
	struct camd35_server_data *cs378x = cfg.cs378x.server;
	while (cs378x) {
		struct camd35_client_data *cli = cs378x->cacheexclient;
		while (cli) {
			if ( (cli->cacheex_mode==2) && (cli->connection.status>0) )
			if ( !nodeid || memcmp(nodeid, cli->nodeid, 8) )
			if ( acceptshare(cli->sharelimits, pcache->caid, pcache->provid) ) {
				if ( !cs378x_send( cli->handle, &cli->encryptkey, cli->ucrc, camd35buf, camd35len) ) cs378x_disconnect_cli(cli);
				cli->cacheex.push[0]++;
				if (nodeid) cli->cacheex.push[2]++; else cli->cacheex.push[1]++;
				//mlogf(LOGDEBUG,getdbgflag(DBG_CACHEEX, 0, 0)," CACHEEX PUSH to client %04x:%06x:%04x:%08x\n",pcache->caid,pcache->provid,pcache->sid,pcache->hash);// debughex(req.cw,16);
			}
			cli = cli->next;
		}
		cs378x = cs378x->next;
	}
#endif

}



void cacheex_pipe_recvmsg()
{
	uint8_t buf[512];
	uint8_t cw[16];
	struct cache_data req;
	struct pollfd pfd;

	do {
		int len =  pipe_recv( prg.pipe.cacheex[0], buf );
		if (len>0) {
			//mlogf(LOGDEBUG,getdbgflag(DBG_CACHEEX, 0, 0)," Recv from CacheEX Pipe\n"); debughex(buf,len);
			switch(buf[0]) {
				case PIPE_WAKEUP:  // ADD NEW CLIENT
					break;

				case PIPE_CACHEEX_PUSH_LOCAL: // from local
					// Setup Cache Request
					req.caid = (buf[1]<<8) | buf[2];
					req.tag = buf[3];
					req.provid = (buf[4]<<16) | (buf[5]<<8) | (buf[6]);
					req.sid = (buf[7]<<8) | buf[8];
					req.hash = (buf[9]<<24) | (buf[10]<<16) | (buf[11]<<8) | (buf[12]);
					memcpy( req.ecmd5, buf+13, 16);
					memcpy( cw, buf+29, 16);
					//mlogf(LOGDEBUG,getdbgflag(DBG_CACHEEX, 0, 0)," PIPE_CACHEEX_PUSH_OUT %04x:%06x:%04x:%08x\n", req.caid,req.provid,req.sid,req.hash);
					// Send Reply
					cfg.cacheex.rep++;
					cacheex_push( &req, cw, NULL );
					break;

				case PIPE_CACHEEX_PUSH_REMOTE: // from cacheex peers
					// Setup Cache Request
					req.caid = (buf[1]<<8) | buf[2];
					req.tag = buf[3];
					req.provid = (buf[4]<<16) | (buf[5]<<8) | (buf[6]);
					req.sid = (buf[7]<<8) | buf[8];
					req.hash = (buf[9]<<24) | (buf[10]<<16) | (buf[11]<<8) | (buf[12]);
					memcpy( req.ecmd5, buf+13, 16);
					memcpy( cw, buf+29, 16);
					//mlogf(LOGDEBUG,getdbgflag(DBG_CACHEEX, 0, 0)," PIPE_CACHEEX_PUSH_REMOTE %04x:%06x:%04x:%08x\n", req.caid,req.provid,req.sid,req.hash);
					// Send Reply
					cfg.cacheex.rep++;
					cacheex_push( &req, cw, buf+29+16 );
					break;

			}//switch
		}//if

		pfd.fd = prg.pipe.cacheex[0];
		pfd.events = POLLIN | POLLPRI;
	} while ( poll(&pfd, 1, 1)>0 );
}

/*
1 for server>clients
1 for client>servers
*/
///////////////////////////////////////////////////////////////////////////////

inline int cacheex_check( struct cache_data *req )
{
	if ( !req->caid || !req->hash || !req->sid ) return 0;
	if (cfg.cache.caids[0]) {
		int i;
		for(i=0; i<32; i++) {
			if (!cfg.cache.caids[i]) break;
			if (cfg.cache.caids[i]==req->caid) return 1;
		}
		return 0;
	}
	return 1;
}

///////////////////////////////////////////////////////////////////////////////

void *cacheex_recvmsg_thread(void *param)
{
	prg.pid_ccex_msg = syscall(SYS_gettid);

	struct pollfd pfd[CACHEEX_MAX_PFD];
	int pfdcount = 0;
	while(1) {
		pfdcount = 0;

		// Clients mode 2
		struct cccam_server_data *cccam = cfg.cccam.server;
		while (cccam) {
			if ( !IS_DISABLED(cccam->flags)&&(cccam->handle>0) ) {
				struct cc_client_data *cccli = cccam->cacheexclient;
				while (cccli) {
					if (cccli->cacheex_mode==2) {
						if ( !IS_DISABLED(cccli->flags)&&(cccli->handle>0) ) {
							cccli->ipoll = pfdcount;
							pfd[pfdcount].fd = cccli->handle;
							pfd[pfdcount++].events = POLLIN | POLLPRI;
						} else cccli->ipoll = -1;
					}
					cccli = cccli->next;
				}
			}
			cccam = cccam->next;
		}

		// Servers mode 3
		struct server_data *srv = cfg.cacheexserver;
		while (srv) {
			if ( (srv->cacheex_mode==3) && !IS_DISABLED(srv->flags) && (srv->handle>0) ) {
				srv->ipoll = pfdcount;
				pfd[pfdcount].fd = srv->handle;
				pfd[pfdcount++].events = POLLIN | POLLPRI;
			} else srv->ipoll = -1;
			srv = srv->next;
		}

		int retval = poll(pfd, pfdcount, 3005); // for 3seconds

		if ( retval>0 ) {
			if (cfg.delay.thread) usleep(cfg.delay.thread);

			// CCcam Clients - cacheex_mode = 3
			struct cccam_server_data *cccam = cfg.cccam.server;
			while (cccam) {
				if ( !IS_DISABLED(cccam->flags)&&(cccam->handle>0) ) {
					//pthread_mutex_lock(&prg.lockcccli);
					struct cc_client_data *cccli = cccam->cacheexclient;
					while (cccli) {
						if (cccli->cacheex_mode==2) {
							if ( !IS_DISABLED(cccli->flags)&&(cccli->handle>0)&&(cccli->ipoll>=0)&&(cccli->handle==pfd[cccli->ipoll].fd) ) {
								if ( pfd[cccli->ipoll].revents & (POLLHUP|POLLNVAL) ) cc_disconnect_cli(cccli);
								else if ( pfd[cccli->ipoll].revents & (POLLIN|POLLPRI) ) cc_cli_recvmsg(cccli);
							}
						}
						cccli = cccli->next;
					}
					//pthread_mutex_unlock(&prg.lockcccli);
				}
				cccam = cccam->next;
			}

			//Servers
			struct server_data *srv = cfg.cacheexserver;
			while (srv) {
				if ( (srv->cacheex_mode==3) && !IS_DISABLED(srv->flags) && (srv->handle>0) )
				if ( (srv->ipoll>=0)&&(srv->handle==pfd[srv->ipoll].fd) ) {
					if ( pfd[srv->ipoll].revents & (POLLIN|POLLPRI) ) {
						if (srv->type==TYPE_CCCAM) cc_srv_recvmsg(srv);
#ifdef CAMD35_CLI
						else if (srv->type==TYPE_CAMD35) camd35_srv_recvmsg(srv);
#endif
#ifdef CS378X_CLI
						else if (srv->type==TYPE_CS378X) cs378x_srv_recvmsg(srv);
#endif
					}
				}
				srv = srv->next;
			}

		}
		else if ( retval<0 ) {
			mlogf(LOGERROR,0," thread receive messages: poll error %d(errno=%d)\n", retval, errno);
		}

	}
	return NULL;
}

void *cacheex_pipe_thread(void *param)
{
	struct pollfd pfd;
	while(1) {
		pfd.fd = prg.pipe.cacheex[0];
		pfd.events = POLLIN | POLLPRI;

		int retval = poll(&pfd, 1, 3015); // for 3seconds

		if ( retval>0 ) {
			cacheex_pipe_recvmsg();
		}
		else if ( retval<0 ) {
			mlogf(LOGERROR,0, " thread receive messages: poll error %d(errno=%d)\n", retval, errno);
		}

	}
	return NULL;
}

int start_thread_cacheex()
{
	//memset( icacheextab, 0, sizeof(icacheextab));
	//create_thread(&prg.tid_cacheex, (threadfn)cacheex_send_thread,NULL);
	create_thread(&prg.tid_cacheex, cacheex_recvmsg_thread,NULL);
	create_thread(&prg.tid_cacheex, cacheex_pipe_thread,NULL);
	return 0;
}

