///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

void camd35_send_keepalive(struct server_data *srv)
{
	uint8_t buf[64];
#ifdef CACHEEX
	if (srv->cacheex_mode) {
		// Request Nodeid
		memset(buf, 0, 32);
		buf[0] = 0x3D;
		buf[1] = 12;
		memcpy( buf+20, cfg.nodeid, 8);
		camd35_sendto( srv->handle, srv->host->ip, srv->port, &srv->encryptkey, srv->ucrc, buf, 20+12);
	}
	else
#endif
	{
		// keepalive
		uint8_t buf[64];
		memset(buf,0, 21);
		buf[0] = 0x37;
		buf[1] = 1;
		camd35_sendto( srv->handle, srv->host->ip, srv->port, &srv->encryptkey, srv->ucrc, buf, 20+1);
	}
}

///////////////////////////////////////////////////////////////////////////////

int camd35_sendecm_srv(struct server_data *srv, ECM_DATA *ecm)
{
	srv->ecm.msgid++;
	if (srv->ecm.msgid>0xfff) srv->ecm.msgid = 1;

	unsigned char buf[1024];
	memset(buf, 0, 20);
	buf[0] = 0; // Command
	buf[1] = 0; // Length
	buf[8] = ecm->sid>>8;
	buf[9] = ecm->sid&0xff;
	buf[10] = ecm->caid>>8;
	buf[11] = ecm->caid&0xff;
	buf[12] = ecm->provid>>24;
	buf[13] = ecm->provid>>16;
	buf[14] = ecm->provid>>8;
	buf[15] = ecm->provid&0xff;
	buf[16] = srv->ecm.msgid>>8;
	buf[17] = srv->ecm.msgid;
	memcpy( buf+20, ecm->ecm, ecm->ecmlen);
	camd35_sendto( srv->handle, srv->host->ip, srv->port, &srv->encryptkey, srv->ucrc, buf, 20+ecm->ecmlen);
	return 1;
}


///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

void camd35_srv_recvmsg(struct server_data *srv)
{
	uint8_t cw[16];
	struct cardserver_data *cs;

	struct sockaddr_in si_other;
	socklen_t slen = sizeof(si_other);
	unsigned char buf[1024];

	int received = recvfrom( srv->handle, buf, sizeof(buf), 0, (struct sockaddr*)&si_other, &slen);
	if ( (received<20)||(received>1020) ) return;

	uint32_t ucrc = (buf[0]<<24)|(buf[1]<<16)|(buf[2]<<8)|buf[3];
	//Check for client
	if (srv->ucrc!=ucrc) return;
	//
	aes_decrypt( &srv->decryptkey, buf+4, received-4);
#ifdef DEBUG_NETWORK
	if (flag_debugnet) {
		unsigned int recv_ip;
		unsigned short recv_port;
		memcpy( &recv_ip, &si_other.sin_addr, 4);
		recv_port = ntohs(si_other.sin_port);
		mlogf(LOGDEBUG,0," camd35: Recv data (length=%d) from address (%s:%d)\n", received, ip2string(recv_ip), recv_port );
		debughex(buf,received);
	}
#endif

	switch (buf[4]) {

		case CAMD_ECM_REPLY:
			srv->lastdcwtime = GetTickCount();
			if (!srv->busy) {
				mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," [!] dcw error from camd35 server (%s:%d), unknown ecm request\n",srv->host->name,srv->port);
				break;
			}
			//
			if (buf[5]!=0x10) {
				mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," [!] dcw error from camd35 server (%s:%d), wrong length!!!\n",srv->host->name,srv->port);
				break;
			}
			// Check Stored ECM
			ECM_DATA *ecm = srv->ecm.request;
			if (!ecm) {
				mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," [!] dcw error from camd35 server (%s:%d), ecm not found!!!\n",srv->host->name,srv->port);
				break;
			}
			// Check for DCW
			cs= ecm->cs;
			if (!cs)
			{
				cs = getcsbycaprovid(ecm->caid, ecm->provid);
			}
			if(!cs)
			{
				// Log abnormal case when cs could not be found
				mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," [!] dcw received from camd35 server (%s:%d). Cannot find cs profile!!!\n",srv->host->name,srv->port);
			}
			int isnanoe0=ecm_isnanoe0(ecm->ecm,ecm->caid);
			if ( isnanoe0 )
				mlogf(LOGDEBUG,getdbgflag(DBG_SERVER,0,srv->id)," [!] viaccess nano e0 detected ch %04x:%06x:%04x\n",ecm->caid, ecm->provid, ecm->sid);

			if (!acceptDCW( buf+24, isnanoe0 ) ) {
				srv->ecmerrdcw++;
				// Log abnormal case when dcw is rejected
				mlogf(LOGDEBUG,getdbgflag(DBG_SERVER,0,srv->id)," [!] dcw error from camd35 server (%s:%d), bad dcw!!! ch %04x:%06x:%04x nanoe0=%d\n",srv->host->name,srv->port,ecm->caid, ecm->provid, ecm->sid,isnanoe0);
				break;
			}
			//
			srv->busy = 0;
			pipe_cmd( prg.pipe.ecm[1], PIPE_SRV_AVAILABLE );
			pthread_mutex_lock(&prg.lockecm); //###
			// check for ECM validity
			if (ecm->hash!=srv->ecm.hash) {
				mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," [!] dcw error from camd35 server (%s:%d), ecm deleted!!!\n",srv->host->name,srv->port);
				pthread_mutex_unlock(&prg.lockecm);
				break;
			}

			srv->ecmok++;
			srv->lastecmoktime = GetTickCount()-srv->lastecmtime;
			srv->ecmoktime += srv->lastecmoktime;
			ecm_setsrvflagdcw( ecm, srv->id, ECM_SRV_REPLY_GOOD, buf+24 );
			mlogf(LOGINFO,getdbgflagpro(DBG_SERVER,0,srv->id,ecm->cs->id)," <= cw from camd35 server (%s:%d) ch %04x:%06x:%04x (%dms)\n", srv->host->name,srv->port, ecm->caid,ecm->provid,ecm->sid, GetTickCount()-srv->lastecmtime);

			if (ecm->dcwstatus!=STAT_DCW_SUCCESS) {
				static char msg[] = "Good dcw from camd35 server";
				ecm->statusmsg = msg;
				// Store ECM Answer
				ecm_setdcw( ecm, buf+24, DCW_SOURCE_SERVER, srv->id );
			}
			else {	//TODO: check same dcw between cards
				srv->ecmerrdcw ++;
				if ( memcmp( ecm->cw, buf+24, 16) ) mlogf(LOGWARNING,getdbgflagpro(DBG_SERVER,0,srv->id,ecm->cs->id)," !!! different dcw from camd35 server (%s:%d)\n",srv->host->name,srv->port);
			}
#ifdef SID_FILTER
			// ADD IN SID LIST
			cs= ecm->cs;
			if (cs) {
				cardsids_update( srv->busycard, ecm->provid, ecm->sid, 1);
				srv_cstatadd( srv, cs->id, 1 , srv->lastecmoktime);
			}
#endif
			pthread_mutex_unlock(&prg.lockecm); //###
			break;

		case 0x44:
			srv->lastdcwtime = GetTickCount();
			if (!srv->busy) {
				mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," [!] dcw error from camd35 server (%s:%d), unknown ecm request\n",srv->host->name,srv->port);
				break;
			}
			// Checl Stored ECM
			ecm = srv->ecm.request;
			if (!ecm) {
				mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," [!] dcw error from camd35 server (%s:%d), ecm not found!!!\n",srv->host->name,srv->port);
				break;
			}
			//
			srv->busy = 0;
			pipe_cmd( prg.pipe.ecm[1], PIPE_SRV_AVAILABLE );
			pthread_mutex_lock(&prg.lockecm); //###
			// check for ECM validity
			if (ecm->hash!=srv->ecm.hash) {
				mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," [!] dcw error from camd35 server (%s:%d), ecm deleted!!!\n",srv->host->name,srv->port);
				pthread_mutex_unlock(&prg.lockecm);
				break;
			}
			cs= ecm->cs;
			ecm_setsrvflag(ecm, srv->id, ECM_SRV_REPLY_FAIL);
			mlogf(LOGINFO,getdbgflagpro(DBG_SERVER,0,srv->id,ecm->cs->id)," <| decode failed from camd35 server (%s:%d) ch %04x:%06x:%04x (%dms)\n", srv->host->name,srv->port, ecm->caid,ecm->provid,ecm->sid, GetTickCount()-srv->lastecmtime);
#ifdef SID_FILTER
			// ADD IN SID LIST
			if (cs) {
				cardsids_update( srv->busycard, ecm->provid, ecm->sid, -1);
				srv_cstatadd( srv, cs->id, 0 , 0);
			}
#endif
			pthread_mutex_unlock(&prg.lockecm); //###
			wakeup_sendecm(); // Wakeup ecm waiting for availabe servers
			break;

		// Keepalive
		case CAMD_KEEPALIVE:
			srv->keepalive.status = 0;
			//mlogf(LOGDEBUG,0," server(camd35): Keepalive from (%s:%d)\n", srv->host->name, srv->port);
			if (srv->connection.status<=0) {
				mlogf(LOGINFO,0," connect to camd35 server (%s:%d)\n", srv->host->name, srv->port);
				srv->connection.status = 1;
				srv->connection.time = GetTickCount();
			}
			break;

		// Request Nodeid
		case CAMD_CEX_IDREPLY:
			srv->keepalive.status = 0;
			//mlogf(LOGDEBUG,0," server(camd35): Got Nodeid from (%s:%d)\n", srv->host->name, srv->port);
			memcpy( srv->nodeid, buf+24, 8);
			if (srv->connection.status<=0) {
				char str[8*3+1];
				array2hex( srv->nodeid, str, 8);
				mlogf(LOGINFO,0," connected to camd35 server (%s:%d), Nodeid = %s\n", srv->host->name, srv->port, str);
				srv->connection.status = 1;
				srv->connection.time = GetTickCount();
			}
			break;

#ifdef CACHEEX
		// push out
		case CAMD_CEX_PUSH:
			memcpy( cw, buf+44, 16);
			//srv->cacheex.totalrep++;
			struct cache_data cacheex;
			cacheex.sid = (buf[12]<<8)|buf[13];
			cacheex.caid = (buf[14]<<8)|buf[15];
			cacheex.provid = (buf[16]<<24)|(buf[17]<<16)|(buf[18]<<8)|buf[19];
			// Look for cardserver
			cs = getcsbycaprovid(cacheex.caid, cacheex.provid);
			if ( !cs || !cs->option.fallowcacheex ) {
				srv->cacheex.badcw++;
				break;
			}
			if (cacheex.caid==0x0500) {
				if (!acceptDCWnonblockCRC(cw)) break;
			}
			else
				if (!acceptDCW(cw,0)) break;
			if ((buf[23]&0xFE)==0x80) cacheex.tag = buf[23]; else cacheex.tag = 0;
			memcpy( cacheex.ecmd5, buf+24, 16);
			//if ( !checkECMD5(cacheex.ecmd5) ) cli->cacheex.totalcsp++;
			cacheex.hash = (buf[43]<<24) | (buf[42]<<16) | (buf[41]<<8) | buf[40];
			if (!cacheex_check(&cacheex)) break;
			//mlogf(LOGDEBUG,getdbgflag(DBG_CACHEEX, 0, 0)," CACHEEX PUSH from client(%d) %04x:%06x:%04x (%08x)\n",cli->id,cacheex.caid,cacheex.provid,cacheex.sid,cacheex.hash);
			srv->cacheex.got[0]++;
			int uphop = buf[60];
			if (uphop<10) srv->cacheex.got[uphop]++;
			//
			pthread_mutex_lock( &prg.lockcache );
			int res = cache_setdcw( &cacheex, cw, NO_CYCLE, PEER_CACHEEX_SERVER | srv->id );
			pthread_mutex_unlock( &prg.lockcache );
			if (res&DCW_ERROR) {
				if ( !(res&DCW_SKIP)) srv->cacheex.badcw++;
			}
			else if (res&DCW_CYCLE) {
				if ( cs->option.cacheex.maxhop>uphop ) {
					uint8_t nodeid[8];
					memcpy( nodeid, buf+61, 8);
					pipe_send_cacheex_push_cache(&cacheex, cw, nodeid); //cacheex_push(&cacheex, cw, nodeid);
				}
			}
			//mlogf(LOGDEBUG,0," camd35: push out from server %04x:%06x:%04x|%02x:%08x\n", cacheex.caid,cacheex.provid,cacheex.sid, cacheex.tag,cacheex.hash);
			break;
#endif

	}

}

// CACHEEX MODE 2
void *camd35_srv_recvmsg_thread(struct server_data *srv)
{
	srv->pid = syscall(SYS_gettid);

	while (!prg.restart) {
		if (srv->handle<=0) {
			srv->pid = 0;
			return NULL;
		}
		//
		struct pollfd pfd;
		pfd.fd = srv->handle;
		pfd.events = POLLIN | POLLPRI;
		int retval = poll(&pfd, 1, 3009);
		if (retval==0) continue; // timeout
		if (retval<0) {
			disconnect_srv(srv);
			srv->pid = 0;
			return NULL;
		}
		camd35_srv_recvmsg(srv);
	}
	return NULL;
}


///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

int camd35_connect_srv(struct server_data *srv, int fd)
{
	uint8_t buf[64];
#ifdef CACHEEX
	if (srv->cacheex_mode) {
		// Request Nodeid
		memset(buf, 0, 32);
		buf[0] = CAMD_CEX_IDREQUEST;
		buf[1] = 12;
		memcpy( buf+20, cfg.nodeid, 8);
		camd35_sendto( fd, srv->host->ip, srv->port, &srv->encryptkey, srv->ucrc, buf, 20+12);
		struct pollfd pfd;
		pfd.fd = fd;
		pfd.events = POLLIN | POLLPRI;
		int ret = poll(&pfd, 1, 3000);
		while (ret>0) {
			struct sockaddr_in si_other;
			socklen_t slen = sizeof(si_other);
			unsigned char buf[1024];
			int received = recvfrom( fd, buf, sizeof(buf), 0, (struct sockaddr*)&si_other, &slen);
			if ( (received<20)||(received>1020) ) break;
			uint32_t ucrc = (buf[0]<<24)|(buf[1]<<16)|(buf[2]<<8)|buf[3];
			if (srv->ucrc!=ucrc) break;
			aes_decrypt( &srv->decryptkey, buf+4, received-4);
			if (buf[4]==CAMD_CEX_IDREPLY) { // good
				memcpy( srv->nodeid, buf+24, 8);
				array2hex( srv->nodeid, buf, 8);
				mlogf(LOGINFO,0," Connected to camd35 server (%s:%d), Nodeid = %s\n", srv->host->name, srv->port, buf);
				srv->connection.status = 1;
				srv->connection.time = GetTickCount();
				srv->keepalive.status = 0;
				srv->keepalive.time = GetTickCount();
				srv->handle = fd;
				if (srv->cacheex_mode==2) {
					if (!create_thread(&srv->tid, (threadfn)camd35_srv_recvmsg_thread, srv)) {
						disconnect_srv(srv);
					}
				}
				else pipe_wakeup( prg.pipe.cacheex[1] );
				return 0;
			}
			break;
		}
		close(fd);			
	}
	else
#endif

	{
		// keepalive
		uint8_t buf[64];
		memset(buf,0, 21);
		buf[0] = CAMD_KEEPALIVE;
		buf[1] = 1;
		camd35_sendto( fd, srv->host->ip, srv->port, &srv->encryptkey, srv->ucrc, buf, 20+1);
		struct pollfd pfd;
		pfd.fd = fd;
		pfd.events = POLLIN | POLLPRI;
		int ret = poll(&pfd, 1, 3000);
		while (ret>0) {
			struct sockaddr_in si_other;
			socklen_t slen = sizeof(si_other);
			unsigned char buf[1024];
			int received = recvfrom( fd, buf, sizeof(buf), 0, (struct sockaddr*)&si_other, &slen);
			if ( (received<20)||(received>1020) ) break;
			uint32_t ucrc = (buf[0]<<24)|(buf[1]<<16)|(buf[2]<<8)|buf[3];
			if (srv->ucrc!=ucrc) break;
			aes_decrypt( &srv->decryptkey, buf+4, received-4);
			if (buf[4]==CAMD_KEEPALIVE) { // good
				//SetUP Cards
				int count = 0;
				while (srv->sharelimits[count].caid!=0xFFFF) {
					struct cs_card_data *pcard = malloc( sizeof(struct cs_card_data) );
					memset(pcard, 0, sizeof(struct cs_card_data) );
					pcard->caid = srv->sharelimits[count].caid;
					pcard->nbprov = 1;
					pcard->prov[0] = srv->sharelimits[count].provid;
					pcard->uphops = srv->sharelimits[count].uphops;
					pcard->next = srv->card;
					srv->card = pcard;
					count++;
				}
				//
				mlogf(LOGINFO,0," Connected to camd35 server (%s:%d)\n", srv->host->name, srv->port);
				srv->connection.status = 1;
				srv->connection.time = GetTickCount();
				srv->keepalive.status = 0;
				srv->keepalive.time = GetTickCount();
				srv->handle = fd;
#ifdef EPOLL_ECM
				pipe_pointer( prg.pipe.ecm[1], PIPE_SRV_CONNECTED, srv );
#else
				pipe_cmd( prg.pipe.ecm[1], PIPE_SRV_CONNECTED );
#endif
				return 0;
			}
			break;
		}
		close(fd);			
	}
	return 1;
}


