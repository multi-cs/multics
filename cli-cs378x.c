///////////////////////////////////////////////////////////////////////////////
// TCP
///////////////////////////////////////////////////////////////////////////////
//CMD00 - ECM (request)
//CMD01 - ECM (response)
//CMD02 - EMM (in clientmode - set EMM, in server mode - EMM data) - obsolete
//CMD03 - ECM (cascading request)
//CMD04 - ECM (cascading response)
//CMD05 - EMM (emm request) send cardata/cardinfo to client
//CMD06 - EMM (incomming EMM in server mode)
//CMD19 - EMM (incomming EMM in server mode) only seen with caid 0x1830
//CMD08 - Stop sending requests to the server for current srvid,prvid,caid
//CMD44 - MPCS/OScam internal error notification
//CMD55 - connect_on_init/keepalive

//CMD0x3d - CACHEEX Cache-push id request
//CMD0x3e - CACHEEX Cache-push id answer
//CMD0x3f - CACHEEX cache-push


void cs378x_send_keepalive(struct server_data *srv)
{
	uint8_t buf[64];

#ifdef CACHEEX
	if (srv->cacheex_mode) {
		// Request Nodeid
		memset(buf, 0, 32);
		buf[0] = CAMD_CEX_IDREQUEST;
		buf[1] = 12;
		memcpy( buf+20, cfg.nodeid, 8);
		cs378x_send( srv->handle, &srv->encryptkey, srv->ucrc, buf, 20+12);
	}
	else
#endif
	{
		// keepalive
		uint8_t buf[64];
		memset(buf,0, 21);
		buf[0] = CAMD_KEEPALIVE;
		buf[1] = 1;
		buf[2] = 0;
		cs378x_send( srv->handle, &srv->encryptkey, srv->ucrc, buf, 20+1);
	}
}

///////////////////////////////////////////////////////////////////////////////
// SEND ECM
///////////////////////////////////////////////////////////////////////////////

int cs378x_sendecm_srv(struct server_data *srv, ECM_DATA *ecm)
{
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
	cs378x_send( srv->handle, &srv->encryptkey, srv->ucrc, buf, 20+ecm->ecmlen);
	return 1;
}

//#ifndef PUBLIC
void cs378x_sendecm_extrasrv(struct server_data *srv, ECM_DATA *ecm)
{
	unsigned char buf[1024];
	memset(buf, 0, 20);
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

	int index = 20;
	memcpy( buf+index, ecm->ecm, ecm->ecmlen);
	index += ecm->ecmlen;

	buf[0] = 0; // Command
	buf[1] = 0; // Length

	if ( ecm->lastdecode.ecm && (ecm->lastdecode.counter>1) ) {
		if (ecm->lastdecode.cwcycle=='0') buf[0] = 0x80;
		else if (ecm->lastdecode.cwcycle=='1') buf[0] = 0x81;
		if ( buf[0] ) {
			memcpy( buf+index, ecm->lastdecode.dcw, 16);
			index+=16;
			buf[index] = ecm->lastdecode.dcwchangetime/1000;
			index++;
			int datalen = ecm->ecmlen+17;
			buf[1] = datalen&0xff; // Length
			buf[2] = datalen>>8; // Length
		}
	}
	//mlogf(LOGDEBUG,0, " cs378x forward ecm %04x:%06x:%04x:%08x (%02x)\n", ecm->caid, ecm->provid, ecm->sid, ecm->hash, buf[0]);

	cs378x_send( srv->handle, &srv->encryptkey, srv->ucrc, buf, index);
}
//#endif


///////////////////////////////////////////////////////////////////////////////
// RECV MSG
///////////////////////////////////////////////////////////////////////////////



///////////////////////////////////////////////////////////////////////////////
// RECV MSG
///////////////////////////////////////////////////////////////////////////////

// CACHEEX MODE 2
void cs378x_srv_recvmsg(struct server_data *srv)
{
	uint8_t cw[16];
	struct cardserver_data *cs;
	unsigned char buf[2048];
	// Get MSG
    int len = cs378x_msg_peek( srv->handle, srv->ucrc, &srv->decryptkey, buf);
	if (len<=0) {
		disconnect_srv(srv);
		return;
	}
	//mlogf(LOGDEBUG,getdbgflag(DBG_SERVER,0,srv->id)," msg from cs378x server (%s:%d)\n", srv->host->name, srv->port); debughex(buf, newlen);

	uint32_t ticks = GetTickCount();
	switch (buf[4]) {

		case CAMD_ECM_REPLY:
			srv->lastdcwtime = ticks;
			if (!srv->busy) {
				mlogf(LOGINFO,getdbgflag(DBG_SERVER,0,srv->id)," [!] dcw error from cs378x server (%s:%d), unknown ecm request\n",srv->host->name,srv->port);
				break;
			}
			//
			if (buf[5]!=0x10) {
				mlogf(LOGINFO,getdbgflag(DBG_SERVER,0,srv->id)," [!] dcw error from cs378x server (%s:%d), wrong length!!!\n",srv->host->name,srv->port);
				break;
			}
			// Check Stored ECM
			ECM_DATA *ecm = srv->ecm.request;
			if (!ecm) {
				mlogf(LOGINFO,getdbgflag(DBG_SERVER,0,srv->id)," [!] dcw error from cs378x server (%s:%d), ecm not found!!!\n",srv->host->name,srv->port);
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
				mlogf(LOGINFO,getdbgflag(DBG_SERVER,0,srv->id)," [!] dcw received from cs378x server (%s:%d). Cannot find cs profile!!!\n",srv->host->name,srv->port);
			}
			int isnanoe0=ecm_isnanoe0(ecm->ecm,ecm->caid);
			if ( isnanoe0 )
				mlogf(LOGDEBUG,getdbgflag(DBG_SERVER,0,srv->id)," [!] viaccess nano e0 detected ch %04x:%06x:%04x\n",ecm->caid, ecm->provid, ecm->sid);
			if (!acceptDCW( buf+24, isnanoe0 ) ) {
				mlogf(LOGINFO,getdbgflag(DBG_SERVER,0,srv->id)," [!] dcw error from cs378x server (%s:%d), bad dcw!!! ch %04x:%06x:%04x nanoe0=%d\n",srv->host->name,srv->port,ecm->caid, ecm->provid, ecm->sid, isnanoe0);
				srv->ecmerrdcw++;
				break;
			}
			//
			srv->busy = 0;
			pipe_cmd( prg.pipe.ecm[1], PIPE_SRV_AVAILABLE );
			pthread_mutex_lock(&prg.lockecm); //###
			// check for ECM validity
			if (ecm->hash!=srv->ecm.hash) {
				mlogf(LOGINFO,getdbgflag(DBG_SERVER,0,srv->id)," [!] dcw error from cs378x server (%s:%d), ecm deleted!!!\n",srv->host->name,srv->port);
				pthread_mutex_unlock(&prg.lockecm);
				break;
			}
			srv->ecmok++;
			srv->lastecmoktime = ticks-srv->lastecmtime;
			srv->ecmoktime += srv->lastecmoktime;
			ecm_setsrvflagdcw( ecm, srv->id, ECM_SRV_REPLY_GOOD, buf+24 );
			mlogf(LOGINFO,getdbgflagpro(DBG_SERVER,0,srv->id,ecm->cs->id)," <= cw from cs378x server (%s:%d) ch %04x:%06x:%04x (%dms)\n", srv->host->name,srv->port, ecm->caid,ecm->provid,ecm->sid, ticks-srv->lastecmtime);
			if (ecm->dcwstatus!=STAT_DCW_SUCCESS) {
				static char msg[] = "Good dcw from camd35 server";
				ecm->statusmsg = msg;
				// Store ECM Answer
				ecm_setdcw( ecm, buf+24, DCW_SOURCE_SERVER, srv->id );
			}
			else {	//TODO: check same dcw between cards
				srv->ecmerrdcw ++;
				if ( memcmp( ecm->cw, buf+24, 16) ) mlogf(LOGINFO,getdbgflagpro(DBG_SERVER,0,srv->id,ecm->cs->id)," !!! different dcw from cs378x server (%s:%d)\n",srv->host->name,srv->port);
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
			if (srv->cacheex_mode) break;
			srv->lastdcwtime = ticks;
			if (!srv->busy) {
				mlogf(LOGINFO,getdbgflag(DBG_SERVER,0,srv->id)," [!] dcw error from cs378x server (%s:%d), unknown ecm request\n",srv->host->name,srv->port);
				break;
			}
			// Checl Stored ECM
			ecm = srv->ecm.request;
			if (!ecm) {
				mlogf(LOGINFO,getdbgflag(DBG_SERVER,0,srv->id)," [!] dcw error from cs378x server (%s:%d), ecm not found!!!\n",srv->host->name,srv->port);
				break;
			}
			//
			srv->busy = 0;
			pipe_cmd( prg.pipe.ecm[1], PIPE_SRV_AVAILABLE );
			pthread_mutex_lock(&prg.lockecm); //###
			// check for ECM validity
			if (ecm->hash!=srv->ecm.hash) {
				mlogf(LOGINFO,getdbgflag(DBG_SERVER,0,srv->id)," [!] dcw error from cs378x server (%s:%d), ecm deleted!!!\n",srv->host->name,srv->port);
				pthread_mutex_unlock(&prg.lockecm);
				break;
			}
			cs= ecm->cs;
			ecm_setsrvflag(ecm, srv->id, ECM_SRV_REPLY_FAIL);
			mlogf(LOGINFO,getdbgflagpro(DBG_SERVER,0,srv->id,ecm->cs->id)," <| decode failed from cs378x server (%s:%d) ch %04x:%06x:%04x (%dms)\n", srv->host->name,srv->port, ecm->caid,ecm->provid,ecm->sid, ticks-srv->lastecmtime);
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
			mlogf(LOGDEBUG,getdbgflag(DBG_SERVER,0,srv->id)," server(cs378x): Keepalive from (%s:%d)\n", srv->host->name, srv->port);
			if (srv->connection.status<=0) {
				mlogf(LOGINFO,getdbgflag(DBG_SERVER,0,srv->id)," Connected to cs378x server (%s:%d)\n", srv->host->name, srv->port);
				srv->connection.status = 1;
				srv->connection.time = ticks;
			}
			break;

#ifdef CACHEEX
		// Request Nodeid
		case CAMD_CEX_IDREPLY:
			srv->keepalive.status = 0;
			//mlogf(LOGDEBUG,getdbgflag(DBG_SERVER,0,srv->id)," server(cs378x): Got Nodeid from (%s:%d)\n", srv->host->name, srv->port);
			memcpy( srv->nodeid, buf+24, 8);
			if (srv->connection.status<=0) {
				char str[8*3+1];
				array2hex( srv->nodeid, str, 8);
				mlogf(LOGINFO,getdbgflag(DBG_SERVER,0,srv->id)," Connected to cs378x server (%s:%d), Nodeid = %s\n", srv->host->name, srv->port, str);
				srv->connection.status = 1;
				srv->connection.time = ticks;
			}
			break;

		// push out
		case CAMD_CEX_PUSH:
			if (len<60) break;
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
			{
				if (!acceptDCW(cw,0)) break;
			}
			if ((buf[23]&0xFE)==0x80) cacheex.tag = buf[23]; else cacheex.tag = 0;
			memcpy( cacheex.ecmd5, buf+24, 16);
			//if ( !checkECMD5(cacheex.ecmd5) ) cli->cacheex.totalcsp++;
			cacheex.hash = (buf[43]<<24) | (buf[42]<<16) | (buf[41]<<8) | buf[40];
			if (!cacheex_check(&cacheex)) break;
			mlogf(LOGTRACE,getdbgflag(DBG_SERVER,0,srv->id), " CACHEEX PUSH from server(%s:%d) %04x:%06x:%04x (%08x)\n",srv->host->name, srv->port,cacheex.caid,cacheex.provid,cacheex.sid,cacheex.hash);
			srv->cacheex.got[0]++;
			int uphop = buf[60];
			if (uphop<10) srv->cacheex.got[uphop]++;
			//
			pthread_mutex_lock( &prg.lockcache );
			int res = cache_setdcw( &cacheex, cw, NO_CYCLE, PEER_CACHEEX_SERVER | srv->id );
			pthread_mutex_unlock( &prg.lockcache );
			if (res&DCW_ERROR) {
				if ( !(res&DCW_SKIP) ) srv->cacheex.badcw++;
			}
			else if (res&DCW_CYCLE) {
				if ( cs->option.cacheex.maxhop>uphop ) {
					uint8_t nodeid[8];
					memcpy( nodeid, buf+61, 8);
					pipe_send_cacheex_push_cache(&cacheex, cw, nodeid); //cacheex_push(&cacheex, cw, nodeid);
				}
			}
			mlogf(LOGDEBUG,getdbgflag(DBG_SERVER,0,srv->id), " cs378x: push out from server %04x:%06x:%04x|%02x:%08x\n", cacheex.caid,cacheex.provid,cacheex.sid, cacheex.tag,cacheex.hash);
			break;
#endif
	}

	srv->keepalive.time = ticks;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// CACHEEX MODE 2
void *cs378x_srv_recvmsg_thread(struct server_data *srv)
{
	srv->pid = syscall(SYS_gettid);

	while (!prg.restart) {
		if (srv->handle<=0) {
			srv->pid = 0;
			disconnect_srv(srv);
			return NULL;
		}
		//
		struct pollfd pfd;
		pfd.fd = srv->handle;
		pfd.events = POLLIN | POLLPRI;
		int retval = poll(&pfd, 1, 3009);
		if (retval==0) continue;
		if (retval<0) {
			disconnect_srv(srv);
			return NULL;
		}
		//
		cs378x_srv_recvmsg( srv );
	}
	return NULL;
}


///////////////////////////////////////////////////////////////////////////////
//
///////////////////////////////////////////////////////////////////////////////

int cs378x_connect_srv(struct server_data *srv, int fd)
{

	srv->handle = fd;
	SetSocketTimeout(fd, 5000);
	cs378x_send_keepalive(srv);
	srv->handle = 0;
	// Poll
	struct pollfd pfd;
	pfd.fd = fd;
	pfd.events = POLLIN | POLLPRI;
	if ( poll( &pfd, 1, 3000) <=0 ) return 1;
	//
	unsigned char buf[1024];
	int n = cs378x_recv( fd, srv->ucrc, &srv->decryptkey, buf);
	if (n>0) {
#ifdef CACHEEX
		if ( buf[4] == CAMD_CEX_IDREPLY ) {
			memcpy( srv->nodeid, buf+24, 8);
			//mlogf(LOGDEBUG,getdbgflag(DBG_SERVER,0,srv->id)," server(cs378x): Got Nodeid from (%s:%d)\n", srv->host->name, srv->port);
			srv->connection.status = 1;
			srv->connection.time = GetTickCount();
			srv->keepalive.status = 0;
			srv->keepalive.time = GetTickCount();
			srv->handle = fd;
			//
			char str[8*3+1];
			array2hex( srv->nodeid, str, 8);
			mlogf(LOGINFO,getdbgflag(DBG_SERVER,0,srv->id)," Connected to cs378x server (%s:%d), Nodeid = %s\n", srv->host->name, srv->port, str);
			// Cache EX 2 -> thread
			if (srv->cacheex_mode==2) {
				if (!create_thread(&srv->tid, (threadfn)cs378x_srv_recvmsg_thread, srv)) {
					disconnect_srv(srv);
					return 1;
				}
			}
			return 0;
		}
		else
#endif
		if ( buf[4] == CAMD_KEEPALIVE ) {
			//
			mlogf(LOGINFO,getdbgflag(DBG_SERVER,0,srv->id)," Connected to cs378x server (%s:%d)\n", srv->host->name, srv->port);
			srv->connection.status = 1;
			srv->connection.time = GetTickCount();
			srv->keepalive.status = 0;
			srv->keepalive.time = GetTickCount();
			srv->handle = fd;
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
#ifdef EPOLL_ECM
			pipe_pointer( prg.pipe.ecm[1], PIPE_SRV_CONNECTED, srv );
#else
			pipe_cmd( prg.pipe.ecm[1], PIPE_SRV_CONNECTED );
#endif
			return 0;
		}
	}
	return 1;
}

