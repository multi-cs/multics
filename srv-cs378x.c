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


struct camd35_client_data *getcs378xclientbyid(uint32_t id)
{
	if (cfg.cs378x.server) {
		struct camd35_client_data *cli = cfg.cs378x.server->client;
		while (cli) {
			if (!(cli->flags&FLAG_DELETE))
				if (cli->id==id) return cli;
			cli = cli->next;
		}
	}
	return NULL;
}

///////////////////////////////////////////////////////////////////////////////
// CONNECT
///////////////////////////////////////////////////////////////////////////////

void cs378x_disconnect_cli(struct camd35_client_data *cli)
{
	cli->connection.status = 0;
	uint32_t ticks = GetTickCount();
	cli->connection.uptime += ticks - cli->connection.time;
	cli->connection.lastseen = ticks; // Last Seen
	close(cli->handle);
	cli->handle = -1;
	mlogf(LOGINFO,0," cs378x: client '%s' disconnected \n", cli->user);
}

void *cs378x_connect_cli(struct connect_cli_data *param)
{
	uint8_t buf[1024];
	// Store data from param
	struct camd35_server_data *cs378x = param->server;
	int sock = param->sock;
	uint32_t ip = param->ip;
	free(param);

	int len = recv_nonb( sock, buf, 32+4, 5000);
	if (len<=0) {
		mlogf(LOGWARNING,getdbgflag(DBG_CS378X,0,0), " cs378x: new connection aborted, rto\n");
		close(sock);
		return NULL;
	}
	uint32_t ucrc = (buf[0]<<24)|(buf[1]<<16)|(buf[2]<<8)|buf[3];
	//Check for clients
	struct camd35_client_data *cli = cs378x->client;
	while (cli) {
		if (cli->ucrc==ucrc) break;
		cli = cli->next;
	}
	if (!cli) {
		cli = cs378x->cacheexclient;
		while (cli) {
			if (cli->ucrc==ucrc) break;
			cli = cli->next;
		}
	}
	if (!cli) {
		mlogf(LOGWARNING,getdbgflag(DBG_CS378X,cs378x->id,0)," cs378x%d: Unknown Client UCRC=%08x (%s)\n", cs378x->id, ucrc, ip2string(ip));
		close(sock);
		return NULL;
	}
	// Check reconnection
	if (cli->connection.status>0) cs378x_disconnect_cli(cli);

	if (IS_DISABLED(cli->flags)) { // Connect only enabled clients
		mlogf(LOGWARNING,getdbgflag(DBG_CS378X,cs378x->id,0)," cs378x%d: connection refused for client '%s' (%s), client disabled\n", cs378x->id, cli->user, ip2string(ip));
		close(sock);
		return NULL;
	}

	//
	aes_decrypt( &cli->decryptkey, buf+4, len-4);
	int datalen = buf[5];
	if (buf[4] == 0) datalen = (((buf[25] & 0x0f) << 8) | buf[26]) + 3;
	else if (buf[4] == CAMD_CEX_IDREQUEST || buf[4] == CAMD_CEX_IDREPLY || buf[4] == CAMD_CEX_PUSH) datalen = buf[5] | (buf[6] << 8);
	int newlen = 4+camd35_padding(20+datalen);
	if (len<newlen) {
		int n = recv_nonb( sock, buf+len, newlen-len, 1000);
		if (n<=0) {
			mlogf(LOGWARNING,getdbgflag(DBG_CS378X,0,0), " cs378x: new connection aborted, failed receive data\n");
			close(sock);
			return NULL;
		}
		aes_decrypt( &cli->decryptkey, buf+len, n);
	}
	//
	if (buf[4]==CAMD_KEEPALIVE) {
		//mlogf(LOGDEBUG,0," camd35: Keepalive from client '%s'\n", cli->user);
		if ( !cs378x_send( sock, &cli->encryptkey, cli->ucrc, buf+4, 20+1) ) {
			close( sock );
			return NULL;
		}
		mlogf(LOGINFO,getdbgflag(DBG_CS378X,0,cli->id)," cs378x: client '%s' connected\n", cli->user);
		cli->connection.status = 1;
		cli->connection.time = GetTickCount();
		cli->handle = sock;
		cli->ip = ip;
		pipe_wakeup( prg.pipe.cs378x[1] );
	}
#ifdef CACHEEX
	else if (buf[4]==CAMD_CEX_IDREQUEST) {
		//mlogf(LOGDEBUG,getdbgflag(DBG_CS378X,0,cli->id)," camd35: Nodeid from client '%s'\n", cli->user);
		memcpy( cli->nodeid, buf+24, 8);
		memset(buf, 0, 20+12);
		buf[0] = CAMD_CEX_IDREPLY;
		buf[1] = 12;
		memcpy( buf+20, cfg.nodeid, 8);
		if ( !cs378x_send( sock, &cli->encryptkey, cli->ucrc, buf, 20+12) ) {
			close( sock );
			return NULL;
		}
		char str[8*3+1];
		array2hex( cli->nodeid, str, 8);
		mlogf(LOGINFO,getdbgflag(DBG_CS378X,0,cli->id)," cs378x: CacheEX client '%s' connected, Nodeid = %s\n", cli->user, str);
		cli->connection.status = 1;
		cli->connection.time = GetTickCount();
		cli->handle = sock;
		cli->ip = ip;
		pipe_wakeup( prg.pipe.cs378x_cex[1] );
	}
#endif
	else close(sock);
	return NULL;
}


void cs378x_srv_accept(struct camd35_server_data *srv)
{
	struct sockaddr_in newaddr;
	socklen_t socklen = sizeof(struct sockaddr);
	int newfd = accept( srv->handle, (struct sockaddr*)&newaddr, /*(socklen_t*)*/&socklen);
	if ( newfd<=0 ) {
		if ( (errno!=EAGAIN) && (errno!=EINTR) ) mlogf(LOGERROR,getdbgflag(DBG_CS378X,0,0)," cs378x: Accept failed (errno=%d)\n", errno);
	}
	else {
		uint32_t newip = newaddr.sin_addr.s_addr;
		if ( isblockedip(newip) ) {
			mlogf(LOGWARNING,getdbgflag(DBG_CS378X,0,0)," cs378x: New Connection (%s) closed, ip blocked\n", ip2string(newip) );
			close(newfd);
		}
		else {
			pthread_t srv_tid;
			if (cfg.cccam.keepalive) SetSocketKeepalive(newfd);
			SetSocketNoDelay(newfd);
			SetSoketNonBlocking(newfd);
			//mlogf(LOGDEBUG,getdbgflag(DBG_CS378X,0,0)," cs378x: new client Connection(%d)...%s\n", newfd, ip2string(newip) );
			struct connect_cli_data *newdata = malloc( sizeof(struct connect_cli_data) );
			newdata->server = srv; 
			newdata->sock = newfd; 
			newdata->ip = newaddr.sin_addr.s_addr;
			if ( !create_thread(&srv_tid, (threadfn)cs378x_connect_cli,newdata) ) {
				free( newdata );
				close( newfd );
			}
		}
	}
}

#ifndef MONOTHREAD_ACCEPT

void *cs378x_accept_thread(void *param)
{

#ifndef PUBLIC
	prctl(PR_SET_NAME,"cs378x Accept",0,0,0);
#endif
	while(!prg.restart) {

		struct pollfd pfd[MAX_PFD];
		int pfdcount = 0;

		struct camd35_server_data *cs378x = cfg.cs378x.server;
		while (cs378x) {
			if ( !IS_DISABLED(cs378x->flags) && (cs378x->handle>0) ) {
				cs378x->ipoll = pfdcount;
				pfd[pfdcount].fd = cs378x->handle;
				pfd[pfdcount++].events = POLLIN | POLLPRI;
			} else cs378x->ipoll = -1;
			cs378x = cs378x->next;
		}

		if (pfdcount) {
			int retval = poll(pfd, pfdcount, 3006);
			if ( retval>0 ) {
				struct camd35_server_data *cs378x = cfg.cs378x.server;
				while (cs378x) {
					if ( !IS_DISABLED(cs378x->flags) && (cs378x->handle>0) && (cs378x->ipoll>=0) && (cs378x->handle==pfd[cs378x->ipoll].fd) ) {
						if ( pfd[cs378x->ipoll].revents & (POLLIN|POLLPRI) ) cs378x_srv_accept(cs378x);
					}
					cs378x = cs378x->next;
				}
			}
			else if (retval<0) usleep(96000);
		} else sleep(1);
	}
	return NULL;
}

#endif


///////////////////////////////////////////////////////////////////////////////
// SEND DCW
///////////////////////////////////////////////////////////////////////////////

void cs378x_senddcw_cli(struct camd35_client_data *cli)
{
	uint8_t buf[CC_MAXMSGSIZE];
	uint32_t ticks = GetTickCount();

	if (cli->ecm.status==STAT_DCW_SENT) {
		mlogf(LOGWARNING,getdbgflag(DBG_CS378X,0,cli->id)," +> cw send failed to cs378x client '%s', cw already sent\n", cli->user); 
		return;
	}
	if (cli->connection.status<=0) {
		mlogf(LOGWARNING,getdbgflag(DBG_CS378X,0,cli->id)," +> cw send failed to cs378x client '%s', client disconnected\n", cli->user); 
		return;
	}
	if (!cli->ecm.busy) {
		mlogf(LOGWARNING,getdbgflag(DBG_CS378X,0,cli->id)," +> cw send failed to cs378x client '%s', no ecm request\n", cli->user); 
		return;
	}

	ECM_DATA *ecm = cli->ecm.request;
	//FREEZE
	int samechannel = (cli->lastecm.caid==ecm->caid)&&(cli->lastecm.prov==ecm->provid)&&(cli->lastecm.sid==ecm->sid);
	int enablefreeze=0;
	if (samechannel) {
		if ( (cli->lastecm.hash!=ecm->hash)&&(cli->lastecm.tag!=ecm->ecm[0]) )
		if ( (cli->lastecm.status=1)&&(cli->lastdcwtime+200<ticks) ) enablefreeze = 1;
	} else cli->zap++;
	//
	cli->lastecm.caid = ecm->caid;
	cli->lastecm.prov = ecm->provid;
	cli->lastecm.sid = ecm->sid;
	cli->lastecm.hash = ecm->hash;
	cli->lastecm.tag = ecm->ecm[0];
	cli->lastecm.decodetime = ticks-cli->ecm.recvtime;
	cli->lastecm.request = cli->ecm.request;

	// SID
	buf[8] = (ecm->sid>>8) & 0xFF;
	buf[9] = (ecm->sid) & 0xFF;
	// CAID
	buf[10] = (ecm->caid>>8) & 0xFF;
	buf[11] = (ecm->caid) & 0xFF;
	// PROVID
	buf[12] = (ecm->provid>>24) & 0xFF;
	buf[13] = (ecm->provid>>16) & 0xFF;
	buf[14] = (ecm->provid>>8) & 0xFF;
	buf[15] = (ecm->provid) & 0xFF;
	// PIN
	buf[16] = (cli->ecm.pin>>8);
	buf[17] = cli->ecm.pin & 0xFF;

	if ( (ecm->dcwstatus==STAT_DCW_SUCCESS)&&(ecm->hash==cli->ecm.hash) ) {
		cli->lastecm.dcwsrctype = ecm->dcwsrctype;
		cli->lastecm.dcwsrcid = ecm->dcwsrcid;
		cli->lastecm.status=1;
		cli->ecmok++;
		cli->lastdcwtime = ticks;
		cli->ecmoktime += ticks-cli->ecm.recvtime;
		//cli->lastecmoktime = ticks-cli->ecm.recvtime;

		buf[0] = CAMD_ECM_REPLY;
		buf[1] = 16;
		// ECM
		memcpy( buf+20, ecm->cw, 16 );
		if ( !cs378x_send( cli->handle, &cli->encryptkey, cli->ucrc, buf, 20+16) ) {
			cs378x_disconnect_cli( cli );
			return;
		}
		mlogf(LOGINFO,getdbgflagpro(DBG_CS378X,0,cli->id,ecm->cs->id)," => cw to cs378x client '%s' ch %04x:%06x:%04x (%dms)\n", cli->user, ecm->caid,ecm->provid,ecm->sid, GetTickCount()-cli->ecm.recvtime);
	}
	else { //if (ecm->data->dcwstatus==STAT_DCW_FAILED)
		if (enablefreeze) {
			cli->freeze++;
		}
		cli->lastecm.dcwsrctype = DCW_SOURCE_NONE;
		cli->lastecm.dcwsrcid = 0;
		cli->lastecm.status=0;
		buf[0] = 0x44;
		buf[1] = 0;
		if ( !cs378x_send( cli->handle, &cli->encryptkey, cli->ucrc, buf, 20) ) {
			cs378x_disconnect_cli( cli );
			return;
		}
		mlogf(LOGINFO,getdbgflagpro(DBG_CS378X,0,cli->id,ecm->cs->id)," |> decode failed to cs378x client '%s' ch %04x:%06x:%04x (%dms)\n", cli->user, ecm->caid,ecm->provid,ecm->sid, GetTickCount()-cli->ecm.recvtime);
	}
	cli->ecm.busy=0;
	cli->ecm.status = STAT_DCW_SENT;
}

///////////////////////////////////////////////////////////////////////////////

// Check sending cw to clients
void cs378x_check_sendcw(ECM_DATA *ecm)
{
	struct camd35_server_data *cs378x = cfg.cs378x.server;
	while (cs378x) {
		if ( !IS_DISABLED(cs378x->flags) && (cs378x->handle>0) ) {
			struct camd35_client_data *cli = cs378x->client;
			while (cli) {
				if ( !IS_DISABLED(cli->flags)&&(cli->handle>0)&&(cli->ecm.busy)&&(cli->ecm.request==ecm) ) {
					cs378x_senddcw_cli( cli );
				}
				cli = cli->next;
			}
		}
		cs378x = cs378x->next;
	}
}



///////////////////////////////////////////////////////////////////////////////
// RECV MSG
///////////////////////////////////////////////////////////////////////////////

void cs378x_store_ecmclient(ECM_DATA *ecm, struct camd35_client_data *cli)
{
	uint32_t ticks = GetTickCount();
	cli->ecm.recvtime = ticks;
	cli->ecm.request = ecm;
    cli->ecm.status = STAT_ECM_SENT;
	ecm_addip(ecm, cli->ip);
}

void cs378x_cli_recvmsg( struct camd35_client_data *cli )
{
	struct cardserver_data *cs;
	uint8_t cw[16];
	uint8_t buf[2048];
	// Get MSG
    int len = cs378x_msg_peek( cli->handle, cli->ucrc, &cli->decryptkey, buf);
	if (len<=0) {
		mlogf(LOGWARNING,getdbgflag(DBG_CS378X,0,cli->id)," cs378x: read failed from client '%s'\n", cli->user);
		cs378x_disconnect_cli(cli);
		return;
	}
	//mlogf(LOGDEBUG,getdbgflag(DBG_CS378X,0,cli->id), " cs378x: msg from client '%s' \n", cli->user); //debughex(buf, len);

	uint32_t ticks = GetTickCount();

	switch (buf[4]) {
		// Keepalive
		case CAMD_KEEPALIVE:
			//mlogf(LOGDEBUG,0," camd35: Keepalive from client '%s'\n", cli->user);
			if ( !cs378x_send( cli->handle, &cli->encryptkey, cli->ucrc, buf+4, 20+1) ) cs378x_disconnect_cli( cli );
			else if (cli->connection.status<=0) {
				mlogf(LOGINFO,getdbgflag(DBG_CS378X,0,cli->id)," cs378x: client '%s' connected\n", cli->user);
				cli->connection.status = 1;
				cli->connection.time = GetTickCount();
			}
			break;

#ifdef CACHEEX
		// Request Nodeid
		case CAMD_CEX_IDREQUEST:
			//mlogf(LOGDEBUG,0," camd35: Nodeid from client '%s'\n", cli->user);
			memcpy( cli->nodeid, buf+24, 8);
			memset(buf, 0, 20+12);
			buf[0] = CAMD_CEX_IDREPLY;
			buf[1] = 12;
			memcpy( buf+20, cfg.nodeid, 8);
			if ( !cs378x_send( cli->handle, &cli->encryptkey, cli->ucrc, buf, 20+12) ) cs378x_disconnect_cli( cli );
			else if (cli->connection.status<=0) {
				char str[8*3+1];
				array2hex( cli->nodeid, str, 8);
				mlogf(LOGINFO,getdbgflag(DBG_CS378X,0,cli->id)," cs378x: client '%s' connected, Nodeid = %s\n", cli->user, str);
				cli->connection.status = 1;
				cli->connection.time = GetTickCount();
			}
			break;

		// push out
		case CAMD_CEX_PUSH:
			if (cli->cacheex_mode!=3) break;
			memcpy( cw, buf+44, 16);
			struct cache_data cacheex;
			cacheex.sid = (buf[12]<<8)|buf[13];
			cacheex.caid = (buf[14]<<8)|buf[15];
			cacheex.provid = (buf[16]<<24)|(buf[17]<<16)|(buf[18]<<8)|buf[19];
			// Look for cardserver
			cs = getcsbycaprovid(cacheex.caid, cacheex.provid);
			if ( !cs || !cs->option.fallowcacheex ) {
				cli->cacheex.badcw++;
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
			cli->cacheex.got[0]++;
			int uphop = buf[60];
			if (uphop<10) cli->cacheex.got[uphop]++;
			//
			pthread_mutex_lock( &prg.lockcache );
			int res = cache_setdcw( &cacheex, cw, NO_CYCLE, PEER_CS378X_CLIENT | cli->id );
			pthread_mutex_unlock( &prg.lockcache );
			if (res&DCW_ERROR) {
				if ( !(res&DCW_SKIP) ) cli->cacheex.badcw++;
			}
			else if (res&DCW_CYCLE) {
				if ( cs->option.cacheex.maxhop>uphop ) {
					uint8_t nodeid[8];
					memcpy( nodeid, buf+61, 8);
					pipe_send_cacheex_push_cache(&cacheex, cw, nodeid); //cacheex_push(&cacheex, cw, nodeid);
				}
			}
			//mlogf(LOGDEBUG,getdbgflag(DBG_CS378X,0,cli->id)," cs378x: push from client '%s' %04x:%06x:%04x|%02x:%08x\n", cli->user, cacheex.caid,cacheex.provid,cacheex.sid, cacheex.tag,cacheex.hash);
			break;
#endif

		case CAMD_ECM_REQUEST:
			cli->ecmnb++;
			cli->lastecmtime = ticks;
			//Check for card availability
			int ecmlen = (((buf[25] & 0x0f) << 8) | buf[26]) + 3;
			uint8_t ecmdata[512];
			memcpy( ecmdata, buf+24, ecmlen );
			uint16_t pin = buf[4+16]<<8 | buf[4+17];
			uint16_t sid = buf[4+8]<<8 | buf[4+9];
			uint16_t caid = buf[4+10]<<8 | buf[4+11];
			uint32_t provid = ecm_getprovid( ecmdata, caid );
			if (provid==0) provid = buf[4+12]<<24 | buf[4+13]<<16 | buf[4+14]<<8 | buf[4+15];
			if ( !caid ) {
				cli->ecmdenied++;
				buf[4] = 0x44;
				buf[5] = 0;
				if ( !cs378x_send( cli->handle, &cli->encryptkey, cli->ucrc, buf+4, 20) ) cs378x_disconnect_cli( cli );
				else mlogf(LOGINFO,getdbgflag(DBG_CS378X,0,cli->id)," <!> decode failed to cs378x client '%s' ch %04x:%06x:%04x Invalid CAID\n", cli->user,caid,provid,sid);
				break;
			}
			// Look for cardserver
			cs = cfg.cardserver;
			while (cs) {
				if (caid==cs->card.caid) {
					int j;
					for (j=0; j<cs->card.nbprov;j++) if (provid==cs->card.prov[j].id) break;
					if (j<cs->card.nbprov) break;
				}
				cs = cs->next;
			}
			if (!cs) {
				cli->ecmdenied++;
				buf[4] = 0x44;
				buf[5] = 0;
				if ( !cs378x_send( cli->handle, &cli->encryptkey, cli->ucrc, buf+4, 20) ) cs378x_disconnect_cli( cli );
				else mlogf(LOGINFO,getdbgflag(DBG_CS378X,0,cli->id)," <!> decode failed to client '%s' ch %04x:%06x:%04x, Invalid CAID/PROVIDER\n", cli->user,caid,provid,sid);
				break;
			}
			// Check for Accepted sids
			uint8_t cw1cycle;
			if ( !accept_sid(cs, provid, sid, ecm_getchid(ecmdata,caid), ecmlen, &cw1cycle) ) {
				cli->ecmdenied++;
				cs->ecmdenied++;
				buf[4] = 0x44;
				buf[5] = 0;
				if ( !cs378x_send( cli->handle, &cli->encryptkey, cli->ucrc, buf+4, 20) ) cs378x_disconnect_cli( cli );
				else mlogf(LOGINFO,getdbgflagpro(DBG_CS378X,0,cli->id,cs->id)," <!> decode failed to cs378x client '%s' ch %04x:%06x:%04x SID not accepted\n", cli->user,caid,provid,sid);
				break;
			}

			// ACCEPTED
			pthread_mutex_lock(&prg.lockecm); //###
			// Search for ECM
			ECM_DATA *ecm = search_ecmdata_any(cs, ecmdata,  ecmlen, sid, caid); // dont get failed ecm request from cache
			int isnew =  ( ecm==NULL );
			if (ecm) {
				ecm->lastrecvtime = ticks;
				if (ecm->dcwstatus==STAT_DCW_FAILED) {
					if (ecm->period > cs->option.dcw.retry) {
						buf[4] = 0x44;
						buf[5] = 0;
						if ( !cs378x_send( cli->handle, &cli->encryptkey, cli->ucrc, buf+4, 20) ) cs378x_disconnect_cli( cli );
						else mlogf(LOGINFO,getdbgflagpro(DBG_CS378X,0,cli->id, cs->id)," <!> decode failed to cs378x client '%s' ch %04x:%06x:%04x:%08x, already failed\n",cli->user, caid, provid, sid, ecm->hash);
					}
					else {
						ecm->period++; // RETRY
						cs378x_store_ecmclient(ecm, cli);
						mlogf(LOGINFO,getdbgflagpro(DBG_CS378X,0,cli->id, cs->id)," <- ecm from cs378x client '%s' ch %04x:%06x:%04x:%08x**\n", cli->user, caid, provid, sid, ecm->hash);
						cli->ecm.busy=1;
						cli->ecm.pin = pin;
						cli->ecm.hash = ecm->hash;
						ecm->dcwstatus = STAT_DCW_WAIT;
						ecm->cachestatus = 0; //ECM_CACHE_NONE; // Resend Request
						ecm->checktime = 1; // Check NOW
						pipe_wakeup( prg.pipe.ecm[1] );
					}
				}
				else { // SUCCESS/WAIT
					cs378x_store_ecmclient(ecm, cli);
					cli->ecm.pin = pin;
					mlogf(LOGINFO,getdbgflagpro(DBG_CS378X,0,cli->id, cs->id)," <- ecm from cs378x client '%s' ch %04x:%06x:%04x:%08x*\n", cli->user, caid, provid, sid, ecm->hash);
					cli->ecm.busy=1;
					cli->ecm.hash = ecm->hash;
					if (cli->dcwcheck) {
						if ( !ecm->lastdecode.ecm && (ecm->lastdecode.ecm!=ecm) ) {
							checkfreeze_checkECM( ecm, cli->lastecm.request);
							if (ecm->lastdecode.ecm) pipe_cache_find(ecm, cs);
						}
					}
					// Check for Success/Timeout
					if (!ecm->checktime) {
						pthread_mutex_unlock(&prg.lockecm);
						cs378x_senddcw_cli(cli);
						break;
						if ( cli->dcwcheck && !cs->option.dcw.halfnulled && (ecm->dcwstatus==STAT_DCW_SUCCESS) && !checkfreeze_setdcw(ecm,ecm->cw) ) { // ??? last ecm is wrong
							ecm->dcwstatus = STAT_DCW_WAIT;
							memset( ecm->cw, 0, 16 );
							ecm->checktime = 1; // Wakeup Now
							pipe_wakeup( prg.pipe.ecm[1] );
						}
						else {
							pthread_mutex_unlock(&prg.lockecm);
							cs378x_senddcw_cli(cli);
							break;
						}
					}
				}
			}
			else {
				cs->ecmaccepted++;
				// Setup ECM Request for Server(s)
				ecm = store_ecmdata(cs, ecmdata, ecmlen, sid,caid,provid);
				cs378x_store_ecmclient(ecm, cli);
				cli->ecm.pin = pin;
				mlogf(LOGINFO,getdbgflagpro(DBG_CS378X,0,cli->id, cs->id)," <- ecm from cs378x client '%s' ch %04x:%06x:%04x:%08x\n",cli->user,caid,provid,sid, ecm->hash);
				cli->ecm.busy=1;
				cli->ecm.hash = ecm->hash;
				ecm->cw1cycle = cw1cycle;
				ecm->dcwstatus = STAT_DCW_WAIT;
#ifdef CHECK_NEXTDCW
				if (cli->dcwcheck) checkfreeze_checkECM( ecm, cli->lastecm.request);
#endif
				if (cs->option.fallowcache) {
					ecm->waitcache = 1;
					ecm->dcwstatus = STAT_DCW_WAITCACHE;
					ecm->checktime = ecm->recvtime + cs->option.cachetimeout;
					pipe_cache_find(ecm, cs);
				}
				else ecm->checktime = 1; // Check NOW
				pipe_wakeup( prg.pipe.ecm[1] );
			}
			pthread_mutex_unlock(&prg.lockecm);
			if (isnew) wakeup_sendecm();
			break;



#ifndef PUBLIC
		case  0x80:    // ECM
		case  0x81:    // ECM
			cli->lastecmtime = ticks;
			cli->cacheex.got[0]++;
			//Check for card availability
			ecmlen = (((buf[25] & 0x0f) << 8) | buf[26]) + 3;
			memcpy( ecmdata, buf+24, ecmlen );
			sid = buf[4+8]<<8 | buf[4+9];
			caid = buf[4+10]<<8 | buf[4+11];
			provid = ecm_getprovid( ecmdata, caid );
			if (provid==0) provid = buf[4+12]<<24 | buf[4+13]<<16 | buf[4+14]<<8 | buf[4+15];
			if ( !caid ) {
				cli->ecmdenied++;
				mlogf(LOGINFO,getdbgflag(DBG_CS378X,0,cli->id)," <|> decode failed to cs378x client '%s' ch %04x:%06x:%04x Invalid CAID\n", cli->user,caid,provid,sid);
				break;
			}
			// Look for cardserver
			cs = cfg.cardserver;
			while (cs) {
				if (caid==cs->card.caid) {
					int j;
					for (j=0; j<cs->card.nbprov;j++) if (provid==cs->card.prov[j].id) break;
					if (j<cs->card.nbprov) break;
				}
				cs = cs->next;
			}
			if (!cs) {
				cli->ecmdenied++;
				mlogf(LOGINFO,getdbgflag(DBG_CS378X,0,cli->id)," <|> decode failed to client '%s' ch %04x:%06x:%04x, Invalid CAID/PROVIDER\n", cli->user,caid,provid,sid);
				break;
			}
			// Check for Accepted sids
			if ( !accept_sid(cs, provid, sid, ecm_getchid(ecmdata,caid), ecmlen, &cw1cycle) ) {
				cli->ecmdenied++;
				cs->ecmdenied++;
				mlogf(LOGINFO,getdbgflagpro(DBG_CS378X,0,cli->id,cs->id)," <|> decode failed to cs378x client '%s' ch %04x:%06x:%04x SID not accepted\n", cli->user,caid,provid,sid);
				break;
			}
			// ACCEPTED
			pthread_mutex_lock(&prg.lockecm); //###
			// Search for ECM
			ecm = search_ecmdata_any(cs, ecmdata,  ecmlen, sid, caid); // dont get failed ecm request from cache
			if (ecm) {
				ecm->lastrecvtime = ticks;
				if (ecm->dcwstatus==STAT_DCW_FAILED) {
					mlogf(LOGINFO,getdbgflagpro(DBG_CS378X,0,cli->id, cs->id)," <- ecm from cs378x client '%s' ch %04x:%06x:%04x:%08x**\n",cli->user,caid,provid,sid,ecm->hash);
					ecm->recvtime = ticks;
					ecm->dcwstatus = STAT_DCW_WAIT;
					ecm->cachestatus = 0; //ECM_CACHE_NONE; // Resend Request
					ecm->checktime = 1; // Check NOW
				}
				else {
					//TODO: Add another card for sending ecm
					mlogf(LOGINFO,getdbgflagpro(DBG_CS378X,0,cli->id, cs->id)," <- ecm from cs378x client '%s' ch %04x:%06x:%04x:%08x*\n",cli->user,caid,provid,sid,ecm->hash);
#ifdef CACHEEX
					// Check for Success/Timeout
					if (!ecm->checktime) pipe_send_cacheex_push_out(ecm);
#endif
				}
			}
			else {
				cs->ecmaccepted++;
				// Setup ECM Request for Server(s)
				ecm = store_ecmdata(cs, ecmdata, ecmlen, sid,caid,provid);
				mlogf(LOGINFO,getdbgflagpro(DBG_CS378X,0,cli->id, cs->id)," <- ecm from cs378x client '%s' ch %04x:%06x:%04x:%08x\n",cli->user,caid,provid,sid,ecm->hash);
				ecm->cw1cycle = cw1cycle;
				ecm->dcwstatus = STAT_DCW_WAIT;
				ecm->checktime = 1; // Check NOW

				// Check Cycle
				if ( (buf[4]&0xFE)==0x80 ) {
					// Setup Cw Cycle
					if (buf[4]==0x80) ecm->lastdecode.cwcycle = '0';
					else if (buf[4]==0x81) ecm->lastdecode.cwcycle = '1';
					ecm->lastdecode.ecm = ecm; // status -> last ecm
					ecm->lastdecode.counter = 3;
					ecm->lastdecode.dcwchangetime = buf[4+20+ecmlen+16]*1000;
					memcpy( ecm->lastdecode.dcw, buf+4+20+ecmlen, 16); // Store latest DCW
				}

				if (cs->option.fallowcache) {
					ecm->waitcache = 1;
					ecm->dcwstatus = STAT_DCW_WAITCACHE;
					ecm->checktime = ecm->recvtime + cs->option.cachetimeout;
					pipe_cache_find(ecm, cs);
				}
				else ecm->checktime = 1; // Check NOW
				pipe_wakeup( prg.pipe.ecm[1] );
			}
			pthread_mutex_unlock(&prg.lockecm); //###
			break;	//camd35_process_ecm(mbuf, n);
#endif 
	}
}

//xxx: host port user pass { cacheex_mode = 3; shares = 0500:42400&42800; }
void cs378x_recv_pipe()
{
	uint8_t buf[64];
	struct pollfd pfd;
	do {
		pipe_recv( prg.pipe.cs378x[0], buf);
		pfd.fd = prg.pipe.cs378x[0];
		pfd.events = POLLIN | POLLPRI;
	} while (poll(&pfd, 1, 0)>0);
}

///////////////////////////////////////////////////////////////////////////////
void *cs378x_recvmsg_thread(void *param)
{
#ifndef PUBLIC
	cfg.cs378x.pid_recvmsg = syscall(SYS_gettid);
	prctl(PR_SET_NAME,"cs378x RecvMSG",0,0,0);
#endif

	while (!prg.restart) {
		struct pollfd pfd[MAX_CSPORTS];
		int pfdcount = 0;

		pfd[pfdcount].fd = prg.pipe.cs378x[0];
		pfd[pfdcount++].events = POLLIN | POLLPRI;
		
		struct camd35_server_data *cs378x = cfg.cs378x.server;
		while (cs378x) {
			if ( !IS_DISABLED(cs378x->flags)&&(cs378x->handle>0) ) {
				struct camd35_client_data *cli = cs378x->client;
				while (cli) {
					if (cli->connection.status>0) {
						cli->ipoll = pfdcount;
						pfd[pfdcount].fd = cli->handle;
						pfd[pfdcount++].events = POLLIN | POLLPRI;
					} else cli->ipoll = -1;
					cli = cli->next;
				}
			}
			cs378x = cs378x->next;
		}

		int retval = poll(pfd, pfdcount, 3000);

		if (retval>0) {

			struct camd35_server_data *cs378x = cfg.cs378x.server;
			while (cs378x) {
				if ( !IS_DISABLED(cs378x->flags)&&(cs378x->handle>0) ) {
					struct camd35_client_data *client = cs378x->client;
					while (client) {
						if ( (client->handle>0) && (client->ipoll>=0) && (client->handle==pfd[client->ipoll].fd) ) {
							if ( pfd[client->ipoll].revents & (POLLIN|POLLPRI) ) {
								cs378x_cli_recvmsg( client );
							}
						}
						client = client->next;
					}
				}
				cs378x = cs378x->next;
			}

			if ( pfd[0].revents & (POLLIN|POLLPRI) ) cs378x_recv_pipe();

		} else if (retval<0) usleep(99000);
	}
	return NULL;
}


///////////////////////////////////////////////////////////////////////////////
// CAMD35 CACHEEX RECVMSG
///////////////////////////////////////////////////////////////////////////////

void cs378x_cacheex_recv_pipe()
{
	uint8_t buf[64];
	struct pollfd pfd;
	do {
		pipe_recv( prg.pipe.cs378x_cex[0], buf);
		pfd.fd = prg.pipe.cs378x_cex[0];
		pfd.events = POLLIN | POLLPRI;
	} while (poll(&pfd, 1, 0)>0);
}

///////////////////////////////////////////////////////////////////////////////
void *cs378x_cacheex_recvmsg_thread(void *param)
{
#ifndef PUBLIC
	cfg.cs378x.pid_recvmsg = syscall(SYS_gettid);
	prctl(PR_SET_NAME,"cs378x RecvMSG",0,0,0);
#endif

	while (!prg.restart) {
		struct pollfd pfd[MAX_CSPORTS];
		int pfdcount = 0;

		pfd[pfdcount].fd = prg.pipe.cs378x_cex[0];
		pfd[pfdcount++].events = POLLIN | POLLPRI;
		
		struct camd35_server_data *cs378x = cfg.cs378x.server;
		while (cs378x) {
			if ( !IS_DISABLED(cs378x->flags)&&(cs378x->handle>0) ) {
				struct camd35_client_data *cli = cs378x->cacheexclient;
				while (cli) {
					if (cli->connection.status>0) {
						cli->ipoll = pfdcount;
						pfd[pfdcount].fd = cli->handle;
						pfd[pfdcount++].events = POLLIN | POLLPRI;
					} else cli->ipoll = -1;
					cli = cli->next;
				}
			}
			cs378x = cs378x->next;
		}

		int retval = poll(pfd, pfdcount, 3000);

		if (retval>0) {

			struct camd35_server_data *cs378x = cfg.cs378x.server;
			while (cs378x) {
				if ( !IS_DISABLED(cs378x->flags)&&(cs378x->handle>0) ) {
					struct camd35_client_data *client = cs378x->cacheexclient;
					while (client) {
						if ( (client->handle>0) && (client->ipoll>=0) && (client->handle==pfd[client->ipoll].fd) ) {
							if ( pfd[client->ipoll].revents & (POLLIN|POLLPRI) ) {
								cs378x_cli_recvmsg( client );
							}
						}
						client = client->next;
					}
				}
				cs378x = cs378x->next;
			}

			if ( pfd[0].revents & (POLLIN|POLLPRI) ) cs378x_cacheex_recv_pipe();

		} else if (retval<0) usleep(99000);
	}
	return NULL;
}

///////////////////////////////////////////////////////////////////////////////
// CAMD35 SERVER: START/STOP
///////////////////////////////////////////////////////////////////////////////

int start_thread_cs378x()
{
	pthread_t tid;
#ifndef MONOTHREAD_ACCEPT
	create_thread(&tid, cs378x_accept_thread,NULL);
#endif

	create_thread(&cfg.cs378x.tid_recvmsg, cs378x_cacheex_recvmsg_thread,NULL);
	create_thread(&cfg.cs378x.tid_recvmsg, cs378x_recvmsg_thread,NULL);
	return 0;
}

