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


struct camd35_server_data *getcamd35serverbyid(uint32_t id)
{
	struct camd35_server_data *camd35 = cfg.camd35.server;
	while (camd35) {
		if (!(camd35->flags&FLAG_DELETE))
			if (camd35->id==id) return camd35;
		camd35 = camd35->next;
	}
	return NULL;
}

struct camd35_client_data *getcamd35clientbyid(uint32_t id)
{
	struct camd35_server_data *camd35 = cfg.camd35.server;
	while (camd35) {
		if (!(camd35->flags&FLAG_DELETE)) {
			struct camd35_client_data *cli = camd35->client;
			while (cli) {
				if (!(cli->flags&FLAG_DELETE))
					if (cli->id==id) return cli;
				cli = cli->next;
			}
		}
		camd35 = camd35->next;
	}
	return NULL;
}


///////////////////////////////////////////////////////////////////////////////
// CONNECT
///////////////////////////////////////////////////////////////////////////////

void camd35_disconnect_cli(struct camd35_client_data *cli)
{
	if (cli->connection.status>0) {
		cli->connection.status = 0;
		uint32_t ticks = GetTickCount();
		cli->connection.uptime += ticks - cli->connection.time;
		cli->connection.lastseen = ticks; // Last Seen
		cli->handle = -1;
		mlogf(LOGINFO,0," camd35: client '%s' disconnected \n", cli->user);
	}
}


void *camd35_connect_cli_thread(void *param);


///////////////////////////////////////////////////////////////////////////////
// SEND DCW
///////////////////////////////////////////////////////////////////////////////

void camd35_senddcw_cli(struct camd35_server_data *camd35, struct camd35_client_data *cli)
{
	uint8_t buf[CC_MAXMSGSIZE];
	uint32_t ticks = GetTickCount();

	if (cli->ecm.status==STAT_DCW_SENT) {
		mlogf(LOGWARNING,getdbgflag(DBG_CAMD35,0,cli->id)," +> cw send failed to camd35 client '%s', cw already sent\n", cli->user); 
		return;
	}
/*
	if (cli->connection.status<=0) {
		mlogf(LOGWARNING,getdbgflag(DBG_CAMD35,0,cli->id)," +> cw send failed to camd35 client '%s', client disconnected\n", cli->user); 
		return;
	}
*/
	if (!cli->ecm.busy) {
		mlogf(LOGWARNING,getdbgflag(DBG_CAMD35,0,cli->id)," +> cw send failed to camd35 client '%s', no ecm request\n", cli->user); 
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

	memset( buf, 0xFF, 20+16);
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
		camd35_sendto( camd35->handle, cli->ip, cli->port, &cli->encryptkey, cli->ucrc, buf, 20+16);
		mlogf(LOGINFO,getdbgflagpro(DBG_CAMD35,0,cli->id,ecm->cs->id)," => cw to camd35 client '%s' ch %04x:%06x:%04x (%dms)\n", cli->user, ecm->caid,ecm->provid,ecm->sid, GetTickCount()-cli->ecm.recvtime);
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
		camd35_sendto( camd35->handle, cli->ip, cli->port, &cli->encryptkey, cli->ucrc, buf, 20);
		mlogf(LOGINFO,getdbgflagpro(DBG_CAMD35,0,cli->id,ecm->cs->id)," |> decode failed to camd35 client '%s' ch %04x:%06x:%04x (%dms)\n", cli->user, ecm->caid,ecm->provid,ecm->sid, GetTickCount()-cli->ecm.recvtime);
	}
	cli->ecm.busy=0;
	cli->ecm.status = STAT_DCW_SENT;
}

///////////////////////////////////////////////////////////////////////////////

// Check sending cw to clients
void camd35_check_sendcw(ECM_DATA *ecm)
{
	struct camd35_server_data *camd35 = cfg.camd35.server;
	while (camd35) {
		if ( !IS_DISABLED(camd35->flags) && (camd35->handle>0) ) {
			struct camd35_client_data *cli = camd35->client;
			while (cli) {
				if ( !IS_DISABLED(cli->flags)&&(cli->ecm.busy)&&(cli->ecm.request==ecm) ) {
					camd35_senddcw_cli(camd35, cli );
				}
				cli = cli->next;
			}
		}
		camd35 = camd35->next;
	}
}

///////////////////////////////////////////////////////////////////////////////
// RECV MSG
///////////////////////////////////////////////////////////////////////////////

void camd35_store_ecmclient(ECM_DATA *ecm, struct camd35_client_data *cli)
{
	uint32_t ticks = GetTickCount();
	cli->ecm.recvtime = ticks;
	cli->ecm.request = ecm;
    cli->ecm.status = STAT_ECM_SENT;
	ecm_addip(ecm, cli->ip);
}

void camd35_recvmsg( struct camd35_server_data *camd35 )
{
	unsigned int recv_ip;
	unsigned short recv_port;
	struct cardserver_data *cs;
	unsigned char buf[1024];
	uint8_t cw[16];

	struct sockaddr_in si_other;
	socklen_t slen = sizeof(si_other);

	int received = recvfrom( camd35->handle, buf, sizeof(buf), 0, (struct sockaddr*)&si_other, &slen);
	if ( (received<20)||(received>1020) ) return;
	memcpy( &recv_ip, &si_other.sin_addr, 4);
	recv_port = ntohs(si_other.sin_port);

#ifdef DEBUG_NETWORK
	if (flag_debugnet) {
		mlogf(LOGDEBUG,0," camd35: Recv data (%d) from address (%s:%d)\n", received, ip2string(recv_ip), recv_port );
		debughex(buf,received);
	}
#endif

	uint32_t ucrc = (buf[0]<<24)|(buf[1]<<16)|(buf[2]<<8)|buf[3];
	//Check for clients
	struct camd35_client_data *cli = camd35->client;
	while (cli) {
		if (cli->ucrc==ucrc) break;
		cli = cli->next;
	}
	if (!cli) {
		cli = camd35->cacheexclient;
		while (cli) {
			if (cli->ucrc==ucrc) break;
			cli = cli->next;
		}
	}
	if (!cli) {
		mlogf(LOGWARNING,getdbgflag(DBG_CAMD35,camd35->id,0)," camd35%d: Unknown Client UCRC=%08x (%s)\n", camd35->id, ucrc, ip2string(recv_ip));
		return;
	}
	if (IS_DISABLED(cli->flags)) { // Connect only enabled clients
		mlogf(LOGINFO,getdbgflag(DBG_CAMD35,camd35->id,0)," camd35%d: connection refused for client '%s' (%s), client disabled\n", camd35->id, cli->user, ip2string(recv_ip));
		return;
	}

	//
	cli->ip = recv_ip;
	cli->port = recv_port;
	aes_decrypt( &cli->decryptkey, buf+4, received-4);
	// Data length
	int len;
	if (buf[4] == 0) len = (((buf[25] & 0x0f) << 8) | buf[26]) + 3; //Fix for ECM request size > 255 (use ecm length field)
	else if ( (buf[4]&0xFC)==0x3C ) len = buf[5] | (buf[6] << 8);
	else len = buf[5];
	// Check for data-crc
	uint32_t datacrc = crc32(0L, buf+24, len);
	uint32_t x = (buf[8]<<24)|(buf[9]<<16)|(buf[10]<<8)|buf[11];
	if (x!=datacrc) {
		mlogf(LOGWARNING,0, " camd35: Bad crc got=%08x calculated=%08x\n", x, datacrc);
		return;
	}
	//
	uint32_t ticks = GetTickCount();
	cli->lastactivity = ticks;
	switch (buf[4]) {

#ifdef CACHEEX
		// Request Nodeid
		case CAMD_CEX_IDREQUEST:
			if (!cli->cacheex_mode) break;
			//mlogf(LOGDEBUG,0," camd35: Nodeid from client '%s'\n", cli->user);
			memcpy( cli->nodeid, buf+24, 8);
			memset(buf, 0, 20+12);
			buf[0] = CAMD_CEX_IDREPLY;
			buf[1] = 12;
			memcpy( buf+20, cfg.nodeid, 8);
			camd35_sendto( camd35->handle, cli->ip, cli->port, &cli->encryptkey, cli->ucrc, buf, 20+12);
			if (cli->connection.status<=0) {
				char str[8*3+1];
				array2hex( cli->nodeid, str, 8);
				mlogf(LOGINFO,0," camd35: CacheEX client '%s' connected, Nodeid = %s\n", cli->user, str);
				cli->connection.status = 1;
				cli->connection.time = GetTickCount();
				cli->handle = -1;
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
			int res = cache_setdcw( &cacheex, cw, NO_CYCLE, PEER_CAMD35_CLIENT | cli->id );
			pthread_mutex_unlock( &prg.lockcache );
			if (res&DCW_ERROR) {
				if ( !(res&DCW_SKIP)) cli->cacheex.badcw++;
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

		// Keepalive
		case CAMD_KEEPALIVE:
			//mlogf(LOGDEBUG,0," camd35: Keepalive from client '%s'\n", cli->user);
			camd35_sendto( camd35->handle, cli->ip, cli->port, &cli->encryptkey, cli->ucrc, buf+4, 20+1);
			if (cli->connection.status<=0) {
				mlogf(LOGINFO,0," camd35: client '%s' connected\n", cli->user);
				cli->connection.status = 1;
				cli->connection.time = GetTickCount();
				cli->handle = camd35->handle;
			}
			break;

		case CAMD_ECM_REQUEST:
			if (cli->cacheex_mode) break;
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
				camd35_sendto( camd35->handle, cli->ip, cli->port, &cli->encryptkey, cli->ucrc, buf+4, 20);
				mlogf(LOGINFO,getdbgflag(DBG_CAMD35,0,cli->id)," <!> decode failed to camd35 client '%s' ch %04x:%06x:%04x Invalid CAID\n", cli->user,caid,provid,sid);
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
				camd35_sendto( camd35->handle, cli->ip, cli->port, &cli->encryptkey, cli->ucrc, buf+4, 20);
				mlogf(LOGINFO,getdbgflag(DBG_CAMD35,0,cli->id)," <!> decode failed to camd35 client '%s' ch %04x:%06x:%04x, Invalid CAID/PROVIDER\n", cli->user,caid,provid,sid);
				break;
			}
			// Check for Accepted sids
			uint8_t cw1cycle;
			if ( !accept_sid(cs, provid, sid, ecm_getchid(ecmdata,caid), ecmlen, &cw1cycle) ) {
				cli->ecmdenied++;
				cs->ecmdenied++;
				buf[4] = 0x44;
				buf[5] = 0;
				camd35_sendto( camd35->handle, cli->ip, cli->port, &cli->encryptkey, cli->ucrc, buf+4, 20);
				mlogf(LOGINFO,getdbgflagpro(DBG_CAMD35,0,cli->id,cs->id)," <!> decode failed to camd35 client '%s' ch %04x:%06x:%04x SID not accepted\n", cli->user,caid,provid,sid);
				break;
			}

			// ACCEPTED
			pthread_mutex_lock(&prg.lockecm); //###
			// Search for ECM
			ECM_DATA *ecm = search_ecmdata_any(cs, ecmdata,  ecmlen, sid, caid); // dont get failed ecm request from cache
			if (ecm) {
				ecm->lastrecvtime = ticks;
				if (ecm->dcwstatus==STAT_DCW_FAILED) {
					if (ecm->period > cs->option.dcw.retry) {
						buf[4] = 0x44;
						buf[5] = 0;
						camd35_sendto( camd35->handle, cli->ip, cli->port, &cli->encryptkey, cli->ucrc, buf+4, 20);
						mlogf(LOGINFO,getdbgflagpro(DBG_CAMD35,0,cli->id, cs->id)," <!> decode failed to camd35 client '%s' ch %04x:%06x:%04x:%08x, already failed\n",cli->user, caid, provid, sid, ecm->hash);
					}
					else {
						ecm->period++; // RETRY
						camd35_store_ecmclient(ecm, cli);
						mlogf(LOGINFO,getdbgflagpro(DBG_CAMD35,0,cli->id, cs->id)," <- ecm from camd35 client '%s' ch %04x:%06x:%04x:%08x**\n", cli->user, caid, provid, sid, ecm->hash);
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
					camd35_store_ecmclient(ecm, cli);
					cli->ecm.pin = pin;
					mlogf(LOGINFO,getdbgflagpro(DBG_CAMD35,0,cli->id, cs->id)," <- ecm from camd35 client '%s' ch %04x:%06x:%04x:%08x*\n", cli->user, caid, provid, sid, ecm->hash);
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
						camd35_senddcw_cli(camd35,cli);
						break;
						if ( cli->dcwcheck && !cs->option.dcw.halfnulled && (ecm->dcwstatus==STAT_DCW_SUCCESS) && !checkfreeze_setdcw(ecm,ecm->cw) ) { // ??? last ecm is wrong
							ecm->dcwstatus = STAT_DCW_WAIT;
							memset( ecm->cw, 0, 16 );
							ecm->checktime = 1; // Wakeup Now
							pipe_wakeup( prg.pipe.ecm[1] );
						}
						else {
							pthread_mutex_unlock(&prg.lockecm);
							camd35_senddcw_cli(camd35,cli);
							break;
						}
					}
				}
			}
			else {
				cs->ecmaccepted++;
				// Setup ECM Request for Server(s)
				ecm = store_ecmdata(cs, ecmdata, ecmlen, sid,caid,provid);
				camd35_store_ecmclient(ecm, cli);
				cli->ecm.pin = pin;
				mlogf(LOGINFO,getdbgflagpro(DBG_CAMD35,0,cli->id, cs->id)," <- ecm from camd35 client '%s' ch %04x:%06x:%04x:%08x\n",cli->user,caid,provid,sid, ecm->hash);
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
			break;	//camd35_process_ecm(mbuf, n);

	}

}

//L: host port user pass { cacheex_mode = 3; shares = 0500:42400&42800; }


///////////////////////////////////////////////////////////////////////////////
void *camd35_recvmsg_thread(void *param)
{
	while (1) {
		struct pollfd pfd[MAX_CSPORTS];
		int pfdcount = 0;

		struct camd35_server_data *camd35 = cfg.camd35.server;
		while (camd35) {
			if (camd35->handle>0) {
				camd35->ipoll = pfdcount;
				pfd[pfdcount].fd = camd35->handle;
				pfd[pfdcount++].events = POLLIN | POLLPRI;
			} else camd35->ipoll = -1;
			camd35 = camd35->next;
		}

		if (pfdcount>0) {
			int retval = poll(pfd, pfdcount, 3000);
			if (retval>0) {
				struct camd35_server_data *camd35 = cfg.camd35.server;
				while (camd35) {
					if ( (camd35->handle>0) && (camd35->ipoll>=0) && (camd35->handle==pfd[camd35->ipoll].fd) ) {
						if ( pfd[camd35->ipoll].revents & (POLLIN|POLLPRI) ) {
							// UDP
							camd35_recvmsg( camd35 );
						}
					}
					camd35 = camd35->next;
				}
			} else if (retval<0) usleep(99000);
		} else sleep(1);
	}
}

///////////////////////////////////////////////////////////////////////////////
// CAMD35 SERVER: START/STOP
///////////////////////////////////////////////////////////////////////////////

pthread_t camd_cli_tid;
int start_thread_camd35()
{
	create_thread(&camd_cli_tid, camd35_recvmsg_thread,NULL);
	return 0;
}


