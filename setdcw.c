///////////////////////////////////////////////////////////////////////////////
// SETDCW
///////////////////////////////////////////////////////////////////////////////

inline void peer_hitprofile( struct cachepeer_data *peer, int csid )
{
	int i;
	for(i=0; i<MAX_CSPORTS; i++) {
		if (!peer->csporthit[i].csid) {
			peer->csporthit[i].csid = csid;
			peer->csporthit[i].hits = 1;
			break;
		}
		else if (peer->csporthit[i].csid==csid) {
			peer->csporthit[i].hits++;
			break;
		}
	}
}

#ifdef CACHEEX
inline void cacheex_cccam_hitprofile( struct cc_client_data *cli, int csid )
{
	int i;
	for(i=0; i<MAX_CSPORTS; i++) {
		if (!cli->csporthit[i].csid) {
			cli->csporthit[i].csid = csid;
			cli->csporthit[i].hits = 1;
			break;
		}
		else if (cli->csporthit[i].csid==csid) {
			cli->csporthit[i].hits++;
			break;
		}
	}
}

#ifdef CAMD35_SRV
inline void cacheex_camd35_hitprofile( struct camd35_client_data *cli, int csid )
{
	int i;
	for(i=0; i<MAX_CSPORTS; i++) {
		if (!cli->csporthit[i].csid) {
			cli->csporthit[i].csid = csid;
			cli->csporthit[i].hits = 1;
			break;
		}
		else if (cli->csporthit[i].csid==csid) {
			cli->csporthit[i].hits++;
			break;
		}
	}
}
#endif

#ifdef CS378X_SRV
inline void cacheex_cs378x_hitprofile( struct camd35_client_data *cli, int csid )
{
	int i;
	for(i=0; i<MAX_CSPORTS; i++) {
		if (!cli->csporthit[i].csid) {
			cli->csporthit[i].csid = csid;
			cli->csporthit[i].hits = 1;
			break;
		}
		else if (cli->csporthit[i].csid==csid) {
			cli->csporthit[i].hits++;
			break;
		}
	}
}
#endif

inline void cacheex_server_hitprofile( struct server_data *srv, int csid )
{
	int i;
	for(i=0; i<MAX_CSPORTS; i++) {
		if (!srv->csporthit[i].csid) {
			srv->csporthit[i].csid = csid;
			srv->csporthit[i].hits = 1;
			break;
		}
		else if (srv->csporthit[i].csid==csid) {
			srv->csporthit[i].hits++;
			break;
		}
	}
}

#endif


inline int dcwcheck_nds( ECM_DATA *ecm, uint8_t dcw[16], int swap )
{
	char nullcw[8] = "\0\0\0\0\0\0\0\0";
	//Must be halfnulled dcw
	//if ( memcmp(dcw,nullcw,3) && memcmp(dcw+8,nullcw,3) ) return 0;
	// get cwcycle
	int cwcycle = 0;
	if ( dcwcmp8(dcw,nullcw) ) cwcycle = 1;
	else if ( dcwcmp8(dcw+8,nullcw) ) cwcycle = 0;
	//
	//if (ecm->cw1cycle==0) return 1;
	if (0x81==ecm->ecm[0]) {
		if (cwcycle==1) return 1;
#ifdef DCWSWAP
		else if (swap) {
			char tmp[8];
			memcpy( tmp, dcw, 8);
			memcpy( dcw, dcw+8, 8);
			memcpy( dcw+8, tmp, 8);
			return 1;
		}
#endif
		else return 0;
	}
	else {
		if (cwcycle==0) return 1;
#ifdef DCWSWAP
		else if (swap) {
			char tmp[8];
			memcpy( tmp, dcw, 8);
			memcpy( dcw, dcw+8, 8);
			memcpy( dcw+8, tmp, 8);
			return 1;
		}
#endif
		else return 0;
	}
	
}





#ifndef THREAD_DCW

void ecm_setdcw( ECM_DATA *ecm, uint8_t dcw[16], int srctype, int srcid )
{
	char nullcw[16] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	if ( dcwcmp16(dcw,nullcw) ) return;

	struct cardserver_data *cs = ecm->cs;
	if (!cs) return;

	if ( dcwcmp8(dcw,nullcw) && dcwcmp8(dcw+8,nullcw) ) return;

	int cwpart = 2;
	if (ecm->cw1cycle) {
		if (ecm->ecm[0]==ecm->cw1cycle) cwpart = 1; else cwpart = 0;
	}
	else {
		if ( dcwcmp8(dcw,nullcw) ) cwpart = 1;
		else if ( dcwcmp8(dcw+8,nullcw) ) cwpart = 0;
	}

	if (ecm->dcwstatus==STAT_DCW_SUCCESS) {
		return;
	}
/*
	if ( !ecmdata_check_cw( ecm->ecm[0], ecm->hash, ecm->caid, ecm->provid, ecm->sid, dcw, cwpart) ) {
		return;
	}
*/

#ifndef PUBLIC
	if (srctype!=DCW_SOURCE_CACHE) {
		pthread_mutex_lock( &prg.lockcache );
		int f = cache_check_cw( ecm->recvtime, ecm->ecm[0], ecm->caid, ecm->hash, ecm->sid, dcw, cwpart);
		pthread_mutex_unlock( &prg.lockcache );
		if (!f) {
			return;
		}
	}
#endif

	// filter non-nds halfnulled cw
	if ( dcwcmp8(dcw,nullcw) || dcwcmp8(dcw+8,nullcw) ) {
		if ((ecm->caid>>8)!=9) {
			return;
		}
		int swap = 0;
#ifdef DCWSWAP
		if (cs)	if (cs->option.dcw.swap) swap = 1;
#endif
		if ( !dcwcheck_nds( ecm, dcw, swap) ) {
			return;
		}
	}

#ifdef CHECK_NEXTDCW
	if (cs->option.dcw.check && !cs->option.dcw.halfnulled) {
		int check = checkfreeze_setdcw(ecm,dcw);
		if (check==0) {
			ecm->lastdecode.error++;
			return;
		}
		else if (check==1) {
			ecm->lastdecode.counter = 0;
			ecm->lastdecode.cwcycle = 0;
		}
		else if (check&2) {
			ecm->lastdecode.counter++;
			if (check&4) ecm->lastdecode.cwcycle = '1';
			else ecm->lastdecode.cwcycle = '0';
		}
	}
#endif

#ifdef TESTCHANNEL
	int testchannel = ( (ecm->caid==cfg.testchn.caid) && (ecm->provid==cfg.testchn.provid) && (ecm->sid==cfg.testchn.sid) );
	if (testchannel) {
		char dump[64];
		array2hex( dcw, dump, 16);
		char temp[512];
		src2string(srctype, srcid, temp);
		mlogf(LOGINFO,0," =(setdcw)= from %s ch %04x:%06x:%04x/%02x:%08x => %s\n", temp, ecm->caid, ecm->provid, ecm->sid, ecm->ecm[0], ecm->hash, dump);
	}
#endif

	ecm->statusmsg = "Decode Success";
	int instant = (ecm->dcwstatus==STAT_DCW_WAITCACHE);
	ecm->dcwsrctype = srctype;
	ecm->dcwsrcid = srcid;
	ecm->dcwstatus = STAT_DCW_SUCCESS;
	ecm->checktime = 0;
	ecm->waitserver = 0;
	sid_newecm(ecm);
	memcpy( ecm->cw, dcw, 16 );

	// Check timeout
	uint32_t ecmtime = GetTickCount()-ecm->recvtime;
			/// if ( ecmtime > cs->option.dcw.timeout*ecm->period ) return;

	// Send DCW to clients
	clients_check_sendcw(ecm);

	// Update Stat
	cs->ecmok++;
	cs->ecmoktime += ecmtime;
	int time = (ecmtime+50)/100;
	if (time<99) cs->ttime[time]++; else cs->ttime[99]++;

	if (srctype==DCW_SOURCE_CACHE) {
		if (srcid&PEER_CSP) { // Cache
			struct cachepeer_data *peer = getpeerbyid(srcid&0xffff);
			if (peer) {
				// setup peer last used cache
				peer->lastcaid = ecm->caid;
				peer->lastprov = ecm->provid;
				peer->lastsid = ecm->sid;
				peer->lastdecodetime = ecmtime;
				// add to profiles hits
				peer_hitprofile( peer, cs->id );
				peer->hitnb++;
				cs->hits.csp++;
				cfg.cache.hits++;
				if (instant) {
					peer->ihitnb++;
					cs->hits.instant.csp++;
					cfg.cache.ihits++;
				}
			}
			if (time<99) cs->ttimecache[time]++; else cs->ttimecache[99]++;
		}

#ifdef CACHEEX
		else if (srcid&PEER_CCCAM_CLIENT) { // Cacheex
			struct cc_client_data *cli = getcecccamclientbyid(srcid&0xffff);
			if (cli) {
				// setup client last used cache
				cli->cacheex.lastcaid = ecm->caid;
				cli->cacheex.lastprov = ecm->provid;
				cli->cacheex.lastsid = ecm->sid;
				cli->cacheex.lastdecodetime = ecmtime;
				// add to profiles hits
				cacheex_cccam_hitprofile( cli, cs->id );
				cli->cacheex.hits++;
				cs->hits.cacheex++;
				cfg.cacheex.hits++;
				if (instant) {
					cfg.cacheex.ihits++;
					cs->hits.instant.cacheex++;
					cli->cacheex.ihits++;
				}
			}
			if (time<99) cs->ttimecacheex[time]++; else cs->ttimecacheex[99]++;
		}

#ifdef CAMD35_SRV
		//PEERID_CAMD35
		else if (srcid&PEER_CAMD35_CLIENT) {
			struct camd35_client_data *cli = getcamd35clientbyid(srcid&0xffff);
			if (cli) {
				// setup client last used cache
				cli->cacheex.lastcaid = ecm->caid;
				cli->cacheex.lastprov = ecm->provid;
				cli->cacheex.lastsid = ecm->sid;
				cli->cacheex.lastdecodetime = ecmtime;
				// add to profiles hits
				cacheex_camd35_hitprofile( cli, cs->id );
				cli->cacheex.hits++;
				cs->hits.cacheex++;
				cfg.cacheex.hits++;
				if (instant) {
					cfg.cacheex.ihits++;
					cs->hits.instant.cacheex++;
					cli->cacheex.ihits++;
				}
			}
			if (time<99) cs->ttimecacheex[time]++; else cs->ttimecacheex[99]++;
		}
#endif

#ifdef CS378X_SRV
		//PEERID_CS378X
		else if (srcid&PEER_CS378X_CLIENT) {
			struct camd35_client_data *cli = getcs378xclientbyid(srcid&0xffff);
			if (cli) {
				// setup client last used cache
				cli->cacheex.lastcaid = ecm->caid;
				cli->cacheex.lastprov = ecm->provid;
				cli->cacheex.lastsid = ecm->sid;
				cli->cacheex.lastdecodetime = ecmtime;
				// add to profiles hits
				cacheex_cs378x_hitprofile( cli, cs->id );
				cli->cacheex.hits++;
				cs->hits.cacheex++;
				cfg.cacheex.hits++;
				if (instant) {
					cfg.cacheex.ihits++;
					cs->hits.instant.cacheex++;
					cli->cacheex.ihits++;
				}
			}
			if (time<99) cs->ttimecacheex[time]++; else cs->ttimecacheex[99]++;
		}
#endif

		else if (srcid&PEER_CACHEEX_SERVER) {
			struct server_data *srv = getcesrvbyid( srcid&0xffff );
			if (srv) {
				// setup client last used cache
				srv->cacheex.lastcaid = ecm->caid;
				srv->cacheex.lastprov = ecm->provid;
				srv->cacheex.lastsid = ecm->sid;
				srv->cacheex.lastdecodetime = ecmtime;
				// add to profiles hits
				cacheex_server_hitprofile( srv, cs->id );
				srv->cacheex.hits++;
				cs->hits.cacheex++;
				cfg.cacheex.hits++;
				if (instant) {
					cfg.cacheex.ihits++;
					cs->hits.instant.cacheex++;
					srv->cacheex.ihits++;
				}
			}
			if (time<99) cs->ttimecacheex[time]++; else cs->ttimecacheex[99]++;
		}
#endif
	}
	else if (srctype==DCW_SOURCE_SERVER) {
		struct server_data *srv = getsrvbyid( srcid&0xffff );
		if (srv) srv->hits++;
		if (time<99) cs->ttimecards[time]++; else cs->ttimecards[99]++;
	}
#ifdef SRV_CSCACHE
	else if (srctype==DCW_SOURCE_CSCLIENT) {
		struct cs_client_data *cli = getnewcamdclientbyid( srcid&0xffff );
		if (cli) cli->cachedcw++;
		if (time<99) cs->ttimeclients[time]++; else cs->ttimeclients[99]++;
	}
	else if (srctype==DCW_SOURCE_MGCLIENT) {
		struct mg_client_data *cli = getmgcamdclientbyid( srcid&0xffff );
		if (cli) cli->cachedcw++;
		if (time<99) cs->ttimeclients[time]++; else cs->ttimeclients[99]++;
	}
#endif

#ifdef CACHEEX
	// Send DCW to CACHE-EX servers
	if ( cs->option.fallowcacheex )
	if (ecmtime<cs->option.cacheexvalidtime) { // only for ecm with low time
		pipe_send_cacheex_push_out(ecm);
	}
#endif

	// Send DCW to Cache if not sent
	if ( cs->option.fallowcache && cs->option.cachesendrep && !(ecm->cachestatus&ECM_CACHE_REP) ) {
		//if (ecm->from!=ECM_FROM_CACHEEX)
		pipe_cache_reply(ecm,cs); //Send Good Cache Reply
		ecm->cachestatus |= ECM_CACHE_REP;
	}

#ifdef CLI_CSCACHE
	// Send to Newcamd Cached Servers
	int i;
	for( i=0; i<20; i++ ) {
		if (!ecm->server[i].srvid) break;
		if (ecm->server[i].flag==ECM_SRV_REQUEST) {
			struct server_data *srv = getsrvbyid(ecm->server[i].srvid);
			if (!srv) continue;
			if (!srv->busy) continue;
			if ( (srv->type==TYPE_NEWCAMD)&&(srv->cscached) ) { // Send DCW to server
				struct cs_custom_data srvcd;
				unsigned char buf[32];
				srvcd.msgid = srv->ecm.msgid;
				srvcd.caid = ecm->caid;
				srvcd.sid = ecm->sid;
				srvcd.provid = ecm->provid;
				buf[0] = ecm->ecm[0] | 0x40; // 0xC0 | 0xC1
				buf[2] = 0x10;
				memcpy(&buf[3], &ecm->cw,16);
				if ( !cs_message_send( srv->handle, &srvcd, buf, 19, srv->sessionkey) ) disconnect_srv( srv );
			}
		}
	}
#endif
}


#endif



#ifdef THREAD_DCW

void ecm_setdcwdata( ECM_DATA *ecm, uint8_t dcw[16], int srctype, int srcid )
{
	char nullcw[16] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	if ( dcwcmp16(dcw,nullcw) ) return;

	struct cardserver_data *cs = ecm->cs;
	if (!cs) return;

	if ( dcwcmp8(dcw,nullcw) && dcwcmp8(dcw+8,nullcw) ) return;

	int cwpart = 2;
	if (ecm->cw1cycle) {
		if (ecm->ecm[0]==ecm->cw1cycle) cwpart = 1; else cwpart = 0;
	}
	else {
		if ( dcwcmp8(dcw,nullcw) ) cwpart = 1;
		else if ( dcwcmp8(dcw+8,nullcw) ) cwpart = 0;
	}

	pthread_mutex_lock(&prg.lockecm);

	if (ecm->dcwstatus==STAT_DCW_SUCCESS) {
		pthread_mutex_unlock(&prg.lockecm);
		return;
	}
/*
	if ( !ecmdata_check_cw( ecm->ecm[0], ecm->hash, ecm->caid, ecm->provid, ecm->sid, dcw, cwpart) ) {
		pthread_mutex_unlock(&prg.lockecm);
		return;
	}
*/

#ifndef PUBLIC
	if (srctype!=DCW_SOURCE_CACHE) {
		pthread_mutex_lock( &prg.lockcache );
		int f = cache_check_cw( ecm->recvtime, ecm->ecm[0], ecm->caid, ecm->hash, ecm->sid, dcw, cwpart);
		pthread_mutex_unlock( &prg.lockcache );
		if (!f) {
			pthread_mutex_unlock(&prg.lockecm);
			return;
		}
	}
#endif

	// filter non-nds halfnulled cw
	if ( dcwcmp8(dcw,nullcw) || dcwcmp8(dcw+8,nullcw) ) {
		if ((ecm->caid>>8)!=9) {
			pthread_mutex_unlock(&prg.lockecm);
			return;
		}
		int swap = 0;
#ifdef DCWSWAP
		if (cs)	if (cs->option.dcw.swap) swap = 1;
#endif
		if ( !dcwcheck_nds( ecm, dcw, swap) ) {
			pthread_mutex_unlock(&prg.lockecm);
			return;
		}
	}

#ifdef CHECK_NEXTDCW
	if (cs->option.dcw.check && !cs->option.dcw.halfnulled) {
		int check = checkfreeze_setdcw(ecm,dcw);
		if (check==0) {
			ecm->lastdecode.error++;
			pthread_mutex_unlock(&prg.lockecm);
			return;
		}
		else if (check==1) {
			ecm->lastdecode.counter = 0;
			ecm->lastdecode.cwcycle = 0;
		}
		else if (check&2) {
			ecm->lastdecode.counter++;
			if (check&4) ecm->lastdecode.cwcycle = '1';
			else ecm->lastdecode.cwcycle = '0';
		}
	}
#endif

#ifdef TESTCHANNEL
	int testchannel = ( (ecm->caid==cfg.testchn.caid) && (ecm->provid==cfg.testchn.provid) && (ecm->sid==cfg.testchn.sid) );
	if (testchannel) {
		char dump[64];
		array2hex( dcw, dump, 16);
		char temp[512];
		src2string(srctype, srcid, temp);
		mlogf(LOGINFO,0," =(setdcw)= from %s ch %04x:%06x:%04x/%02x:%08x => %s\n", temp, ecm->caid, ecm->provid, ecm->sid, ecm->ecm[0], ecm->hash, dump);
	}
#endif

	ecm->statusmsg = "Decode Success";
	int instant = (ecm->dcwstatus==STAT_DCW_WAITCACHE);
	ecm->dcwsrctype = srctype;
	ecm->dcwsrcid = srcid;
	ecm->dcwstatus = STAT_DCW_SUCCESS;
	ecm->checktime = 0;
	ecm->waitserver = 0;
	sid_newecm(ecm);
	memcpy( ecm->cw, dcw, 16 );

	pthread_mutex_unlock(&prg.lockecm);

	// Check timeout
	uint32_t ecmtime = GetTickCount()-ecm->recvtime;
	 //////if ( ecmtime > cs->option.dcw.timeout*ecm->period ) return;
	// Send DCW to clients
	clients_check_sendcw(ecm);

	// Update Stat
	cs->ecmok++;
	cs->ecmoktime += ecmtime;
	int time = (ecmtime+50)/100;
	if (time<99) cs->ttime[time]++; else cs->ttime[99]++;

	if (srctype==DCW_SOURCE_CACHE) {
		if (srcid&PEER_CSP) { // Cache
			struct cachepeer_data *peer = getpeerbyid(srcid&0xffff);
			if (peer) {
				// setup peer last used cache
				peer->lastcaid = ecm->caid;
				peer->lastprov = ecm->provid;
				peer->lastsid = ecm->sid;
				peer->lastdecodetime = ecmtime;
				// add to profiles hits
				peer_hitprofile( peer, cs->id );
				peer->hitnb++;
				cs->hits.csp++;
				cfg.cache.hits++;
				if (instant) {
					peer->ihitnb++;
					cs->hits.instant.csp++;
					cfg.cache.ihits++;
				}
			}
			if (time<99) cs->ttimecache[time]++; else cs->ttimecache[99]++;
		}

#ifdef CACHEEX
		else if (srcid&PEER_CCCAM_CLIENT) { // Cacheex
			struct cc_client_data *cli = getcecccamclientbyid(srcid&0xffff);
			if (cli) {
				// setup client last used cache
				cli->cacheex.lastcaid = ecm->caid;
				cli->cacheex.lastprov = ecm->provid;
				cli->cacheex.lastsid = ecm->sid;
				cli->cacheex.lastdecodetime = ecmtime;
				// add to profiles hits
				cacheex_cccam_hitprofile( cli, cs->id );
				cli->cacheex.hits++;
				cs->hits.cacheex++;
				cfg.cacheex.hits++;
				if (instant) {
					cfg.cacheex.ihits++;
					cs->hits.instant.cacheex++;
					cli->cacheex.ihits++;
				}
			}
			if (time<99) cs->ttimecacheex[time]++; else cs->ttimecacheex[99]++;
		}

#ifdef CAMD35_SRV
		//PEERID_CAMD35
		else if (srcid&PEER_CAMD35_CLIENT) {
			struct camd35_client_data *cli = getcamd35clientbyid(srcid&0xffff);
			if (cli) {
				// setup client last used cache
				cli->cacheex.lastcaid = ecm->caid;
				cli->cacheex.lastprov = ecm->provid;
				cli->cacheex.lastsid = ecm->sid;
				cli->cacheex.lastdecodetime = ecmtime;
				// add to profiles hits
				cacheex_camd35_hitprofile( cli, cs->id );
				cli->cacheex.hits++;
				cs->hits.cacheex++;
				cfg.cacheex.hits++;
				if (instant) {
					cfg.cacheex.ihits++;
					cs->hits.instant.cacheex++;
					cli->cacheex.ihits++;
				}
			}
			if (time<99) cs->ttimecacheex[time]++; else cs->ttimecacheex[99]++;
		}
#endif

#ifdef CS378X_SRV
		//PEERID_CS378X
		else if (srcid&PEER_CS378X_CLIENT) {
			struct camd35_client_data *cli = getcs378xclientbyid(srcid&0xffff);
			if (cli) {
				// setup client last used cache
				cli->cacheex.lastcaid = ecm->caid;
				cli->cacheex.lastprov = ecm->provid;
				cli->cacheex.lastsid = ecm->sid;
				cli->cacheex.lastdecodetime = ecmtime;
				// add to profiles hits
				cacheex_cs378x_hitprofile( cli, cs->id );
				cli->cacheex.hits++;
				cs->hits.cacheex++;
				cfg.cacheex.hits++;
				if (instant) {
					cfg.cacheex.ihits++;
					cs->hits.instant.cacheex++;
					cli->cacheex.ihits++;
				}
			}
			if (time<99) cs->ttimecacheex[time]++; else cs->ttimecacheex[99]++;
		}
#endif

		else if (srcid&PEER_CACHEEX_SERVER) {
			struct server_data *srv = getcesrvbyid( srcid&0xffff );
			if (srv) {
				// setup client last used cache
				srv->cacheex.lastcaid = ecm->caid;
				srv->cacheex.lastprov = ecm->provid;
				srv->cacheex.lastsid = ecm->sid;
				srv->cacheex.lastdecodetime = ecmtime;
				// add to profiles hits
				cacheex_server_hitprofile( srv, cs->id );
				srv->cacheex.hits++;
				cs->hits.cacheex++;
				cfg.cacheex.hits++;
				if (instant) {
					cfg.cacheex.ihits++;
					cs->hits.instant.cacheex++;
					srv->cacheex.ihits++;
				}
			}
			if (time<99) cs->ttimecacheex[time]++; else cs->ttimecacheex[99]++;
		}
#endif
	}
	else if (srctype==DCW_SOURCE_SERVER) {
		struct server_data *srv = getsrvbyid( srcid&0xffff );
		if (srv) srv->hits++;
		if (time<99) cs->ttimecards[time]++; else cs->ttimecards[99]++;
	}
#ifdef SRV_CSCACHE
	else if (srctype==DCW_SOURCE_CSCLIENT) {
		struct cs_client_data *cli = getnewcamdclientbyid( srcid&0xffff );
		if (cli) cli->cachedcw++;
		if (time<99) cs->ttimeclients[time]++; else cs->ttimeclients[99]++;
	}
	else if (srctype==DCW_SOURCE_MGCLIENT) {
		struct mg_client_data *cli = getmgcamdclientbyid( srcid&0xffff );
		if (cli) cli->cachedcw++;
		if (time<99) cs->ttimeclients[time]++; else cs->ttimeclients[99]++;
	}
#endif

#ifdef CACHEEX
	// Send DCW to CACHE-EX servers
	if ( cs->option.fallowcacheex )
	if (ecmtime<cs->option.cacheexvalidtime) { // only for ecm with low time
		pipe_send_cacheex_push_out(ecm);
	}
#endif

	// Send DCW to Cache if not sent
	if ( cs->option.fallowcache && cs->option.cachesendrep && !(ecm->cachestatus&ECM_CACHE_REP) ) {
		//if (ecm->from!=ECM_FROM_CACHEEX)
		pipe_cache_reply(ecm,cs); //Send Good Cache Reply
		ecm->cachestatus |= ECM_CACHE_REP;
	}

#ifdef CLI_CSCACHE
	// Send to Newcamd Cached Servers
	int i;
	for( i=0; i<20; i++ ) {
		if (!ecm->server[i].srvid) break;
		if (ecm->server[i].flag==ECM_SRV_REQUEST) {
			struct server_data *srv = getsrvbyid(ecm->server[i].srvid);
			if (!srv) continue;
			if (!srv->busy) continue;
			if ( (srv->type==TYPE_NEWCAMD)&&(srv->cscached) ) { // Send DCW to server
				struct cs_custom_data srvcd;
				unsigned char buf[32];
				srvcd.msgid = srv->ecm.msgid;
				srvcd.caid = ecm->caid;
				srvcd.sid = ecm->sid;
				srvcd.provid = ecm->provid;
				buf[0] = ecm->ecm[0] | 0x40; // 0xC0 | 0xC1
				buf[2] = 0x10;
				memcpy(&buf[3], &ecm->cw,16);
				if ( !cs_message_send( srv->handle, &srvcd, buf, 19, srv->sessionkey) ) disconnect_srv( srv );
			}
		}
	}
#endif
}





inline int get_setdcwdata(uint8_t *buf, void *ecm, uint8_t *dcw, int *srctype, int *srcid)
{
	int index = 1;
	memcpy(srctype, buf+index, sizeof(int) );
	index += sizeof(int);
	memcpy(srcid, buf+index, sizeof(int) );
	index += sizeof(int);
	memcpy( ecm, buf+index, sizeof(void*) );
	index += sizeof(void*);
	memcpy( dcw, buf+index, 16 );
	index+=16;
	return index;
}

int put_setdcwdata(uint8_t *buf, ECM_DATA *ecm, uint8_t *dcw, int srctype, int srcid )
{
	buf[0] = 55;
	int index = 1;
	memcpy(buf+index, &srctype, sizeof(int) );
	index += sizeof(int);
	memcpy(buf+index, &srcid, sizeof(int) );
	index += sizeof(int);
	memcpy( buf+index, &ecm, sizeof(void*) );
	index += sizeof(void*);
	memcpy( buf+index, dcw, 16 );
	index+=16;
	return index;
}


void ecm_setdcw( ECM_DATA *ecm, uint8_t dcw[16], int srctype, int srcid )
{
	uint8_t buf[64];
	int len = put_setdcwdata(buf, ecm, dcw, srctype, srcid );
	pipe_send( dcwpipe[1], buf, len);
}

void *setdcw_thread(void *param)
{

#ifndef PUBLIC
	prg.pid_setdcw = syscall(SYS_gettid);
	prg.tid_setdcw = pthread_self();
	prctl(PR_SET_NAME,"Set DCW",0,0,0);
#endif

	struct pollfd pfd;
	while (1) {
		pfd.fd = dcwpipe[0];
		pfd.events = POLLIN | POLLPRI;
		int retval = poll(&pfd, 1, 3000);
		if ( retval>0 ) {
			uint8_t buf[64];
			int len = pipe_recv( dcwpipe[0], buf);
			if (len>0) {
				ECM_DATA *ecm;
				uint8_t dcw[16];
				int srctype;
				int srcid;
				get_setdcwdata(buf, &ecm, dcw, &srctype, &srcid);
				ecm_setdcwdata( ecm, dcw, srctype, srcid );
			}
		}
	}
}

#endif
