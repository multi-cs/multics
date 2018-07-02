///////////////////////////////////////////////////////////////////////////////
// TOOLS
///////////////////////////////////////////////////////////////////////////////

static char CCcam[] = "CCcam";
static char CCcam_OScam[] = "CCcam/OScam";
static char CCcam_MultiCS[] = "CCcam/MCS";

struct cs_card_data *cc_getcardbyid( struct server_data *srv, uint32_t id )
{
	struct cs_card_data *card = srv->card;
	while (card) {
		if (card->shareid==id) return card;
		card = card->next;
	}
	return NULL;
}

///////////////////////////////////////////////////////////////////////////////
// SEND ECM
///////////////////////////////////////////////////////////////////////////////

int cc_sendecm_srv(struct server_data *srv, ECM_DATA *ecm)
{
	unsigned char buf[CC_MAXMSGSIZE];

	//if ( (srv->handle>0)&&(!srv->busy) ) {
	//	if (!cc_getcardbyid(srv, srv->busycardid)) return 0;
		//mlogf(LOGINFO,getdbgflag(DBG_SERVER, 0, srv->id), " -> ecm to CCcam server (%s:%d) ch %04x:%06x:%04x shareid %x\n", srv->host->name, srv->port,ecm->caid,ecm->provid,ecm->sid,srv->busycardid);
	buf[0] = ecm->caid>>8;
	buf[1] = ecm->caid&0xff;
	buf[2] = ecm->provid>>24;
	buf[3] = ecm->provid>>16;
	buf[4] = ecm->provid>>8;
	buf[5] = ecm->provid&0xff;
	// srv->busycardid is saved from srvtab_arrange()
	buf[6] = srv->busycardid>>24;
	buf[7] = srv->busycardid>>16;
	buf[8] = srv->busycardid>>8;
	buf[9] = srv->busycardid&0xff;
	buf[10] = ecm->sid>>8;
	buf[11] = ecm->sid&0xff;
	buf[12] = ecm->ecmlen;
	memcpy( &buf[13],&ecm->ecm[0], ecm->ecmlen);
	srv->lastecmtime = GetTickCount();
	srv->busy = 1;
	////srv->ecm.msgid = ecm->id;
	return cc_msg_send( srv->handle, &srv->sendblock, CC_MSG_ECM_REQUEST, 13+ecm->ecmlen, buf );
}

///////////////////////////////////////////////////////////////////////////////
// RECV MESSAGE
///////////////////////////////////////////////////////////////////////////////

void cc_srv_recvmsg(struct server_data *srv)
{     
	// Check
	if (srv->handle<=0) return;
	if (srv->type!=TYPE_CCCAM) return;
	// Variables
	unsigned char buf[CC_MAXMSGSIZE];
	struct cs_card_data *card;
	struct cardserver_data *cs;
	int i;
	ECM_DATA *ecm;
	// Get Message
	int len = cc_msg_peek( srv->handle, &srv->recvblock, &srv->msg, buf );
	if (len==0) disconnect_srv(srv);
	else if (len<0) {
		mlogf(LOGINFO,getdbgflag(DBG_SERVER, 0, srv->id), " Server CCcam (%s:%d) read failed %d (%d)\n", srv->host->name, srv->port, len, errno);
		disconnect_srv(srv);
	}
	else {
		uint32_t ticks = GetTickCount();

		switch (buf[1]) {
			case CC_MSG_CLI_INFO:
				mlogf(LOGINFO,getdbgflag(DBG_SERVER, 0, srv->id), " Client data ACK from Server (%s:%d)\n", srv->host->name,srv->port);
				break;

			case CC_MSG_ECM_REQUEST: // Get CW
				if (!srv->busy) {
					mlogf(LOGINFO,getdbgflag(DBG_SERVER, 0, srv->id), " [!] dcw error from server (%s:%d), unknown ecm request\n",srv->host->name,srv->port);
					break;
				}
#ifdef CACHEEX
				if (srv->cacheex_mode) {
					mlogf(LOGINFO,getdbgflag(DBG_SERVER, 0, srv->id), " [!] dcw error from cacheex server (%s:%d)\n",srv->host->name,srv->port);
					break;
				}
#endif
				uint8_t dcw[16];
				cc_crypt_cw( cfg.nodeid, srv->busycardid, &buf[4]);
				memcpy(dcw, &buf[4], 16);
				cc_decrypt(&srv->recvblock, buf+4, len-4); // additional crypto step				

				srv->busy = 0;
				pipe_cmd( prg.pipe.ecm[1], PIPE_SRV_AVAILABLE );

				srv->lastdcwtime = ticks;

				pthread_mutex_lock(&prg.lockecm); //###

				ecm = srv->ecm.request;
				if (!ecm) {
					mlogf(LOGINFO,getdbgflag(DBG_SERVER, 0, srv->id), " [!] error cw from server (%s:%d), ecm not found!!!\n",srv->host->name,srv->port);
					pthread_mutex_unlock(&prg.lockecm); //###
					srv->busy = 0;
					break;
				}
				// check for ECM???
				if (ecm->hash!=srv->ecm.hash) {
					mlogf(LOGINFO,getdbgflag(DBG_SERVER, 0, srv->id), " [!] error cw from server (%s:%d), ecm deleted!!!\n",srv->host->name,srv->port);
					pthread_mutex_unlock(&prg.lockecm); //###
					srv->busy = 0;
					break;
				}

				cs = ecm->cs;
				card = cc_getcardbyid( srv, srv->busycardid );
				if (!cs)
				{
					cs = getcsbycaprovid(ecm->caid, ecm->provid);
				}
				if(!cs)
				{
					// Log abnormal case when cs could not be found
					mlogf(LOGINFO,getdbgflag(DBG_SERVER,0,srv->id)," [!] dcw received from cccam server (%s:%d). Cannot find cs profile!!!\n",srv->host->name,srv->port);
				}
				int isnanoe0=ecm_isnanoe0(ecm->ecm,ecm->caid);
				if ( isnanoe0 )
					mlogf(LOGDEBUG,getdbgflag(DBG_SERVER,0,srv->id)," [!] viaccess nano e0 detected ch %04x:%06x:%04x\n",ecm->caid, ecm->provid, ecm->sid);
				// Check for DCW
				if (!acceptDCW( dcw, isnanoe0 ) ) {
					mlogf(LOGDEBUG,getdbgflag(DBG_SERVER,0,srv->id)," [!] dcw error from cccam server (%s:%d), bad dcw!!! ch %04x:%06x:%04x nanoe0=%d\n",srv->host->name,srv->port,ecm->caid, ecm->provid, ecm->sid, isnanoe0);
					srv->ecmerrdcw ++;
#ifdef SID_FILTER
					if (cs && card) {
						cardsids_update( card, ecm->provid, ecm->sid, -1);
						srv_cstatadd( srv, cs->id, 0 , 0);
					}
#endif
					ecm_setsrvflag(srv->ecm.request, srv->id, ECM_SRV_REPLY_FAIL);
					pthread_mutex_unlock(&prg.lockecm); //###
					break;
				}
//				else {

				srv->lastecmoktime = ticks-srv->lastecmtime;
				srv->ecmoktime += srv->lastecmoktime;
				srv->ecmok++;

				ecm_setsrvflagdcw(srv->ecm.request, srv->id, ECM_SRV_REPLY_GOOD,dcw);
#ifdef SID_FILTER
				if (cs && card) {
					cardsids_update( card, ecm->provid, ecm->sid, 1); /// + Card nodeID
					srv_cstatadd( srv, cs->id, 1 , srv->lastecmoktime);
				}
#endif
				if (card) {
					card->ecmoktime += ticks-srv->lastecmtime;
					card->ecmok++;
				}

				if (ecm->dcwstatus!=STAT_DCW_SUCCESS) {
					static char msg[] = "Good dcw from CCcam server";
					ecm->statusmsg = msg;
					mlogf(LOGINFO,getdbgflagpro(DBG_SERVER, 0, srv->id,cs->id), " <= cw from CCcam server (%s:%d) ch %04x:%06x:%04x (%dms)\n", srv->host->name,srv->port, ecm->caid,ecm->provid,ecm->sid, ticks-srv->lastecmtime);
					if (loglevel>=LOGDEBUG)
					{
			                	char dumpcw[64];
						char dumpecm[4*MAX_ECM_SIZE];
                				array2hex( dcw, dumpcw, 16);
						array2hex( ecm->ecm, dumpecm, ecm->ecmlen );
                				mlogf(LOGDEBUG,getdbgflagpro(DBG_SERVER, 0, srv->id,cs->id)," <= cw from CCcam server (%s:%d)- %04x:%06x:%04x/%s => %s\n", srv->host->name,srv->port, ecm->caid, ecm->provid, ecm->sid, dumpecm, dumpcw);
					}
					ecm_setdcw( ecm, dcw, DCW_SOURCE_SERVER, srv->id );
				}

				pthread_mutex_unlock(&prg.lockecm); //###
				wakeup_sendecm(); // Wakeup ecm waiting for availabe servers
				break;

			case CC_MSG_ECM_NOK1: // EAGAIN, Retry
/*
				if (!srv->busy) break;
				ecm = srv->busyecm;
				mlogf(LOGINFO,getdbgflag(DBG_SERVER, 0, srv->id), " <| decode1 failed from CCcam server (%s:%d) ch %04x:%06x:%04x (%dms)\n", srv->host->name,srv->port, ecm->caid,ecm->provid,ecm->sid, ticks-srv->lastecmtime);

				if ( (ticks-srv->lastecmtime)<CC_ECMRETRY_TIMEOUT ) {
					if (srv->retry<CC_ECMRETRY_MAX) {
						srv->busy = 0;
						if (cc_sendecm_srv(srv, ecm)) {
							srv->lastecmtime = ticks;
							srv->busy = 1;
							srv->retry++;
							break;
						}
					}
				}
				if (srv->retry>=CC_ECMRETRY_MAX) {
					ecm_setsrvflag(ecm, srv->id, ECM_SRV_EXCLUDE); 
				}
				srv->busy = 0;
				break;
*/
			case CC_MSG_ECM_NOK2: // ecm decode failed
				if (!srv->busy) {
					mlogf(LOGINFO,getdbgflag(DBG_SERVER, 0, srv->id), " [!] dcw error from server (%s:%d), unknown ecm request\n",srv->host->name,srv->port);
					break;
				}
#ifdef CACHEEX
				if (srv->cacheex_mode) {
					mlogf(LOGINFO,getdbgflag(DBG_SERVER, 0, srv->id), " [!] dcw error from cacheex server (%s:%d)\n",srv->host->name,srv->port);
					break;
				}
#endif

				pthread_mutex_lock(&prg.lockecm); //###

				ecm = srv->ecm.request;
				if (!ecm) {
					mlogf(LOGINFO,getdbgflag(DBG_SERVER, 0, srv->id), " [!] dcw error from server (%s:%d), ecm not found!!!\n",srv->host->name,srv->port);
					pthread_mutex_unlock(&prg.lockecm); //###
					srv->busy = 0;
					break;
				}
				// check for ECM???
				if (ecm->hash!=srv->ecm.hash) {
					mlogf(LOGINFO,getdbgflag(DBG_SERVER, 0, srv->id), " [!] dcw error from server (%s:%d), ecm deleted!!!\n",srv->host->name,srv->port);
					pthread_mutex_unlock(&prg.lockecm); //###
					srv->busy = 0;
					break;
				}

				mlogf(LOGINFO,getdbgflagpro(DBG_SERVER, 0, srv->id,ecm->cs->id), " <| decode failed from CCcam server (%s:%d) ch %04x:%06x:%04x (%dms)\n", srv->host->name,srv->port, ecm->caid,ecm->provid,ecm->sid, ticks-srv->lastecmtime);
				cs = ecm->cs;

				if ( cs && (ecm->dcwstatus!=STAT_DCW_SUCCESS) && (srv->retry<cs->option.retry.cccam) ) {
					if ((ticks-ecm->recvtime) < (cs->option.server.timeout*ecm->period)) {
						srv->busy = 0;
						if (cc_sendecm_srv(srv, ecm)) {
							srv->lastecmtime = ticks;
							srv->busy = 1;
							srv->retry++;
							mlogf(LOGINFO,getdbgflagpro(DBG_SERVER, 0, srv->id,ecm->cs->id), " (RE%d) -> ecm to CCcam server (%s:%d) ch %04x:%06x:%04x\n",srv->retry,srv->host->name,srv->port,ecm->caid,ecm->provid,ecm->sid);
							pthread_mutex_unlock(&prg.lockecm); //###
							break;
						}
					}
				}
#ifdef SID_FILTER
				if (cs) {
					card = cc_getcardbyid( srv, srv->busycardid );
					if (card) cardsids_update(card, ecm->provid, ecm->sid, -1);
					srv_cstatadd( srv, cs->id, 0 , 0);
				}
#endif
				ecm_setsrvflag(srv->ecm.request, srv->id, ECM_SRV_REPLY_FAIL);

				srv->busy = 0;
				pthread_mutex_unlock(&prg.lockecm); //###
				pipe_cmd( prg.pipe.ecm[1], PIPE_SRV_AVAILABLE );
				break;


			case CC_MSG_BAD_ECM:
				if ( !cc_msg_send( srv->handle, &srv->sendblock, CC_MSG_BAD_ECM, 0, NULL) ) disconnect_srv(srv);
				//mlogf(LOGDEBUG,getdbgflag(DBG_SERVER, 0, srv->id), " CCcam: cmd 0x05 from Server (%s:%d)\n",srv->host->name,srv->port);
				//currentecm.state = ECM_STATUS_FAILED;
				break;

			case CC_MSG_KEEPALIVE:
				srv->keepalive.status = 0;
				//mlogf(LOGDEBUG,getdbgflag(DBG_SERVER, 0, srv->id), " CCcam: Keepalive ACK from Server (%s:%d)\n",srv->host->name,srv->port);
				break;

			case CC_MSG_CARD_DEL: // Delete Card
				pthread_mutex_lock(&prg.lockecm); //###
				card = srv->card;
				uint32_t k = buf[4]<<24 | buf[5]<<16 | buf[6]<<8 | buf[7];
				struct cs_card_data *prevcard = NULL;
				while (card) {
					if (card->shareid==k) {
						mlogf(LOGINFO,getdbgflag(DBG_SERVER, 0, srv->id), " CCcam: server (%s:%d), remove share-id %d\n",srv->host->name,srv->port,k);
						if (prevcard) prevcard->next = card->next; else srv->card = card->next;
						//Free SIDs
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
						// check for current ecm
						if (srv->busy && (srv->busycardid==k) ) ecm_setsrvflag(srv->ecm.request, srv->id, ECM_SRV_EXCLUDE);
						break;
					}
					prevcard = card;
					card = card->next;
				}
				pthread_mutex_unlock(&prg.lockecm); //###
		  		break;

			case CC_MSG_CARD_ADD:
				// remove own cards -> same nodeid "cfg.nodeid"
				if ( (buf[24]<=16) ) { // && memcmp(buf+26+buf[24]*7,cfg.nodeid,8) ) { // check Only the first 4 bytes
					// nodeid index = 26 + 7 * buf[24]
					struct cs_card_data tcard;
					memset(&tcard, 0, sizeof(struct cs_card_data) );
					tcard.shareid = buf[4]<<24 | buf[5]<<16 | buf[6]<<8 | buf[7];
					tcard.uphops = buf[14]+1;
					memcpy( tcard.nodeid, buf+26+buf[24]*7, 8);
					tcard.caid = (buf[12]<<8)+(buf[13]);
					tcard.nbprov = buf[24];
					i = 26+buf[24]*7;
					if (tcard.nbprov>CARD_MAXPROV) tcard.nbprov = CARD_MAXPROV;
					mlogf(LOGINFO,getdbgflag(DBG_SERVER, 0, srv->id), " CCcam: new card (%s:%d) %02x%02x%02x%02x%02x%02x%02x%02x_%x uphops %d caid %04x providers %d\n",srv->host->name,srv->port, buf[i],buf[i+1],buf[i+2],buf[i+3],buf[i+4],buf[i+5],buf[i+6],buf[i+7],tcard.shareid ,tcard.uphops, tcard.caid, tcard.nbprov);
					int nbprov = 0; // Accepted Providers
					for (i=0;i<tcard.nbprov; i++) {
						uint32_t provid = (buf[25+i*7]<<16) | (buf[26+i*7]<<8) | (buf[27+i*7]);
						if ( tcard.uphops <= srv_sharelimits( srv, tcard.caid, provid) ) {
							tcard.prov[nbprov] = provid;
							nbprov++;
							//mlogf(LOGDEBUG,getdbgflag(DBG_SERVER, 0, srv->id), " Accepted %04x:%06x\n", tcard.caid, provid);
						}
						//else mlogf(LOGDEBUG,getdbgflag(DBG_SERVER, 0, srv->id), " Ignored %04x:%06x\n", tcard.caid, provid);
					}
					if (nbprov) {
						tcard.nbprov = nbprov;
						//mlogf(LOGDEBUG,getdbgflag(DBG_SERVER, 0, srv->id), " CCcam: new card (%s:%d) %02x%02x%02x%02x%02x%02x%02x%02x_%x uphops %d caid %04x providers %d\n",srv->host->name,srv->port, buf[i],buf[i+1],buf[i+2],buf[i+3],buf[i+4],buf[i+5],buf[i+6],buf[i+7],tcard.shareid ,tcard.uphops, tcard.caid, tcard.nbprov);
						card = malloc( sizeof(struct cs_card_data) );
						memcpy( card, &tcard, sizeof(struct cs_card_data) );
						pthread_mutex_lock(&prg.lockecm); //###
						card->next = srv->card;
						srv->card = card;
						pthread_mutex_unlock(&prg.lockecm); //###
					}
				}
				break;

			case CC_MSG_SRV_INFO:
				memcpy(srv->nodeid, buf+4, 8);
				memcpy(srv->version, buf+12, 31);
				if ( (srv->version[25]=='M')&&(srv->version[26]=='C')&&(srv->version[27]=='S')&&(srv->version[28]==0) ) {
					sprintf( srv->version, "r%d",  srv->version[29] | (srv->version[30]<<8));
					srv->progname = CCcam_MultiCS;
					// printf(" Multics %d\n", srv->version[29] | (srv->version[30]<<8) );
				}
				for (i=12; i<53; i++) {
					if (!buf[i]) break;
					if ( (buf[i]<32)||(buf[i]>'z') ) {
						memset(srv->version, 0, 31);
						break;
					}
				}
				memcpy(srv->build, buf+44, 31);
				mlogf(LOGINFO,getdbgflag(DBG_SERVER, 0, srv->id), " CCcam: server (%s:%d), info: version %s build %s\n",srv->host->name,srv->port,buf+12, buf+44);
				break;

#ifdef CACHEEX
			 case CC_MSG_CACHE_PUSH:
				if (srv->cacheex_mode!=2) break;
				if (buf[18]==0) { // Got CW
					struct cache_data cacheex;
					cacheex.caid = (buf[4]<<8) | buf[5];
					cacheex.provid = (buf[6]<<24) | (buf[7]<<16) | (buf[8]<<8) | buf[9];
					cacheex.sid = (buf[14]<<8) | buf[15];
					// Look for cardserver
					cs = getcsbycaprovid(cacheex.caid, cacheex.provid);
					if ( !cs || !cs->option.fallowcacheex ) {
						srv->cacheex.badcw++;
						break;
					}
					if (cacheex.caid==0x0500) {
						if (!acceptDCWnonblockCRC(buf+44)) break;
					}
					else
					{
						if (!acceptDCW(buf+44,0)) break;
					}

					uint8_t cw[16];
					srv->cacheex.got[0]++;
					int uphop = buf[60];
					if (uphop<10) srv->cacheex.got[uphop]++;
					if ((buf[19+4]&0xFE)==0x80) cacheex.tag = buf[19+4]; else cacheex.tag = 0;
					memcpy( cacheex.ecmd5, buf+24, 16);
					if ( !checkECMD5(cacheex.ecmd5) ) srv->cacheex.csp++;
					cacheex.hash = (buf[43]<<24) | (buf[42]<<16) | (buf[41]<<8) | buf[40];
					memcpy( cw, buf+44, 16);
					if (!cacheex_check(&cacheex)) break;
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
							pipe_send_cacheex_push_cache(&cacheex, cw, srv->nodeid); //cacheex_push(&cacheex, cw, nodeid);
						}
					}
					mlogf(LOGTRACE,getdbgflag(DBG_CACHEEX, 0, 0)," CACHEEX PUSH from CCcam server (%s:%d) %04x:%06x:%04x:%08x\n", srv->host->name, srv->port,cacheex.caid,cacheex.provid,cacheex.sid,cacheex.hash);
				}
				break;
#endif
			//default: debugdump(buf,len," CCcam: unknown packet from server (%s:%d): ",srv->host->name,srv->port);
		} // switch
		srv->keepalive.time = ticks;
	}
}

///////////////////////////////////////////////////////////////////////////////
// RECEIVE MESSAGE FROM CACHEEX SERVER (MODE 2)
///////////////////////////////////////////////////////////////////////////////

void *cacheex_cc_srv_recvmsg(struct server_data *srv)
{
	srv->pid = syscall(SYS_gettid);

	while (srv->handle>0) {
		struct pollfd pfd;
		pfd.fd = srv->handle;
		pfd.events = POLLIN | POLLPRI;
		int retval = poll(&pfd, 1, 3005); // for 3seconds
		if (retval==0) continue;
		else if (retval<0) { // error
			disconnect_srv(srv);
			break;
		}
		else if ( pfd.revents & (POLLIN|POLLPRI) ) cc_srv_recvmsg(srv);
		else {
			disconnect_srv(srv);
			break;
		}
	}

	srv->pid = 0;
	return NULL;
}

///////////////////////////////////////////////////////////////////////////////
// CONNECT SERVER
///////////////////////////////////////////////////////////////////////////////

// Send Client info to server.
int cc_sendinfo_srv(struct server_data *srv, int ismultics)
{
	uint8_t buf[CC_MAXMSGSIZE];
	memset(buf, 0, CC_MAXMSGSIZE);
	memcpy(buf, srv->user, 20);
	memcpy(buf + 20, cfg.nodeid, 8 );
	buf[28] = 0; //srv->wantemus;
	memcpy(buf + 29, cfg.cccam.version, 32);	// cccam version (ascii)
	if (ismultics) {
		buf[57]='W'; buf[58]='H'; buf[59]='O';
	}
	memcpy(buf + 61, cfg.cccam.build, 32);	// build number (ascii)
	mlogf(LOGINFO,getdbgflag(DBG_SERVER, 0, srv->id), " Server: send client info User: '%s', Version: '%s', Build: '%s'.\n", srv->user, cfg.cccam.version, cfg.cccam.build);
	return cc_msg_send( srv->handle, &srv->sendblock, CC_MSG_CLI_INFO, 20 + 8 + 1 + 64, buf);
}

int cc_connect_srv(struct server_data *srv, int fd)
{
	int n;
	uint8_t data[20];
	uint8_t hash[SHA_DIGEST_LENGTH];
	uint8_t buf[CC_MAXMSGSIZE];
	char pwd[64];
	//
	if (fd < 0) return -1;
	// INIT
	srv->progname = CCcam;
	memset( srv->version, 0, sizeof(srv->version) );
	// get init seed(random) from server
	if((n = recv_nonb(fd, data, 16,5000)) != 16) {
		static char msg[]= "Server does not return init sequence";
		srv->statmsg = msg;
		mlogf(LOGINFO,getdbgflag(DBG_SERVER, 0, srv->id), " Server (%s:%d) does not return 16 bytes\n", srv->host->name,srv->port);
		return -2;
	}

#ifdef DEBUG_NETWORK
	if (flag_debugnet) {
		mlogf(LOGINFO,getdbgflag(DBG_SERVER, 0, srv->id), " CCcam: receive server init seed (%d)\n",n);
		debughex(data,n);
	}
#endif

	// Check Multics
	int ismultics = 0;
	uint8_t a = (data[0]^'M') + data[1] + data[2];
	uint8_t b = data[4] + (data[5]^'C') + data[6];
	uint8_t c = data[8] + data[9] + (data[10]^'S');
	if ( (a==data[3])&&(b==data[7])&&(c==data[11]) ) {
		srv->progname = CCcam_MultiCS;
		ismultics = 1;
	}

	//Check oscam-cccam
	uint32_t sum = 0x1234;
	uint32_t recv_sum = (data[14] << 8) | data[15];
	int i;
	for (i=0; i<14; i++) sum+= data[i];
	if (sum==recv_sum) srv->progname = CCcam_OScam;

	cc_crypt_xor(data);  // XOR init bytes with 'CCcam'

	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, data, 16);
	SHA1_Final(hash, &ctx);

	//debugdump(hash, sizeof(hash), "CCcam: sha1 hash:");

	//init crypto states
	cc_crypt_init(&srv->recvblock, hash, 20);
	cc_decrypt(&srv->recvblock, data, 16); 
	cc_crypt_init(&srv->sendblock, data, 16);
	cc_decrypt(&srv->sendblock, hash, 20);

	if ( !cc_msg_send( fd, &srv->sendblock, CC_MSG_NO_HEADER, 20,hash) ) return -1;   // send crypted hash to server
	memset(buf, 0, sizeof(buf));
	memcpy(buf, srv->user, 20);
	//mlogf(LOGDEBUG,getdbgflag(DBG_SERVER, 0, srv->id), " CCcam: username '%s'\n",srv->username);
	if ( !cc_msg_send( fd, &srv->sendblock, CC_MSG_NO_HEADER, 20, buf) ) return -1;    // send usr '0' padded -> 20 bytes

	memset(buf, 0, sizeof(buf));
	memset(pwd, 0, sizeof(pwd));

	//mlogf(LOGDEBUG,0,"CCcam: 'CCcam' xor\n");
	memcpy(buf, "CCcam\0", 6);
	strncpy(pwd, srv->pass, 63);
	cc_encrypt(&srv->sendblock, (uint8_t *)pwd, strlen(pwd));
	if ( !cc_msg_send( fd, &srv->sendblock, CC_MSG_NO_HEADER, 6, buf) ) return -1; // send 'CCcam' xor w/ pwd
	if ((n = recv_nonb(fd, data, 20,5000)) != 20) {
		static char msg[]= "Password ACK not received";
		srv->statmsg = msg;
		mlogf(LOGWARNING,getdbgflag(DBG_SERVER, 0, srv->id), " CCcam: login failed to Server (%s:%d), pwd ack not received (n = %d)\n",srv->host->name,srv->port, n);
		return -2;
	}
	cc_decrypt(&srv->recvblock, data, 20);
	//hexdump(data, 20, "CCcam: pwd ack received:");

	if (memcmp(data, buf, 5)) {  // check server response
		static char msg[]= "Invalid user/pass";
		srv->statmsg = msg;
		mlogf(LOGWARNING,getdbgflag(DBG_SERVER, 0, srv->id), " CCcam: login failed to Server (%s:%d), usr/pwd invalid\n",srv->host->name,srv->port);
		return -2;
	}// else mlogf(LOGDEBUG,getdbgflag(DBG_SERVER, 0, srv->id), " CCcam: login succeeded to Server (%s:%d)\n",srv->host->name,srv->port);

	srv->handle = fd;
	if (!cc_sendinfo_srv(srv,ismultics)) {
		srv->handle = -1;
		static char msg[]= "Error sending client data";
		srv->statmsg = msg;
		mlogf(LOGWARNING,getdbgflag(DBG_SERVER, 0, srv->id), " CCcam: login failed to Server (%s:%d), could not send client data\n",srv->host->name,srv->port);
		return -3;
	}
	// Update Server data
	static char msg[]= "Connected";
	srv->statmsg = msg;
	srv->connection.status = 1;
	srv->connection.time = GetTickCount();
	srv->keepalive.status = 0;
	srv->keepalive.time = GetTickCount();
	srv->busy = 0;
	srv->lastecmoktime = 0;
	srv->lastecmtime = 0;
	srv->lastdcwtime = 0;
	srv->chkrecvtime = 0;
	srv->msg.len = 0;
	//srv->handle = fd;
	memset(srv->version,0,32);

#ifdef CACHEEX
	if (srv->cacheex_mode==2) {
		if (!create_thread( &srv->tid, (threadfn)cacheex_cc_srv_recvmsg, srv )) {
			disconnect_srv(srv);
		}
	}
	else
#endif

#ifdef EPOLL_ECM
	pipe_pointer( prg.pipe.ecm[1], PIPE_SRV_CONNECTED, srv );
#else
	pipe_cmd( prg.pipe.ecm[1], PIPE_SRV_CONNECTED );
#endif
	return 0;
}

