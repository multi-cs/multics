///////////////////////////////////////////////////////////////////////////////
// TOOLS
///////////////////////////////////////////////////////////////////////////////

static char string_newcamd[] = "Newcamd";
static char string_mgcamd[] = "Mgcamd";
static char string_newcamd_mcs[] = "Newcamd-MCS";
static char string_mgcamd_mcs[] = "Mgcamd-MCS";


///////////////////////////////////////////////////////////////////////////////
// SEND ECM
///////////////////////////////////////////////////////////////////////////////

int cs_sendecm_srv(struct cardserver_data *cs, struct server_data *srv, ECM_DATA *ecm)
{
	unsigned char buf[CWS_NETMSGSIZE];
	struct cs_custom_data srvcd; // Custom data

	srv->ecm.msgid++;
	if (srv->ecm.msgid>0xfff) srv->ecm.msgid = 1;
	srvcd.msgid = srv->ecm.msgid;
	srvcd.sid = ecm->sid;
	srvcd.caid = ecm->caid;
	srvcd.provid = ecm->provid;

	memcpy( &buf[0], &ecm->ecm[0], ecm->ecmlen );
	return cs_message_send(  srv->handle, &srvcd, buf, ecm->ecmlen, srv->sessionkey);
}


///////////////////////////////////////////////////////////////////////////////
// CONNECT SERVER
///////////////////////////////////////////////////////////////////////////////

int cs_connect_srv(struct server_data *srv, int fd)
{
	char passwdcrypt[120];
	unsigned char keymod[14];
	int i,index,len;
	unsigned char buf[CWS_NETMSGSIZE];
	unsigned char sessionkey[16];
	// INIT
	srv->progname = NULL;
	memset( srv->version, 0, sizeof(srv->version) );
	memset( srv->build, 0, 32);
	//
	if( recv_nonb(fd, keymod, 14,5000) != 14 ) {
		static char msg[]= "Server does not return init sequence";
		srv->statmsg = msg;
		mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," newcamd: server does not return init sequence\n");
		return -1;
	}
	// Check Multics
	int ismultics = 0;

	uint8_t a = (keymod[0]^'M') + keymod[1] + keymod[2];
	uint8_t b = keymod[4] + (keymod[5]^'C') + keymod[6];
	uint8_t c = keymod[8] + keymod[9] + (keymod[10]^'S');
	if ( (a==keymod[3])&&(b==keymod[7])&&(c==keymod[11]) ) {
		ismultics = 1;
	}

	//debugdump(keymod,14,"Recv DES Key: ");
	des_login_key_get(keymod, srv->key, 14, sessionkey);  
	//debugdump(sessionkey,16,"Login Key: ");

	// 3. Send login info
	struct cs_custom_data clicd; // Custom data
	memset( &clicd, 0, sizeof(clicd));
	//clicd.sid =  0x4343; // CCcam
	clicd.sid =  cfg.newcamd.clientid; // Mgcamd

	index = 3;
	buf[0] = MSG_CLIENT_2_SERVER_LOGIN;
	buf[1] = 0;
	strcpy( (char*)&buf[3], srv->user);
	index += strlen(srv->user)+1;

	__md5_crypt(srv->pass, "$1$abcdefgh$",passwdcrypt);
	//mlogf(LOGDEBUG,getdbgflag(DBG_SERVER,0,srv->id)," passwdcrypt = %s\n",passwdcrypt);
	strcpy((char*)buf+index, (char*)passwdcrypt);
	index+=strlen(passwdcrypt)+1;
	if (ismultics) clicd.provid=0x0057484F;
	if ( !cs_message_send(fd, &clicd, buf, index, sessionkey) ) return -1;
	srv->ping = GetTickCount();
	// 3.1 Get login answer

	len = cs_message_receive(fd, &clicd, buf, sessionkey,15000);
	if (len<3) {
		static char msg[]= "Login error";
		srv->statmsg = msg;
		mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," newcamd: login answer length error (%d) from server (%s:%d)\n",len, srv->host->name,srv->port);
		return INVALID_SOCKET;
	}
	if ( buf[0] == MSG_CLIENT_2_SERVER_LOGIN_NAK ) {
		static char msg[]= "Invalid user/pass";
		srv->statmsg = msg;
		mlogf(LOGERROR,getdbgflag(DBG_SERVER,0,srv->id)," newcamd: login failed to server (%s:%d)\n", srv->host->name,srv->port);
		return -1;
	}
	else if( buf[0] != MSG_CLIENT_2_SERVER_LOGIN_ACK ) {
		static char msg[]= "Login error";
		srv->statmsg = msg;
		mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," newcamd: Error, expected MSG_CLIENT_2_SERVER_LOGIN_ACK\n");
		return -1;
	}
	else mlogf(LOGINFO,getdbgflag(DBG_SERVER,0,srv->id)," newcamd: connect to server (%s:%d) user '%s'\n", srv->host->name, srv->port, srv->user);
	// Ping
	srv->ping = GetTickCount()-srv->ping;
	// mgcamd protocol version?
	if (clicd.sid==0x6E73) { //&&( (clicd.provid>>24)==0x14) ) {
		if (ismultics) srv->progname = string_mgcamd_mcs;
		else srv->progname = string_mgcamd;
	}
	else if (clicd.provid==0x004D4353) {
		sprintf( srv->version, "r%d", clicd.sid);
		srv->progname = string_newcamd_mcs;
	}
	else srv->progname = string_newcamd;
	//
	des_login_key_get( srv->key, (uint8_t*)passwdcrypt, strlen(passwdcrypt), sessionkey);
//debugdump(sessionkey,16,"sessionkey: ");
	memcpy( srv->sessionkey, sessionkey,16);

	// 4. Send MSG_CARD_DATA_REQ
	memset( &clicd, 0, sizeof(clicd) );
	clicd.msgid = 1;
	buf[0]=MSG_CARD_DATA_REQ;
	buf[1]=0; buf[2]=0;
	if ( !cs_message_send(fd, &clicd, buf, 3, srv->sessionkey) ) return -1;
	len = cs_message_receive( fd, NULL, buf, srv->sessionkey,5000);
	if (len==0) {
		static char msg[]= "Disconnected";
		srv->statmsg = msg;
		mlogf(LOGINFO,getdbgflag(DBG_SERVER,0,srv->id)," newcamd: client disconnected\n");
		return INVALID_SOCKET;
	}
	else if (len<0) {
		static char msg[]= "failed to receive card data";
		srv->statmsg = msg;
		mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," newcamd: Error Recv MSG_CARD_DATA (%d)\n",len);
		return INVALID_SOCKET;
	}
	if (buf[0]!=MSG_CARD_DATA) {
		static char msg[]= "failed to receive card data";
		srv->statmsg = msg;
		mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," newcamd: expected MSG_CARD_DATA\n");
		return INVALID_SOCKET;
	}

	else if (len<15) {
		mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," newcamd: MSG_CARD_DATA, length error (%d)\n",len);
		//return INVALID_SOCKET;
	}
	else {
		// 5. Parse CAID and PROVID(s)
		if ( (buf[14]<CARD_MAXPROV)&&(len>=(6+11*buf[14]))&&(buf[4]||buf[5]) ) { // CAID != 0x0000
			struct cs_card_data *pcard = malloc( sizeof(struct cs_card_data) );
			if (pcard) {
				memset(pcard, 0, sizeof(struct cs_card_data) );
				pcard->caid = ((buf[4]<<8) | buf[5]);
				pcard->nbprov = buf[14];
				pcard->uphops = 1;
				//pcard->sids = NULL;
				if (pcard->nbprov>CARD_MAXPROV) pcard->nbprov = CARD_MAXPROV;
				mlogf(LOGINFO,getdbgflag(DBG_SERVER,0,srv->id)," newcamd: caid %04x providers %d\n", pcard->caid,buf[14]);
				for( i=0; i<pcard->nbprov; i++ ) {
					pcard->prov[i] = (buf[15+11*i]<<16)|(buf[16+11*i]<<8)|buf[17+11*i];
					//mlogf(LOGDEBUG,getdbgflag(DBG_SERVER,0,srv->id)," newcamd: provider %02d = %06X\n", i+1, pcard->prov[i]);
				}
				pcard->next = srv->card;
				srv->card = pcard;
			}
			else mlogf(LOGCRITICAL,0," newcamd: failed to allocate memory\n");
		} else mlogf(LOGINFO,getdbgflag(DBG_SERVER,0,srv->id)," newcamd: caid 0\n");
	}

#ifdef CLI_CSCACHE
/*	// Send keepalive Caching Check???
	clicd.msgid = 0;
	clicd.sid = ('C'<<8) | 'H';
	clicd.caid = 0;
	clicd.provid = 0;
	buf[0] = MSG_KEEPALIVE;
	buf[1] = 0;
	buf[2] = 0;
	cs_message_send(fd, &clicd, buf, 3, srv->sessionkey);
	srv->keepalive.status = GetTickCount();
*/
	srv->cscached = 0;
#endif
	// Update Server data
	static char msg[]= "Connected";
	srv->statmsg = msg;
	srv->connection.status = 1;
	srv->connection.time = srv->keepalive.time = GetTickCount();
	srv->keepalive.status = 0;
	srv->busy = 0;
	srv->lastecmoktime = 0;
	srv->lastecmtime = 0;
	srv->lastdcwtime = 0;
	srv->chkrecvtime = 0;
	srv->msg.len = 0;
	srv->handle = fd;
#ifdef EPOLL_ECM
	pipe_pointer( prg.pipe.ecm[1], PIPE_SRV_CONNECTED, srv );
#else
	pipe_cmd( prg.pipe.ecm[1], PIPE_SRV_CONNECTED );
#endif
	return 0;
}


///////////////////////////////////////////////////////////////////////////////
// RECV MESSAGE
///////////////////////////////////////////////////////////////////////////////

void cs_srv_recvmsg(struct server_data *srv)
{
	// Check
	if (srv->handle<=0) return;
	if (srv->type!=TYPE_NEWCAMD) return;
	// Variables
	unsigned char buf[CWS_NETMSGSIZE];
	struct cardserver_data *cs;
	struct cs_custom_data srvcd; // Custom data
	ECM_DATA *ecm;
	// Get Message
	int len = cs_msg_peek( srv->handle, &srvcd, buf, srv->sessionkey );
	if (len==0) disconnect_srv(srv);
	else if (len<0) {
		mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," newcamd: server (%s:%d) read failed %d (%d)\n", srv->host->name, srv->port, len, errno);
		disconnect_srv(srv);
	}
	else {
		uint32_t ticks = GetTickCount();

		switch ( buf[0] ) {

			case 0x80:
			case 0x81:
				srv->lastdcwtime = ticks;
				if (!srv->busy) {
					mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," [!] dcw error from server (%s:%d), unknown ecm request\n",srv->host->name,srv->port);
					break;
				}
				srv->busy = 0;
				pipe_cmd( prg.pipe.ecm[1], PIPE_SRV_AVAILABLE );
				//
				if (srvcd.msgid!=srv->ecm.msgid) {
					mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," [!] dcw error from server (%s:%d), wrong message-id!!!\n",srv->host->name,srv->port);
					break;
				}
				//
				pthread_mutex_lock(&prg.lockecm); //###
				//
				ecm = srv->ecm.request;
				if (!ecm) {
					mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," [!] dcw error from server (%s:%d), ecm not found!!!\n",srv->host->name,srv->port);
					pthread_mutex_unlock(&prg.lockecm); //###
					break;
				}
				// check for ECM???
				if (ecm->hash!=srv->ecm.hash) {
					mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," [!] dcw error from server (%s:%d), ecm deleted!!!\n",srv->host->name,srv->port);
					pthread_mutex_unlock(&prg.lockecm); //###
					break;
				}
				if (buf[2]==0x10) {
					// Check for DCW
					cs= ecm->cs;
					int isnanoe0=ecm_isnanoe0(ecm->ecm,ecm->caid);
					if ( isnanoe0 )
						mlogf(LOGDEBUG,getdbgflag(DBG_SERVER,0,srv->id)," [!] viaccess nano e0 detected ch %04x:%06x:%04x\n",ecm->caid, ecm->provid, ecm->sid);

					if (!acceptDCW(buf+3, isnanoe0)) {
						mlogf(LOGDEBUG,getdbgflag(DBG_SERVER,0,srv->id)," [!] dcw error from newcamd server (%s:%d), bad dcw!!! ch %04x:%06x:%04x nanoe0=%d\n",srv->host->name,srv->port,ecm->caid, ecm->provid, ecm->sid, isnanoe0);
						srv->ecmerrdcw ++;
						pthread_mutex_unlock(&prg.lockecm); //###
						break;
					}
					srv->ecmok++;
					srv->lastecmoktime = ticks-srv->lastecmtime;
					srv->ecmoktime += srv->lastecmoktime;
					ecm_setsrvflagdcw( ecm, srv->id, ECM_SRV_REPLY_GOOD,buf+3 );
					mlogf(LOGINFO,getdbgflagpro(DBG_SERVER,0,srv->id,ecm->cs->id)," <= cw from server (%s:%d) ch %04x:%06x:%04x-%d (%dms)\n", srv->host->name,srv->port, ecm->caid,ecm->provid,ecm->sid,ecm->ecmlen,ticks-srv->lastecmtime);
					if (loglevel >= LOGDEBUG) {
						char dumpcw[64];
						char dumpecm[4*MAX_ECM_SIZE];
						array2hex( buf+3, dumpcw, 16);
						array2hex( ecm->ecm, dumpecm, ecm->ecmlen );
						mlogf(LOGDEBUG,getdbgflag(DBG_SERVER,0,srv->id)," <= cw from server (%s:%d)- %04x:%06x:%04x-%d/%s => %s\n", srv->host->name,srv->port, ecm->caid, ecm->provid, ecm->sid, ecm->ecmlen,dumpecm, dumpcw);
					}
					if (ecm->dcwstatus!=STAT_DCW_SUCCESS) {
						static char msg[] = "Good dcw from Newcamd server";
						ecm->statusmsg = msg;
						// Store ECM Answer
						ecm_setdcw( ecm, buf+3, DCW_SOURCE_SERVER, srv->id );
					}
					else {	//TODO: check same dcw between cards
						srv->ecmerrdcw ++;
						if ( memcmp(ecm->cw, buf+3, 16) ) mlogf(LOGWARNING,getdbgflagpro(DBG_SERVER,0,srv->id,ecm->cs->id)," !!! different dcw from server (%s:%d)\n",srv->host->name,srv->port);
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
				}
				else {
					cs= ecm->cs;
					if ( cs && (ecm->dcwstatus!=STAT_DCW_SUCCESS) && (srv->retry<cs->option.retry.newcamd) ) {
						if ( (ticks-ecm->recvtime) < (cs->option.server.timeout*ecm->period) ) {
							srv->busy = 0;
							if (cs_sendecm_srv(cs, srv, ecm)>0) {
								srv->retry++;
								ecm->lastsendtime = ticks;
								mlogf(LOGINFO,getdbgflagpro(DBG_SERVER,0,srv->id,ecm->cs->id)," (RE%d) -> ecm to server (%s:%d) ch %04x:%06x:%04x\n",srv->retry,srv->host->name,srv->port,ecm->caid,ecm->provid,ecm->sid);
								srv->lastecmtime = ticks;
								srv->ecmnb++;
								srv->busy = 1;
								srv->ecm.request = ecm;
								pthread_mutex_unlock(&prg.lockecm); //###
								break;
							}
						}
					}
					ecm_setsrvflag(ecm, srv->id, ECM_SRV_REPLY_FAIL);
					mlogf(LOGINFO,getdbgflagpro(DBG_SERVER,0,srv->id,ecm->cs->id)," <| decode failed from server (%s:%d) ch %04x:%06x:%04x (%dms)\n", srv->host->name,srv->port, ecm->caid,ecm->provid,ecm->sid, ticks-srv->lastecmtime);
#ifdef SID_FILTER
					// ADD IN SID LIST
					if (cs) {
						cardsids_update( srv->busycard, ecm->provid, ecm->sid, -1);
						srv_cstatadd( srv, cs->id, 0 , 0);
					}
#endif
					wakeup_sendecm(); // Wakeup ecm waiting for availabe servers
					pthread_mutex_unlock(&prg.lockecm); //###
				}
				break;

//	MSG_SERVER_2_CLIENT_ADDCARD = 0xd3,
			case 0xD3:  // ADD CARD
				if (srvcd.caid) { // CAID != 0x0000
					struct cs_card_data tcard;
					memset(&tcard, 0, sizeof(struct cs_card_data) );
					tcard.caid = srvcd.caid;
					tcard.nbprov = 1;
					tcard.prov[0] = srvcd.provid;
					tcard.uphops = 1;
					if ( tcard.uphops <= srv_sharelimits( srv, tcard.caid, srvcd.provid) ) {
						mlogf(LOGINFO,getdbgflag(DBG_SERVER,0,srv->id)," Mgcamd: new card (%s:%d) caid %04x provider %06X\n", srv->host->name,srv->port, tcard.caid, tcard.prov[0]);
						//mlogf(LOGDEBUG,getdbgflag(DBG_SERVER,0,srv->id)," Accepted %04x:%06x\n", tcard.caid, srvcd.provid);
						struct cs_card_data *card = malloc( sizeof(struct cs_card_data) );
						memcpy( card, &tcard, sizeof(struct cs_card_data) );
						pthread_mutex_lock(&srv->lock); //###
						card->next = srv->card;
						srv->card = card;
						pthread_mutex_unlock(&srv->lock); //###
					}
					//else mlogf(LOGDEBUG,getdbgflag(DBG_SERVER,0,srv->id)," Ignored %04x:%06x\n", tcard.caid, srvcd.provid);
				}
				break;

//	MSG_SERVER_2_CLIENT_REMOVECARD = 0xd4,
			case 0xD4: // Delete Card
				pthread_mutex_lock(&prg.lockecm); //###
				struct cs_card_data *card = srv->card;
				struct cs_card_data *prevcard = NULL;
				while (card) {
					if ( (card->caid==srvcd.caid)&&(card->prov[0]==srvcd.provid) ) {
						mlogf(LOGINFO,getdbgflag(DBG_SERVER, 0, srv->id), " Mgcamd: server (%s:%d), remove card %04x:%06x\n",srv->host->name,srv->port, srvcd.caid, srvcd.provid);
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
						/////XXX if (srv->busy && (srv->busycardid==k) ) ecm_setsrvflag(srv->ecm.request, srv->id, ECM_SRV_EXCLUDE);
						break;
					}
					prevcard = card;
					card = card->next;
				}
				pthread_mutex_unlock(&prg.lockecm); //###
		  		break;

			default:
				if (buf[0]==MSG_KEEPALIVE) {
					if (srv->keepalive.status) {
#ifdef CLI_CSCACHE
						if ( ( srvcd.sid==(('C'<<8)|'H') ) && ( srvcd.caid==(('O'<<8)|'K') ) ) srv->cscached = 1;
#endif
						srv->ping = ticks - srv->keepalive.time;
						//mlogf(LOGDEBUG,getdbgflag(DBG_SERVER,0,srv->id)," <- keepalive from server (%s:%d) ping %dms\n",srv->host->name,srv->port,srv->ping);
						srv->keepalive.status = 0;
					}
					//else mlogf(LOGDEBUG,getdbgflag(DBG_SERVER,0,srv->id)," <- Error keepalive from server (%s:%d)\n",srv->host->name,srv->port);
				}
				else mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," unknown message type '%02x' CAID:%04X PROVID:%06X from server (%s:%d)\n",buf[0],srvcd.caid,srvcd.provid,srv->host->name,srv->port);
				break;
		} // Switch-End
		srv->keepalive.time = ticks;
	}
}


void cs_check_keepalive(struct server_data *srv)
{
	struct cs_custom_data clicd; // Custom data
	unsigned char buf[CWS_NETMSGSIZE];

	if ( (srv->handle<=0)||(srv->type!=TYPE_NEWCAMD) ) return;

	// Check for sending keep alive
	if (!srv->keepalive.status) {
		if ( srv->keepalive.time+(KEEPALIVE_NEWCAMD*1000) < GetTickCount() ) {
			buf[0] = MSG_KEEPALIVE;
			buf[1] = 0;
			buf[2] = 0;
			//mlogf(LOGDEBUG,getdbgflag(DBG_SERVER,0,srv->id)," -> keepalive to server (%s:%d)\n",srv->host->name,srv->port);
			if ( !cs_message_send( srv->handle, NULL, buf, 3, srv->sessionkey) ) {
				disconnect_srv( srv );
			}
			else {
				srv->keepalive.time = GetTickCount();
				srv->keepalive.status = 1;
			}
		}
	}
	else {
		if ( srv->keepalive.status+10000 < GetTickCount() ) { ///???
#ifdef CLI_CSCACHE
			// Send keepalive Caching Check???
			clicd.msgid = 0;
			clicd.sid = ('C'<<8) | 'H';
			clicd.caid = 0;
			clicd.provid = 0;
			buf[0] = MSG_KEEPALIVE;
			buf[1] = 0;
			buf[2] = 0;
			srv->keepalive.status = GetTickCount();
			if ( !cs_message_send( srv->handle, &clicd, buf, 3, srv->sessionkey) ) disconnect_srv( srv );
#else
			mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," ??? no keepalive response from server (%s:%d)\n",srv->host->name,srv->port);
			srv->keepalive.status = 0;
#endif
		}
	}
}

