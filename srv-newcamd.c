///////////////////////////////////////////////////////////////////////////////
// PROTO
///////////////////////////////////////////////////////////////////////////////

struct cs_client_data *getnewcamdclientbyid(uint32_t id)
{
	struct cardserver_data *cs = cfg.cardserver;
	while (cs) {
		if (!(cs->flags&FLAG_DELETE)) {
			struct cs_client_data *cli = cs->newcamd.client;
			while (cli) {
				if (!(cli->flags&FLAG_DELETE))
					if (cli->id==id) return cli;
				cli = cli->next;
			}
		}
		cs = cs->next;
	}
	return NULL;
}


///////////////////////////////////////////////////////////////////////////////
// DISCONNECT
///////////////////////////////////////////////////////////////////////////////

void cs_disconnect_cli(struct cs_client_data *cli)
{
	cli->connection.status = 0;
	uint32_t ticks = GetTickCount();
	cli->connection.uptime += ticks - cli->connection.time;
	cli->connection.lastseen = ticks; // Last Seen
	close(cli->handle);
	cli->handle = -1;
	mlogf(LOGINFO,getdbgflag(DBG_NEWCAMD,cli->pid,cli->id)," newcamd: client '%s' disconnected\n", cli->user);
}

///////////////////////////////////////////////////////////////////////////////
// CONNECT
///////////////////////////////////////////////////////////////////////////////

void *cs_connect_cli(struct connect_cli_data *param)
{
    char passwdcrypt[120];
	unsigned char keymod[14];
	int i,index;
	unsigned char sessionkey[16];
	struct cs_custom_data clicd;
	unsigned char buf[CWS_NETMSGSIZE];

	struct cardserver_data *cs = param->server;
	int sock = param->sock;
	uint32_t ip = param->ip;
	free(param);
	// Create random deskey
	for (i=0; i<14; i++) keymod[i] = 0xff & rand();
	// Create Multics ID
	keymod[3] = (keymod[0]^'M') + keymod[1] + keymod[2];
	keymod[7] = keymod[4] + (keymod[5]^'C') + keymod[6];
	keymod[11] = keymod[8] + keymod[9] + (keymod[10]^'S');

//STAT: SEND RND KEY
	// send random des key

	if ( !send_nonb(sock, keymod, 14, 500) ) {
		mlogf(LOGWARNING,getdbgflag(DBG_NEWCAMD,cs->id,0)," newcamd: error sending init sequence\n");
		close(sock);
		return NULL;
	}

	uint32_t ticks = GetTickCount();
	// Calc SessionKey
	//mlogf(LOGDEBUG,getdbgflag(DBG_NEWCAMD,cs->id,0)," DES Key: "); debughex(keymod,14);
	des_login_key_get(keymod, cs->newcamd.key, 14, sessionkey);
	//mlogf(LOGDEBUG,getdbgflag(DBG_NEWCAMD,cs->id,0)," Login Key: "); debughex(sessionkey,16);

//STAT: LOGIN INFO
	// 3. login info
	i = cs_message_receive(sock, &clicd, buf, sessionkey,3000);
	if (i<=0) {
		if (i==-2) mlogf(LOGWARNING,getdbgflag(DBG_NEWCAMD,cs->id,0)," %s: (%s) new connection closed, wrong des key\n", cs->name, ip2string(ip));
		else mlogf(LOGWARNING,getdbgflag(DBG_NEWCAMD,cs->id,0)," %s: (%s) new connection closed, receive timeout\n", cs->name, ip2string(ip));
		close(sock);
		return NULL;
	}

	ticks = GetTickCount()-ticks;
	if (buf[0]!=MSG_CLIENT_2_SERVER_LOGIN) {
		close(sock);
		return NULL;
	}

	// Check username length
	if ( strlen( (char*)buf+3 )>63 ) {
		/*
		buf[0] = MSG_CLIENT_2_SERVER_LOGIN_NAK;
		buf[1] = 0;
		buf[2] = 0;
		cs_message_send(sock, NULL, buf, 3, sessionkey);
		*/
		mlogf(LOGWARNING,getdbgflag(DBG_NEWCAMD,cs->id,0)," %s: (%s) new connection closed, wrong username length\n", cs->name, ip2string(ip));
		close(sock);
		return NULL;
	}

	// test username
	for(i=3; i<(3+64); i++) {
		if (buf[i]==0) break;
		if (buf[i]<=32) { // bad username
			close(sock);
			return NULL;
		}
	}

	pthread_mutex_lock(&prg.lockcli);
	index = 3;
	struct cs_client_data *cli = cs->newcamd.client;
	int found = 0;
	char *name = (char*)(buf+index);
	uint32_t hash = hashCode( (unsigned char *)name, strlen(name) );
	while (cli) {
		if (cli->userhash==hash)
		if (!strcmp(cli->user,name)) {
			if (IS_DISABLED(cli->flags)) { // Connect only enabled clients
				pthread_mutex_unlock(&prg.lockcli);
				mlogf(LOGWARNING,getdbgflag(DBG_NEWCAMD,cli->pid,cli->id)," %s: connection refused for client '%s' (%s), client disabled\n", cs->name, cli->user, ip2string(ip));
				close(sock);
				return NULL;
			}
			found=1;
			break;
		}
		cli = cli->next;
	}
	if (!found) {
		pthread_mutex_unlock(&prg.lockcli);
		/*
		buf[0] = MSG_CLIENT_2_SERVER_LOGIN_NAK;
		buf[1] = 0;
		buf[2] = 0;
		cs_message_send(sock, NULL, buf, 3, sessionkey); */
		mlogf(LOGWARNING,getdbgflag(DBG_NEWCAMD,cs->id,0)," %s: unknown user '%s' (%s)\n", cs->name, &buf[3], ip2string(ip));
		close(sock);
		return NULL;
	}

	// Check password
	index += strlen(cli->user) +1;
	__md5_crypt(cli->pass, "$1$abcdefgh$",passwdcrypt);
	if (!strcmp(passwdcrypt,(char*)&buf[index])) {
		if (cli->ip==ip) cli->nbdiffip++;
		//Check Reconnection
		if (cli->connection.status>0) {
			if ( (GetTickCount()-cli->connection.time) > 60000 ) {
				cs_disconnect_cli(cli);
				if (cli->ip==ip) mlogf(LOGWARNING,getdbgflag(DBG_NEWCAMD,cli->pid,cli->id)," %s: Client '%s' (%s) already connected\n", cs->name,cli->user, ip2string(ip));
				else {
					pthread_mutex_unlock(&prg.lockcli);
					mlogf(LOGWARNING,getdbgflag(DBG_NEWCAMD,cli->pid,cli->id)," %s: Client '%s' (%s) already connected with different ip, Connection closed (%s)\n", cs->name, cli->user, ip2string(cli->ip), ip2string(ip));
					cli->nbloginerror++;
					close(sock);
					return NULL;
				}
			}
			else {
				mlogf(LOGWARNING,getdbgflag(DBG_NEWCAMD,cli->pid,cli->id)," %s: Client '%s' just connected, new connection closed (%s)\n", cs->name, cli->user, ip2string(ip));
				pthread_mutex_unlock(&prg.lockcli);
				cli->nbloginerror++;
				close(sock);
				return NULL;
			}
		}
		cli->nblogin++;
		// Store program id
		cli->progid = clicd.sid;
		//
		buf[0] = MSG_CLIENT_2_SERVER_LOGIN_ACK;
		buf[1] = 0;
		buf[2] = 0;
		// Send Multics Id&Version
		if (clicd.provid==0x0057484F) { // WHO 
			clicd.provid = 0x004D4353; // MCS
			clicd.sid = REVISION; // Revision
			cs_message_send(sock, &clicd, buf, 3, sessionkey);
		} else cs_message_send(sock, NULL, buf, 3, sessionkey);
		des_login_key_get( cs->newcamd.key, (unsigned char*)passwdcrypt, strlen(passwdcrypt),sessionkey);
		memcpy( &cli->sessionkey, &sessionkey, 16);

		// Setup User data
		cli->msg.len = 0;
		cli->handle = sock;
		cli->ip = ip;
		memset( &cli->ecm, 0, sizeof(cli->ecm) );
		cli->connection.status = 1;
		cli->connection.time = GetTickCount();
		cli->lastactivity = GetTickCount();
		cli->lastecmtime = 0;
		cli->chkrecvtime = 0;
		mlogf(LOGINFO,getdbgflag(DBG_NEWCAMD,cli->pid,cli->id)," %s: client '%s' connected (%s)\n", cs->name, cli->user, ip2string(ip));
		pthread_mutex_unlock(&prg.lockcli);
		cli->cs->newcamd.clipfd.update = 1;
#ifdef EPOLL_NEWCAMD
		pipe_pointer( prg.pipe.newcamd[1], PIPE_CLI_CONNECTED, cli );
#else
		pipe_wakeup( prg.pipe.newcamd[1] );
#endif
	}
	else {
		pthread_mutex_unlock(&prg.lockcli);
		// send NAK
		buf[0] = MSG_CLIENT_2_SERVER_LOGIN_NAK;
		buf[1] = 0;
		buf[2] = 0;
		//cs_message_send(sock, NULL, buf, 3, sessionkey);
		mlogf(LOGWARNING,getdbgflag(DBG_NEWCAMD,cli->pid,cli->id)," %s: client '%s' wrong password (%s)\n", cs->name, cli->user, ip2string(ip));
		cli->nbloginerror++;
		close(sock);
	}
	return NULL;
}


void newcamd_srv_accept(struct cardserver_data *srv)
{
	struct sockaddr_in newaddr;
	socklen_t socklen = sizeof(struct sockaddr);
	int newfd = accept( srv->newcamd.handle, (struct sockaddr*)&newaddr, /*(socklen_t*)*/&socklen);
	if ( newfd<=0 ) {
		if ( (errno!=EAGAIN) && (errno!=EINTR) ) mlogf(LOGERROR,getdbgflag(DBG_NEWCAMD,srv->id,0)," [%s] Accept failed (errno=%d)\n", srv->name,errno);
	}
	else {
		SetSocketReuseAddr(newfd);
		uint32_t newip = newaddr.sin_addr.s_addr;
		if ( isblockedip(newip) ) {
			mlogf(LOGWARNING,getdbgflag(DBG_NEWCAMD,srv->id,0)," [%s] New Connection (%s) closed, ip blocked\n", srv->name, ip2string(newip) );
			close(newfd);
		}
		else {
			pthread_t srv_tid;
			if (cfg.newcamd.keepalive) SetSocketKeepalive(newfd);
			SetSocketNoDelay(newfd);
			SetSoketNonBlocking(newfd);
			//mlogf(LOGDEBUG,getdbgflag(DBG_NEWCAMD,srv->id,0)," [%s] new connection (%s)\n", srv->name, ip2string(newip) );
			struct connect_cli_data *newdata = malloc( sizeof(struct connect_cli_data) );
			newdata->server = srv; 
			newdata->sock = newfd; 
			newdata->ip = newaddr.sin_addr.s_addr;
			if ( !create_thread(&srv_tid, (threadfn)cs_connect_cli,newdata) ) {
				free( newdata );
				close( newfd );
			}
		}
	}
}

#ifndef MONOTHREAD_ACCEPT

void *newcamd_accept_thread(void *param)
{
	sleep(5);

	while(!prg.restart) {

		struct pollfd pfd[256];
		int pfdcount = 0;

		struct cardserver_data *cs = cfg.cardserver;
		while(cs) {
			if ( cs->option.fsharenewcamd && !IS_DISABLED(cs->newcamd.flags) && (cs->newcamd.handle>0) ) {
				cs->newcamd.ipoll = pfdcount;
				pfd[pfdcount].fd = cs->newcamd.handle;
				pfd[pfdcount++].events = POLLIN | POLLPRI;
			} else cs->newcamd.ipoll = -1;
			cs = cs->next;
		}

		if (pfdcount) {
			int retval = poll(pfd, pfdcount, 3006);
			if ( retval>0 ) {
				struct cardserver_data *cs = cfg.cardserver;
				while (cs) {
					if ( cs->option.fsharenewcamd )
					if ( !IS_DISABLED(cs->newcamd.flags)&&(cs->newcamd.handle>0) && (cs->newcamd.ipoll>=0) && (cs->newcamd.handle==pfd[cs->newcamd.ipoll].fd) ) {
						if ( pfd[cs->newcamd.ipoll].revents & (POLLIN|POLLPRI) ) newcamd_srv_accept( cs );
					}
					cs = cs->next;
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

void cs_senddcw_cli(struct cs_client_data *cli)
{
	unsigned char buf[CWS_NETMSGSIZE];
	struct cs_custom_data clicd; // Custom data

	if (cli->ecm.status==STAT_DCW_SENT) {
		mlogf(LOGWARNING,getdbgflag(DBG_NEWCAMD,cli->pid,cli->id)," +> cw send failed to client '%s', cw already sent\n", cli->user); 
		return;
	}
	if (cli->handle==INVALID_SOCKET) {
		mlogf(LOGWARNING,getdbgflag(DBG_NEWCAMD,cli->pid,cli->id)," +> cw send failed to client '%s', client disconnected\n", cli->user); 
		return;
	}
	if (!cli->ecm.busy) {
		mlogf(LOGWARNING,getdbgflag(DBG_NEWCAMD,cli->pid,cli->id)," +> cw send failed to client '%s', no ecm request\n", cli->user); 
		return;
	}

	ECM_DATA *ecm = cli->ecm.request;
	//FREEZE
	int enablefreeze;
	if ( (cli->lastecm.caid==ecm->caid)&&(cli->lastecm.prov==ecm->provid)&&(cli->lastecm.sid==ecm->sid) ) {
		if ( (cli->lastecm.status=1)&&(cli->lastdcwtime+200<GetTickCount()) ) enablefreeze = 1;
	} else cli->zap++;

	cli->lastecm.caid = ecm->caid;
	cli->lastecm.prov = ecm->provid;
	cli->lastecm.sid = ecm->sid;
	cli->lastecm.decodetime = GetTickCount()-cli->ecm.recvtime;
	cli->lastecm.request = cli->ecm.request;

	clicd.msgid = cli->ecm.climsgid;
	clicd.sid = ecm->sid;
	clicd.caid = ecm->caid;
	clicd.provid = ecm->provid;

	if ( (ecm->hash==cli->ecm.hash)&&(ecm->dcwstatus==STAT_DCW_SUCCESS) ) {
		cli->lastecm.dcwsrctype = ecm->dcwsrctype;
		cli->lastecm.dcwsrcid = ecm->dcwsrcid;
		cli->lastecm.status=1;
		cli->ecmok++;
		cli->ecmoktime += GetTickCount()-cli->ecm.recvtime;
		buf[0] = ecm->ecm[0];
		buf[1] = 0;
		buf[2] = 0x10;
		memcpy( &buf[3], &ecm->cw, 16 );
		if ( !cs_message_send( cli->handle, &clicd, buf, 19, cli->sessionkey) ) cs_disconnect_cli( cli );
		else mlogf(LOGINFO,getdbgflag(DBG_NEWCAMD,cli->pid,cli->id)," => cw to client '%s' ch %04x:%06x:%04x (%dms)\n", cli->user, ecm->caid,ecm->provid,ecm->sid, GetTickCount()-cli->ecm.recvtime);
		cli->lastdcwtime = GetTickCount();
	}
	else { //if (ecm->data->dcwstatus==STAT_DCW_FAILED)
		if (enablefreeze) cli->freeze++;
		cli->lastecm.status=0;
		cli->lastecm.dcwsrctype = DCW_SOURCE_NONE;
		cli->lastecm.dcwsrcid = 0;
		buf[0] = ecm->ecm[0];
		buf[1] = 0;
		buf[2] = 0;
		if ( !cs_message_send(  cli->handle, &clicd, buf, 3, cli->sessionkey) ) cs_disconnect_cli( cli );
		else mlogf(LOGINFO,getdbgflag(DBG_NEWCAMD,cli->pid,cli->id)," |> decode failed to client '%s' ch %04x:%06x:%04x (%dms)\n", cli->user, ecm->caid,ecm->provid,ecm->sid, GetTickCount()-cli->ecm.recvtime);
	}
	cli->ecm.busy=0;
	cli->ecm.status = STAT_DCW_SENT;
}

// Check sending cw to clients
void cs_check_sendcw(ECM_DATA *ecm)
{
	struct cardserver_data *cs = cfg.cardserver;
	while (cs) {
		if (  !IS_DISABLED(cs->flags)&&(cs->newcamd.handle>0) ) {
			struct cs_client_data *cli = cs->newcamd.client;
			while (cli) {
				if (  !IS_DISABLED(cli->flags)&&(cli->handle!=INVALID_SOCKET)&&(cli->ecm.busy)&&(cli->ecm.request==ecm)&&(cli->ecm.status==STAT_ECM_SENT) ) {
					cs_senddcw_cli( cli );
				}
				cli = cli->next;
			}
		}
		cs = cs->next;
	}
}

///////////////////////////////////////////////////////////////////////////////
// RECV MESSAGE
///////////////////////////////////////////////////////////////////////////////

void cs_store_ecmclient(struct cardserver_data *cs, ECM_DATA *ecm, struct cs_client_data *cli, int climsgid)
{
	cli->ecm.recvtime = GetTickCount();
	cli->ecm.request = ecm;
    cli->ecm.climsgid = climsgid;
    cli->ecm.status = STAT_ECM_SENT;
	ecm_addip(ecm, cli->ip);
}

void cs_cli_recvmsg(struct cs_client_data *cli)
{
	if (cli->handle<=0) return;
	// Get Message
	struct cardserver_data *cs = cli->cs;
	uint8_t buf[CC_MAXMSGSIZE];
	uint8_t data[CWS_NETMSGSIZE]; // for other use
	struct cs_custom_data clicd; // Custom data
    int len = cs_msg_peek( cli->handle, &clicd, buf, cli->sessionkey );
	if (len==0) cs_disconnect_cli(cli);
	else if (len<0) {
		mlogf(LOGWARNING,getdbgflag(DBG_NEWCAMD,cli->pid,cli->id)," newcamd: client '%s' read failed %d (%d)\n", cli->user, len, errno);
		cs_disconnect_cli(cli);
	}
	else {
		// Parse 
		uint32_t ticks = GetTickCount();
		cli->lastactivity = ticks;
		switch ( buf[0] ) {
			case MSG_CARD_DATA_REQ:
					memset( buf, 0, sizeof(buf) );
					buf[0] = MSG_CARD_DATA;
					if (!cli->card.caid) {
						buf[4] = cs->card.caid>>8;
						buf[5] = cs->card.caid&0xff;
						//buf[14] = cs->card.nbprov;
						int nbprov=0;
						for(len=0;len<cs->card.nbprov;len++) {
							buf[15+11*nbprov] = cs->card.prov[len].id>>16;
							buf[16+11*nbprov] = cs->card.prov[len].id>>8;
							buf[17+11*nbprov] = cs->card.prov[len].id&0xff;
							nbprov++;
						}
						buf[14] = nbprov;
						cs_message_send(cli->handle, &clicd, buf, 15+11*nbprov, cli->sessionkey);
					}
					else {
						buf[4] = cli->card.caid>>8;
						buf[5] = cli->card.caid&0xff;
						int nbprov=0;
						for(len=0;len<cli->card.nbprov;len++) {
							buf[15+11*nbprov] = cli->card.prov[len]>>16;
							buf[16+11*nbprov] = cli->card.prov[len]>>8;
							buf[17+11*nbprov] = cli->card.prov[len]&0xff;
							nbprov++;
						}
						buf[14] = nbprov;
						cs_message_send(cli->handle, &clicd, buf, 15+11*nbprov, cli->sessionkey);
					}
					//mlogf(LOGDEBUG,getdbgflag(DBG_NEWCAMD,cli->pid,cli->id)," newcamd: send card data to client '%s'\n", cli->user);
					break;
			case 0x80:
			case 0x81:
					//debugdump(buf, len, "ECM: ");
					cli->lastecmtime = ticks;
					cli->ecmnb++;
					memcpy( data, buf, len);
					uint32_t provid = ecm_getprovid( data, clicd.caid );
					if (provid!=0) clicd.provid = provid;

					if (cli->ecm.busy) {
						cli->ecmdenied++;
						// send decode failed
						buf[1] = 0; buf[2] = 0;
						if ( !cs_message_send( cli->handle, &clicd, buf, 3, cli->sessionkey) ) cs_disconnect_cli( cli );
						else mlogf(LOGINFO,getdbgflag(DBG_NEWCAMD,cli->pid,cli->id)," <|> decode failed to client '%s' ch %04x:%06x:%04x, too many ecm requests\n", cli->user,clicd.caid,clicd.provid,clicd.sid);
						break;
					}
					// CHECK FOR ECM
					uint8_t cw1cycle;
					char *error = cs_accept_ecm(cs,clicd.caid,clicd.provid,clicd.sid,ecm_getchid(data,clicd.caid), len, data, &cw1cycle);
					if (error) {
						cs->ecmdenied++;
						cli->ecmdenied++;
						buf[1] = 0; buf[2] = 0;
						if ( !cs_message_send( cli->handle, &clicd, buf, 3, cli->sessionkey) ) cs_disconnect_cli( cli );
						else mlogf(LOGINFO,getdbgflag(DBG_NEWCAMD,cli->pid,cli->id)," <|> decode failed to client '%s' ch %04x:%06x:%04x, %s\n",cli->user, clicd.caid,clicd.provid,clicd.sid, error);
						break;
					}

					clicd.caid = cs->card.caid; // if caid == 0

					// ACCEPTED
					pthread_mutex_lock(&prg.lockecm); //###

					// Search for ECM
					ECM_DATA *ecm = search_ecmdata_any(cs, data,  len, clicd.sid, clicd.caid); // dont get failed ecm request from cache
					if (ecm) {
						ecm->lastrecvtime = ticks;
						if (ecm->dcwstatus==STAT_DCW_FAILED) {
							if (ecm->period > cs->option.dcw.retry) {
								buf[1] = 0; buf[2] = 0;
								cs_message_send( cli->handle, &clicd, buf, 3, cli->sessionkey);
								mlogf(LOGINFO,getdbgflag(DBG_NEWCAMD,cli->pid,cli->id)," <|> decode failed to client '%s' ch %04x:%06x:%04x, already failed\n",cli->user, clicd.caid,clicd.provid,clicd.sid);
							}
							else {
								ecm->period++; // RETRY
								cs_store_ecmclient(cs, ecm, cli, clicd.msgid);
								mlogf(LOGINFO,getdbgflag(DBG_NEWCAMD,cli->pid,cli->id)," <- ecm from client '%s' ch %04x:%06x:%04x:%08x**\n",cli->user,clicd.caid,clicd.provid,clicd.sid,ecm->hash);
								cli->ecm.busy=1;
								cli->ecm.hash = ecm->hash;
								ecm->dcwstatus = STAT_DCW_WAIT;
								ecm->cachestatus = 0; //ECM_CACHE_NONE; // Resend Request
								ecm->checktime = 1; // Check NOW
								pipe_wakeup( prg.pipe.ecm[1] );
							}
						}
						else {
							//TODO: Add another card for sending ecm
							cs_store_ecmclient(cs, ecm, cli, clicd.msgid);
							mlogf(LOGINFO,getdbgflag(DBG_NEWCAMD,cli->pid,cli->id)," <- ecm from client '%s' ch %04x:%06x:%04x:%08x*\n",cli->user,clicd.caid,clicd.provid,clicd.sid,ecm->hash);
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
								cs_senddcw_cli(cli);
								break;
								if ( cli->dcwcheck && !cs->option.dcw.halfnulled && (ecm->dcwstatus==STAT_DCW_SUCCESS) && !checkfreeze_setdcw(ecm,ecm->cw) ) { // ??? last ecm is wrong
									ecm->dcwstatus = STAT_DCW_WAIT;
									memset( ecm->cw, 0, 16 );
									ecm->checktime = 1; // Wakeup Now
									pipe_wakeup( prg.pipe.ecm[1] );
								}
								else {
									pthread_mutex_unlock(&prg.lockecm);
									cs_senddcw_cli(cli);
									break;
								}
							}
						}
					}
					else {
						cs->ecmaccepted++;
						// Setup ECM Request for Server(s)
						ecm = store_ecmdata(cs, data, len, clicd.sid, clicd.caid, clicd.provid);
						cs_store_ecmclient(cs, ecm, cli, clicd.msgid);
						mlogf(LOGINFO,getdbgflag(DBG_NEWCAMD,cli->pid,cli->id)," <- ecm from client '%s' ch %04x:%06x:%04x:%08x\n",cli->user,clicd.caid,clicd.provid,clicd.sid,ecm->hash);
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

#ifndef PUBLIC
#if defined(CACHEEX) && defined(CS378X_SRV)
						forward_cs378x(ecm);
#endif
#endif

#ifdef TESTCHANNEL
						int testchannel = ( (ecm->caid==cfg.testchn.caid)&&(ecm->provid==cfg.testchn.provid)&&(!cfg.testchn.sid||(ecm->sid==cfg.testchn.sid)) );
						if (testchannel) {
							mlogf(LOGINFO,0," <- ecm from Newcamd client '%s' ch %04x:%06x:%04x %02x:%08x\n", cli->user, ecm->caid, ecm->provid, ecm->sid, ecm->ecm[0], ecm->hash);
						}
#endif
					}

					pthread_mutex_unlock(&prg.lockecm); //###
					break;


#ifdef SRV_CSCACHE
			// Incoming DCW from client
			case 0xC0:
			case 0xC1:
					cli->lastecmtime = ticks;
					if (!cli->ecm.busy) break;
					if (!cli->ecm.request) break;
					//
					pthread_mutex_lock(&prg.lockecm); //###
					ecm = cli->ecm.request;
					if (ecm->hash!=cli->ecm.hash) {
						mlogf(LOGWARNING,getdbgflag(DBG_NEWCAMD,cli->pid,cli->id)," <!= wrong cw from Client '%s' ch %04x:%06x:%04x\n", cli->user, ecm->caid,ecm->provid,ecm->sid, ticks-cli->lastecmtime);
						pthread_mutex_unlock(&prg.lockecm);
						break;
					}
					if ( (ecm->caid!=clicd.caid) || (ecm->sid!=clicd.sid) || (ecm->provid!=clicd.provid) || (cli->ecm.climsgid!=clicd.msgid) ) {
						mlogf(LOGWARNING,getdbgflag(DBG_NEWCAMD,cli->pid,cli->id)," <!= wrong cw from Client '%s' ch %04x:%06x:%04x\n", cli->user, ecm->caid,ecm->provid,ecm->sid, ticks-cli->lastecmtime);
						pthread_mutex_unlock(&prg.lockecm);
						break;
					}
					if ( (buf[0]&0x81)!=ecm->ecm[0] ) {
						mlogf(LOGWARNING,getdbgflag(DBG_NEWCAMD,cli->pid,cli->id)," <!= wrong cw from Client '%s' ch %04x:%06x:%04x\n", cli->user, ecm->caid,ecm->provid,ecm->sid, ticks-cli->lastecmtime);
						pthread_mutex_unlock(&prg.lockecm);
						break;
					}
					if (buf[2]!=0x10) {
						mlogf(LOGWARNING,getdbgflag(DBG_NEWCAMD,cli->pid,cli->id)," <!= wrong cw from Client '%s' ch %04x:%06x:%04x\n", cli->user, ecm->caid,ecm->provid,ecm->sid, ticks-cli->lastecmtime);
						pthread_mutex_unlock(&prg.lockecm);
						break;
					}
					// Check for DCW
					cs= ecm->cs;
					int isnanoe0=ecm_isnanoe0(ecm->ecm,ecm->caid);
					if ( isnanoe0 )
                                        	mlogf(LOGDEBUG,getdbgflag(DBG_NEWCAMD,cli->pid,cli->id)," [!] viaccess nano e0 detected ch %04x:%06x:%04x\n",ecm->caid, ecm->provid, ecm->sid);
					if (!acceptDCW(&buf[3], isnanoe0)) {
						mlogf(LOGINFO,getdbgflag(DBG_NEWCAMD,cli->pid,cli->id)," <!= wrong cw from Client '%s' ch %04x:%06x:%04x\n", cli->user, ecm->caid,ecm->provid,ecm->sid, ticks-cli->lastecmtime);
						pthread_mutex_unlock(&prg.lockecm);
						break;
					}
					mlogf(LOGINFO,getdbgflag(DBG_NEWCAMD,cli->pid,cli->id)," <= cw from Client '%s' ch %04x:%06x:%04x (%dms)\n", cli->user, ecm->caid,ecm->provid,ecm->sid, ticks-cli->lastecmtime);
					if (ecm->dcwstatus!=STAT_DCW_SUCCESS) {
						static char msg[] = "Good dcw from Newcamd Client";
						ecm->statusmsg = msg;
						// Store ECM Answer
						ecm_setdcw( ecm, &buf[3], DCW_SOURCE_CSCLIENT, (ecm->cs->id<<16)|cli->id );
					}
					else {	//TODO: check same dcw between cards
						if ( memcmp(&ecm->cw, &buf[3],16) ) mlogf(LOGWARNING,getdbgflag(DBG_NEWCAMD,cli->pid,cli->id)," !!! different dcw from newcamd client '%s'\n", cli->user);
					}

					pthread_mutex_unlock(&prg.lockecm); //###
					break;
#endif

			default:
					if (buf[0]==MSG_KEEPALIVE) {
#ifdef SRV_CSCACHE
						// Check for Cache client??
						if (clicd.sid==(('C'<<8)|'H')) clicd.caid = ('O'<<8)|'K';
#endif
						//mlogf(LOGDEBUG,getdbgflag(DBG_NEWCAMD,cli->pid,cli->id)," <-> keepalive from/to client '%s'\n",cli->user);
						if ( !cs_message_send(cli->handle, &clicd, buf, 3, cli->sessionkey) ) cs_disconnect_cli( cli );
					}
					else {
						mlogf(LOGWARNING,getdbgflag(DBG_NEWCAMD,cli->pid,cli->id)," newcamd: unknown message type '%02x' from client '%s'\n",buf[0],cli->user);
						buf[1]=0; buf[2]=0;
						if ( !cs_message_send( cli->handle, &clicd, buf, 3, cli->sessionkey) ) cs_disconnect_cli( cli );
					}
		} // Switch
	}
}


///////////////////////////////////////////////////////////////////////////////

void cs_recv_pipe()
{
	uint8_t buf[1024];
	struct pollfd pfd[2];
	struct cs_client_data *cli;

	do {
		int len = pipe_recv( prg.pipe.newcamd[0], buf);
		if (len>0) {
			switch(buf[0]) {
				case PIPE_WAKEUP:  // ADD NEW CLIENT
					//mlogf(LOGTRACE,0," wakeup csmsg\n");
					break;
#ifdef EPOLL_NEWCAMD
				case PIPE_CLI_CONNECTED:  // ADD NEW FD
					memcpy( &cli, buf+1, sizeof(void*) );
					// Add to events
					struct epoll_event ev; // epoll event
					ev.events = EPOLLIN;
					ev.data.fd = cli->handle;
					ev.data.ptr = cli;
					if ( epoll_ctl(prg.epoll.newcamd, EPOLL_CTL_ADD, cli->handle, &ev) == -1 ) mlogf(LOGERROR,DBG_ERROR,"Err! EPOLL_CTL_ADD %s (%d)\n", cli->user, cli->handle);
					//else mlogf(LOGERROR,0,"EPOLL_CTL_ADD %s (%d)\n", cli->user, cli->handle);
					break;
#endif
			}
		}
		pfd[0].fd = prg.pipe.newcamd[0];
		pfd[0].events = POLLIN | POLLPRI;
	} while (poll(pfd, 1, 3)>0);
}

///////////////////////////////////////////////////////////////////////////////

#ifdef EPOLL_NEWCAMD


void *cs_recvmsg_thread(void *param)
{
#ifndef PUBLIC
	prg.pid_cs_msg = syscall(SYS_gettid);
	prctl(PR_SET_NAME,"Newcamd RecvMSG",0,0,0);
#endif

	prg.epoll.newcamd = epoll_create( MAX_EPOLL_EVENTS );
	// Add PIPE
	struct epoll_event ev; // epoll event
	ev.events = EPOLLIN | EPOLLPRI | EPOLLRDHUP;
	ev.data.ptr = NULL;
	if ( epoll_ctl(prg.epoll.newcamd, EPOLL_CTL_ADD, prg.pipe.newcamd[0], &ev) == -1 ) mlogf(LOGERROR,DBG_ERROR," epoll_ctl newcamd error -1\n");
	// Main Loop
	struct epoll_event evlist[MAX_EPOLL_EVENTS]; // epoll recv events
	while (!prg.restart) {
		int ready = epoll_wait( prg.epoll.newcamd, evlist, MAX_EPOLL_EVENTS, 1004);
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
		else if (ready==0) continue; // timeout

		usleep(cfg.delay.thread);

		int i;
		for (i=0; i < ready; i++) {
			if ( evlist[i].events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR) ) { // EPOLLRDHUP
				if (evlist[i].data.ptr == NULL) mlogf(LOGERROR,DBG_ERROR,"Err! epoll_wait() pipe\n"); // error !!!
				else cs_disconnect_cli(evlist[i].data.ptr);
			}
			else if ( evlist[i].events & (EPOLLIN|EPOLLPRI) ) {
				if (evlist[i].data.ptr == NULL) cs_recv_pipe();
				else cs_cli_recvmsg(evlist[i].data.ptr);
			}
		}
	}
	return NULL;
}

#else

void *cs_recvmsg_thread(void *param)
{
	struct pollfd pfd[MAX_PFD];
	int pfdcount;

#ifndef PUBLIC
	prg.pid_cs_msg = syscall(SYS_gettid);
	prctl(PR_SET_NAME,"Newcamd RecvMSG",0,0,0);
#endif

	while (!prg.restart) {
		pfdcount = 0;
		// PIPE
		pfd[pfdcount].fd = prg.pipe.newcamd[0];
		pfd[pfdcount++].events = POLLIN | POLLPRI;

		struct cardserver_data *cs = cfg.cardserver;
		while (cs) {
			if ( cs->option.fsharenewcamd )
			if ( !IS_DISABLED(cs->newcamd.flags)&&(cs->newcamd.handle>0) ) {
				if (cs->newcamd.clipfd.update||cs->newcamd.clipfd.count<0) {
					cs->newcamd.clipfd.count = 0;
					struct cs_client_data *cli = cs->newcamd.client;
					while (cli && (cs->newcamd.clipfd.count<NEWCAMD_MAX_PFD)) {
						if ( !IS_DISABLED(cli->flags) && (cli->handle>0) && !(cli->flags&FLAG_WORKTHREAD) ) {
							cli->ipoll = cs->newcamd.clipfd.count;
							cs->newcamd.clipfd.pfd[cs->newcamd.clipfd.count].fd = cli->handle;
							cs->newcamd.clipfd.pfd[cs->newcamd.clipfd.count++].events = POLLIN | POLLPRI;
						} else cli->ipoll = -1;
						cli = cli->next;
					}
					cs->newcamd.clipfd.update = 0;
					//mlogf(LOGDEBUG,getdbgflag(DBG_ERROR,0,0), " [%s] clients poll updated %d\n", cs->name, cs->newcamd.clipfd.count);
				}
				cs->newcamd.clipfd.ipoll = pfdcount;
				if (cs->newcamd.clipfd.count>0) {
					memcpy( &pfd[pfdcount], cs->newcamd.clipfd.pfd, cs->newcamd.clipfd.count * sizeof(struct pollfd) );
					pfdcount += cs->newcamd.clipfd.count;
				}
			} else cs->newcamd.clipfd.count = 0;
			cs = cs->next;
		}

		int retval = poll(pfd, pfdcount, 3012); // for 3seconds

		if ( retval>0 ) {
			usleep(cfg.delay.thread);

			// Newcamd Clients
			cs = cfg.cardserver;
			while (cs) {
				if ( cs->option.fsharenewcamd )
				if ( !IS_DISABLED(cs->newcamd.flags)&&(cs->newcamd.handle>0)&&(cs->newcamd.clipfd.count>0) ) {
					//pthread_mutex_lock(&prg.lockcli);
					struct cs_client_data *cscli = cs->newcamd.client;
					while (cscli) {
						if ( !IS_DISABLED(cscli->flags)&&(cscli->handle>0) && (cscli->ipoll>=0) && (cscli->handle==pfd[cs->newcamd.clipfd.ipoll+cscli->ipoll].fd) ) {
							if ( pfd[cs->newcamd.clipfd.ipoll+cscli->ipoll].revents & (POLLHUP|POLLNVAL) ) cs_disconnect_cli(cscli);
							else if ( pfd[cs->newcamd.clipfd.ipoll+cscli->ipoll].revents & (POLLIN|POLLPRI) ) {
								cs_cli_recvmsg(cscli);
							}
						}
						cscli = cscli->next;
					}
					//pthread_mutex_unlock(&prg.lockcli);
				}
				cs = cs->next;
			}
			//
			if ( pfd[0].revents & (POLLIN|POLLPRI) ) cs_recv_pipe();
		}
		else if ( retval<0 ) {
			mlogf(LOGERROR,0, " thread receive messages: poll error %d(errno=%d)\n", retval, errno);
			usleep(99000);
		}

	}
	return NULL;
}

#endif

///////////////////////////////////////////////////////////////////////////////
// NEWCAMD SERVER: START/STOP
///////////////////////////////////////////////////////////////////////////////

int start_thread_newcamd()
{
	pthread_t tid;
#ifndef MONOTHREAD_ACCEPT
	create_thread(&tid, newcamd_accept_thread,NULL);
#endif
	create_thread(&tid, cs_recvmsg_thread,NULL);
	return 0;
}

