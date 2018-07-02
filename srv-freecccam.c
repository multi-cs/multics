///////////////////////////////////////////////////////////////////////////////
// File: srv-freecccam.c
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// PROTO
///////////////////////////////////////////////////////////////////////////////

void freecccam_cli_recvmsg(struct cc_client_data *cli);



///////////////////////////////////////////////////////////////////////////////
// FREECCCAM SERVER: CONNECT CLIENTS
///////////////////////////////////////////////////////////////////////////////

void freecccam_sendcards_cli(struct cc_client_data *cli)
{
	int nbcard=0;
	struct cardserver_data *cs = cfg.cardserver;

	int i;
	if (cfg.freecccam.csport[0]) {
		for(i=0;i<MAX_CSPORTS;i++) {
			if(cfg.freecccam.csport[i]) {
				cs = getcsbyport(cfg.freecccam.csport[i]);
				if (cs)
					if (cc_sendcard_cli(cs, cli,0)) nbcard++;
			} else break;
		}
	}
	else {
		while (cs) {
			if (cc_sendcard_cli(cs, cli,0)) nbcard++;
			cs = cs->next;
		}
	}

	mlogf(LOGINFO,0," FreeCCcam: %d cards --> client(%s)\n",  nbcard, ip2string(cli->ip) );
}


///////////////////////////////////////////////////////////////////////////////
// CCCAM SERVER: DISCONNECT CLIENTS
///////////////////////////////////////////////////////////////////////////////

void freecccam_disconnect_cli(struct cc_client_data *cli)
{
	if ( (cli->connection.status>0) && (cli->handle>0) ) {
		cli->connection.status = 0;
		uint32_t ticks = GetTickCount();
		cli->connection.uptime += ticks - cli->connection.time;
		cli->connection.lastseen = ticks; // Last Seen
		close(cli->handle);
		cli->handle = -1;
		mlogf(LOGINFO,0," FreeCCcam: client '%s' disconnected \n", cli->user);
		//////cli->parent->clipfd.update = 1;
	}
}

///////////////////////////////////////////////////////////////////////////////

void *freecccam_connect_cli(struct connect_cli_data *param)
{
	uint8_t buf[CC_MAXMSGSIZE];
	uint8_t data[64];
	int i;
	struct cc_crypt_block sendblock;	// crypto state block
	struct cc_crypt_block recvblock;	// crypto state block
	char usr[64];
	char pwd[255];

	int sock = param->sock;
	uint32_t ip = param->ip;
	free(param);

	memset(usr, 0, sizeof(usr));
	memset(pwd, 0, sizeof(pwd));
	// create & send random seed
	for(i=0; i<12; i++ ) data[i]=fast_rnd();
	// Create Multics ID
	data[3] = (data[0]^'M') + data[1] + data[2];
	data[7] = data[4] + (data[5]^'C') + data[6];
	data[11] = data[8] + data[9] + (data[10]^'S');
	//Create checksum for "O" cccam:
	for (i = 0; i < 4; i++) {
		data[12 + i] = (data[i] + data[4 + i] + data[8 + i]) & 0xff;
	}
	if ( !send_nonb(sock, data, 16, 100) ) {
		close(sock);
		return NULL;
	}
	//XOR init bytes with 'CCcam'
	cc_crypt_xor(data);
	//SHA1
	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, data, 16);
	SHA1_Final(buf, &ctx);
	//initialisate crypto states
	cc_crypt_init(&sendblock, buf, 20);
	cc_decrypt(&sendblock, data, 16);
	cc_crypt_init(&recvblock, data, 16);
	cc_decrypt(&recvblock, buf, 20);
	//debugdump(buf, 20, "SHA1 hash:");
	memcpy(usr,buf,20);
	if ((i=recv_nonb(sock, buf, 20,3000)) == 20) {
		cc_decrypt(&recvblock, buf, 20);
		//debugdump(buf, 20, "Recv SHA1 hash:");
		if ( memcmp(buf,usr,20)!=0 ) {
			//mlogf(LOGDEBUG,0," cc_connect_cli(): wrong sha1 hash from client! (%s)\n",ip2string(ip));
			close(sock);
			return NULL;
		}
	} else {
		//mlogf(LOGDEBUG,0," cc_connect_cli(): recv sha1 timeout\n");
		close(sock);
		return NULL;
	}

  // receive username
	if ((i=recv_nonb(sock, buf, 20,3000)) == 20) {
		cc_decrypt(&recvblock, buf, i);
		memcpy(usr,buf,20);
		//mlogf(LOGDEBUG,0," cc_connect_cli(): username '%s'\n", usr);
	}
	else {
		//mlogf(LOGDEBUG,0," cc_connect_cli(): recv user timeout\n");
		close(sock);
		return NULL;
	}


  // Check for username
	if ( strcmp(cfg.freecccam.user,usr) ) {
		mlogf(LOGWARNING,0," FreeCCcam: Failed to connect client (%s), wrong username\n",ip2string(ip));
		close(sock);
		return NULL;
	}

	pthread_mutex_lock(&prg.lockfreecccli);

	int found = 0;
	struct cc_client_data *cli = cfg.freecccam.server.client;
	while (cli) {
		if (cli->handle<=0) {
			found = 1;
			break;
		}
		else {
			if (cli->ip == ip) { // dont connect
				freecccam_disconnect_cli(cli);
				found = 1;
				break;
			}
		}
		cli = cli->next;
	}
	// check for inactive clients
	if (!found) {
		uint32_t ticks = GetTickCount();
		while (cli) {
			if (cli->handle>0) {
				// Check if we can disconnect idle state clients
				if  ( (ticks-cli->lastecmtime) > 90000 ) freecccam_disconnect_cli(cli);
			}
			if (cli->handle<=0) {
				found = 1;
				break;
			}
			cli = cli->next;
		}
	}

	pthread_mutex_unlock(&prg.lockfreecccli);

	if (!found) {
		mlogf(LOGWARNING,0," FreeCCcam: Failed to connect client (%s), no available connection\n",ip2string(ip));
		close(sock);
		return NULL;
	}

  // receive passwd / 'CCcam'
	if ((i=recv_nonb(sock, buf, 6,3000)) == 6) {
		memset(pwd, 0, sizeof(pwd));
		strcpy( pwd, cfg.freecccam.pass);
		cc_encrypt(&recvblock, (uint8_t *)pwd, strlen(pwd));
		cc_decrypt(&recvblock, buf, 6);
		if (memcmp( buf, "CCcam\0",6)) {
			mlogf(LOGWARNING,0," FreeCCcam: login failed from client(%s)\n",ip2string(ip));
			close(sock);
			return NULL;
		}
	} 
	else {
		close(sock);
		return NULL;
	}

  // send passwd ack
	memset(buf, 0, 20);
	memcpy(buf, "CCcam\0", 6);
	//mlogf(LOGDEBUG,0,"Server: send ack '%s'\n",buf);
	cc_encrypt(&sendblock, buf, 20);
	if ( !send_nonb(sock, buf, 20, 100) ) {
		close(sock);
		return NULL;
	}
	sprintf(cli->user,"%s", ip2string(ip));
	//cli->ecmnb=0;
	//cli->ecmok=0;
	memcpy(&cli->sendblock,&sendblock,sizeof(sendblock));
	memcpy(&cli->recvblock,&recvblock,sizeof(recvblock));
	mlogf(LOGINFO,0," FreeCCcam: client(%s) connected\n",ip2string(ip));

  // recv cli data
	memset(buf, 0, sizeof(buf));
	i = cc_msg_recv( sock, &cli->recvblock, buf, 3000);
	if (i!=97) {
		mlogf(LOGERROR,0," freecccam error recv cli data from client(%s)\n",ip2string(ip));
		close(sock);
		return NULL;
	}

  // Setup Client Data
//	pthread_mutex_lock(&prg.lockfreecccli);
	memcpy( cli->nodeid, buf+24, 8);
	memcpy( cli->version, buf+33, 32);
	memcpy( cli->build, buf+65, 32 );
	mlogf(LOGINFO,0," FreeCCcam: client(%s) running version %s build %s\n",ip2string(ip), cli->version, cli->build);  // cli->nodeid,8,
	cli->cardsent = 0;

	cli->connection.status = 1;
	cli->connection.time = GetTickCount();
	cli->lastactivity = GetTickCount();
	cli->lastecmtime = GetTickCount();
	cli->chkrecvtime = 0;
	cli->ip = ip;
	cli->msg.len = 0;
	cli->handle = sock;
	cli->ecm.busy = 0;
	strcpy( cli->user, ip2string(cli->ip) );

//	pthread_mutex_unlock(&prg.lockfreecccli);
  // send cli data ack
	cc_msg_send( sock, &cli->sendblock, CC_MSG_CLI_INFO, 0, NULL);
	//cc_msg_send( sock, &cli->sendblock, CC_MSG_BAD_ECM, 0, NULL);
	int sendversion = ( (cli->version[28]=='W')&&(cli->version[29]='H')&&(cli->version[30]='O') );
	cc_sendinfo_cli(cli, sendversion);
	//cc_msg_send( sock, &cli->sendblock, CC_MSG_BAD_ECM, 0, NULL);
	cli->cardsent = 1;
	usleep(99000);
	//if (!sendversion)
	freecccam_sendcards_cli(cli);


#ifdef EPOLL_CCCAM
	pipe_pointer( prg.pipe.freecccam[1], PIPE_CLI_CONNECTED, cli );
#else
	pipe_wakeup( prg.pipe.freecccam[1] );
#endif
	return cli;
}

void freecccam_srv_accept(struct cccam_server_data *srv)
{
	struct sockaddr_in newaddr;
	socklen_t socklen = sizeof(struct sockaddr);
	int newfd = accept( srv->handle, (struct sockaddr*)&newaddr, /*(socklen_t*)*/&socklen);
	if ( newfd<=0 ) {
		if ( (errno!=EAGAIN) && (errno!=EINTR) ) mlogf(LOGERROR,getdbgflag(DBG_CCCAM,0,0)," FreeCCcam%d: Accept failed (errno=%d)\n", errno);
	}
	else {
		uint32_t newip = newaddr.sin_addr.s_addr;
		if ( isblockedip(newip) ) {
			mlogf(LOGWARNING,getdbgflag(DBG_CCCAM,0,0)," FreeCCcam%d: New Connection (%s) closed, ip blocked\n", ip2string(newip) );
			close(newfd);
		}
		else {
			pthread_t srv_tid;
			SetSocketKeepalive(newfd);
			SetSoketNonBlocking(newfd);
			//mlogf(LOGDEBUG,getdbgflag(DBG_CCCAM,0,0)," FreeCCcam%d: new connection (%s)\n", ip2string(newip) );
			struct connect_cli_data *newdata = malloc( sizeof(struct connect_cli_data) );
			newdata->server = srv; 
			newdata->sock = newfd; 
			newdata->ip = newaddr.sin_addr.s_addr;
			if ( !create_thread(&srv_tid, (threadfn)freecccam_connect_cli,newdata) ) {
				free( newdata );
				close( newfd );
			}
		}
	}
}

#ifndef MONOTHREAD_ACCEPT
void *freecccam_accept_thread(void *param)
{
#ifndef PUBLIC
	prctl(PR_SET_NAME,"FreeCCcam Accept",0,0,0);
#endif

	while(!prg.restart) {

		struct pollfd pfd[3];
		int pfdcount = 0;

		if ( !IS_DISABLED(cfg.freecccam.server.flags)&&(cfg.freecccam.server.handle>0) ) {
				cfg.freecccam.server.ipoll = pfdcount;
				pfd[pfdcount].fd = cfg.freecccam.server.handle;
				pfd[pfdcount++].events = POLLIN | POLLPRI;
		} else cfg.freecccam.server.ipoll = -1;

		if (pfdcount) {
			int retval = poll(pfd, pfdcount, 3006);
			if ( retval>0 ) {
				if ( !IS_DISABLED(cfg.freecccam.server.flags) && (cfg.freecccam.server.handle>0) && (cfg.freecccam.server.ipoll>=0) && (cfg.freecccam.server.handle==pfd[cfg.freecccam.server.ipoll].fd) ) {
					if ( pfd[cfg.freecccam.server.ipoll].revents & (POLLIN|POLLPRI) ) freecccam_srv_accept( &cfg.freecccam.server );
				}
			}
			else if (retval<0) usleep(96000);
		} else sleep(1);
	}
	return NULL;
}
#endif

////////////////////////////////////////////////////////////////////////////////
// CCCAM SERVER: SEND DCW TO CLIENTS
////////////////////////////////////////////////////////////////////////////////

void freecccam_senddcw_cli(struct cc_client_data *cli)
{
	uint8_t buf[CC_MAXMSGSIZE];
	uint32_t ticks = GetTickCount();

	if (cli->ecm.status==STAT_DCW_SENT) {
		mlogf(LOGWARNING,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," +> cw send failed to CCcam client '%s', cw already sent\n", cli->user); 
		return;
	}
	if (cli->handle<=0) {
		mlogf(LOGWARNING,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," +> cw send failed to CCcam client '%s', client disconnected\n", cli->user); 
		return;
	}
	if (!cli->ecm.busy) {
		mlogf(LOGWARNING,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," +> cw send failed to CCcam client '%s', no ecm request\n", cli->user); 
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

	if ( (ecm->dcwstatus==STAT_DCW_SUCCESS)&&(ecm->hash==cli->ecm.hash) ) {
		cli->lastecm.dcwsrctype = ecm->dcwsrctype;
		cli->lastecm.dcwsrcid = ecm->dcwsrcid;
		cli->lastecm.status=1;
		cli->ecmok++;
		cli->lastdcwtime = ticks;
		cli->ecmoktime += ticks-cli->ecm.recvtime;
		//cli->lastecmoktime = ticks-cli->ecm.recvtime;
		memcpy( buf, ecm->cw, 16 );
		cc_crypt_cw( cli->nodeid, cli->ecm.cardid , buf);
		cc_msg_send( cli->handle, &cli->sendblock, CC_MSG_ECM_REQUEST, 16, buf);
		cc_encrypt(&cli->sendblock, buf, 16); // additional crypto step
		mlogf(LOGINFO,0," => cw to CCcam client '%s' ch %04x:%06x:%04x (%dms)\n", cli->user, ecm->caid,ecm->provid,ecm->sid, GetTickCount()-cli->ecm.recvtime);
	}
	else { //if (ecm->data->dcwstatus==STAT_DCW_FAILED)
		if (enablefreeze) {
			cli->freeze++;
		}
		cli->lastecm.dcwsrctype = DCW_SOURCE_NONE;
		cli->lastecm.dcwsrcid = 0;
		cli->lastecm.status=0;
		cc_msg_send( cli->handle, &cli->sendblock, CC_MSG_ECM_NOK1, 0, NULL);
		mlogf(LOGINFO,0," |> decode failed to CCcam client '%s' ch %04x:%06x:%04x (%dms)\n", cli->user, ecm->caid,ecm->provid,ecm->sid, GetTickCount()-cli->ecm.recvtime);
	}
	cli->ecm.busy=0;
	cli->ecm.status = STAT_DCW_SENT;
}

// Check sending cw to clients
void freecccam_check_sendcw(ECM_DATA *ecm)
{
	struct cccam_server_data *cccam = &cfg.freecccam.server;
	if (cccam) {
		if ( !IS_DISABLED(cccam->flags) && (cccam->handle>0) ) {
			struct cc_client_data *cli = cccam->client;
			while (cli) {
				if ( !IS_DISABLED(cli->flags)&&(cli->handle>0)&&(cli->ecm.busy)&&(cli->ecm.request==ecm) ) {
					freecccam_senddcw_cli( cli );
				}
				cli = cli->next;
			}
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
// FREECCCAM: RECEIVE MESSAGES FROM CLIENTS
///////////////////////////////////////////////////////////////////////////////

void freecccam_store_ecmclient(ECM_DATA *ecm, struct cc_client_data *cli)
{
	cli->ecm.recvtime = GetTickCount();
	cli->ecm.busy = 1;
	cli->ecm.request = ecm;
	cli->ecm.hash = ecm->hash;
    cli->ecm.status = STAT_ECM_SENT;
	ecm_addip(ecm, cli->ip);
}

// Receive messages from clients
void freecccam_cli_recvmsg(struct cc_client_data *cli)
{
	if (cli->handle<=0) return;
	// Get Message
	unsigned char buf[CC_MAXMSGSIZE];
	unsigned char data[CC_MAXMSGSIZE]; // for other use
	unsigned int cardid;
    int len = cc_msg_peek( cli->handle, &cli->recvblock, &cli->msg, buf );
	if (len==0) {
		freecccam_disconnect_cli(cli);
	}
	else if (len<0) {
		mlogf(LOGWARNING,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," FreeCCcam: client '%s' read failed %d (%d)\n", cli->user, len, errno);
		freecccam_disconnect_cli(cli);
	}
	else {
		if (len>=CC_MAXMSGSIZE) return;
		uint32_t ticks = GetTickCount();
		cli->lastactivity = ticks;

		switch (buf[1]) {

			 case CC_MSG_ECM_REQUEST:
				cli->ecmnb++;
				cli->lastecmtime = ticks;
				if (len<20) return; // Avoid malicious peers
				if (cli->ecm.busy) {
					// send decode failed
					mlogf(LOGWARNING,0," <|> decode failed to FreeCCcam client(%s), too many ecm requests\n", cli->user);
					break;
				}
				cli->ecm.busy = 0;
				//Check for card availability
				memcpy( data, buf+17, len-17);
				cardid = buf[10]<<24 | buf[11]<<16 | buf[12]<<8 | buf[13];
				uint16_t caid = buf[4]<<8 | buf[5];
				uint16_t sid = buf[14]<<8 | buf[15];
				uint32_t provid = ecm_getprovid( data, caid );
				if (provid==0) provid = buf[6]<<24 | buf[7]<<16 | buf[8]<<8 | buf[9];
				// Check for Profile
				struct cardserver_data *cs=getcsbyid( cardid );
				if (!cs) {
					cli->ecmdenied++;
					cc_msg_send( cli->handle, &cli->sendblock, CC_MSG_ECM_NOK2, 0, NULL);
					mlogf(LOGWARNING,0," <|> decode failed to FreeCCcam client(%s), card-id %x not found\n", cli->user, cardid);
					break;
				}
				// Check ECM
				uint8_t cw1cycle;
				char *error = cs_accept_ecm(cs,caid,provid,sid,ecm_getchid(data,caid), len-17, data, &cw1cycle);
				if (error) {
					cli->ecmdenied++;
					cs->ecmdenied++;
					cc_msg_send( cli->handle, &cli->sendblock, CC_MSG_ECM_NOK2, 0, NULL);
					mlogf(LOGINFO,0," <|> decode failed to FreeCCcam client(%s) ch %04x:%06x:%04x, %s\n", cli->user, caid,provid,sid, error);
					break;
				}
				// ACCEPTED
				pthread_mutex_lock(&prg.lockecm);
				// Search for ECM
				ECM_DATA *ecm = search_ecmdata_any(cs, data,  len-17, sid, caid); // dont get failed ecm request from cache
				int isnew =  ( ecm==NULL );
				if (ecm) {
					ecm->lastrecvtime = ticks;
					if (ecm->dcwstatus==STAT_DCW_FAILED) {
						freecccam_store_ecmclient(ecm, cli);
						mlogf(LOGINFO,getdbgflagpro(DBG_CCCAM,0,cli->id,cs->id)," <- ecm from FreeCCcam client '%s' ch %04x:%06x:%04x**\n", cli->user, caid, provid, sid);
						cli->ecm.busy=1;
						cli->ecm.hash = ecm->hash;
						cli->ecm.cardid = cardid;
						ecm->recvtime = ticks;
						ecm->dcwstatus = STAT_DCW_WAIT;
						ecm->cachestatus = 0; //ECM_CACHE_NONE; // Resend Request
						ecm->checktime = 1; // Check NOW
					}
					else { // SUCCESS/WAIT
						freecccam_store_ecmclient(ecm, cli);
						mlogf(LOGINFO,getdbgflagpro(DBG_CCCAM,0,cli->id,cs->id)," <- ecm from FreeCCcam client '%s' ch %04x:%06x:%04x*\n", cli->user, caid, provid, sid);
						cli->ecm.busy=1;
						cli->ecm.hash = ecm->hash;
						cli->ecm.cardid = cardid;
						// Check for Success/Timeout
						if (!ecm->checktime) freecccam_senddcw_cli(cli);
					}
				}
				else {
					cs->ecmaccepted++;
					// Setup ECM Request for Server(s)
					ecm = store_ecmdata(cs, data, len-17, sid, caid, provid);
					freecccam_store_ecmclient(ecm, cli);
					mlogf(LOGINFO,getdbgflagpro(DBG_CCCAM,0,cli->id,cs->id), " <- ecm from FreeCCcam client(%s) ch %04x:%06x:%04x\n", cli->user,caid,provid,sid);
					cli->ecm.busy=1;
					cli->ecm.hash = ecm->hash;
					cli->ecm.cardid = cardid;
					ecm->dcwstatus = STAT_DCW_WAIT;
					ecm->checktime = 1; // Check NOW
					if (cs->option.fallowcache) {
						ecm->waitcache = 1;
						ecm->dcwstatus = STAT_DCW_WAITCACHE;
						ecm->checktime = ecm->recvtime + cs->option.cachetimeout;
						pipe_cache_find(ecm, cs);
					}
				}
				pthread_mutex_unlock(&prg.lockecm);
				if (isnew) wakeup_sendecm();
				break;

			 case CC_MSG_KEEPALIVE:
				//printf(" Keepalive from client '%s'\n",cli->user);
				cc_msg_send( cli->handle, &cli->sendblock, CC_MSG_KEEPALIVE, 0, NULL);
				break;
		} // Switch-End
	}
}


///////////////////////////////////////////////////////////////////////////////

void freecccam_recv_pipe()
{
	struct cc_client_data *cli;
	uint8_t buf[1024];
	struct pollfd pfd[2];
	do {
		int len = pipe_recv( prg.pipe.freecccam[0], buf);
		if (len>0) {
			switch(buf[0]) {
				case PIPE_WAKEUP:  // ADD NEW CLIENT
					//mlogf(LOGTRACE,0," wakeup csmsg\n");
					break;
#ifdef EPOLL_CCCAM
				case PIPE_CLI_CONNECTED:  // ADD NEW FD
					memcpy( &cli, buf+1, sizeof(void*) );
					// Add to events
					struct epoll_event ev; // epoll event
					ev.events = EPOLLIN;
					ev.data.fd = cli->handle;
					ev.data.ptr = cli;
					if ( epoll_ctl(prg.epoll.freecccam, EPOLL_CTL_ADD, cli->handle, &ev) == -1 )
						mlogf(LOGERROR,DBG_ERROR," FreeCCcam: Error EPOLL_CTL_ADD %s (%d) %d\n", cli->user, cli->handle, errno);
					//else mlogf(LOGDEBUG,0,"EPOLL_CTL_ADD %s (%d)\n", cli->user, cli->handle);
					break;
#endif

			}
		}
		pfd[0].fd = prg.pipe.freecccam[0];
		pfd[0].events = POLLIN | POLLPRI;
	} while (poll(pfd, 1, 1)>0);
}

///////////////////////////////////////////////////////////////////////////////


#ifdef EPOLL_FREECCCAM

void *freecccam_recvmsg_thread(void *param)
{
	int i;

#ifndef PUBLIC
	prctl(PR_SET_NAME,"FreeCCcam RecvMSG",0,0,0);
#endif

	struct epoll_event evlist[MAX_EPOLL_EVENTS]; // epoll recv events
	prg.epoll.freecccam = epoll_create( MAX_EPOLL_EVENTS );
	// Add PIPE
	struct epoll_event ev; // epoll event
	ev.events = EPOLLIN | EPOLLPRI | EPOLLRDHUP;
	ev.data.ptr = NULL;
	if ( epoll_ctl(prg.epoll.freecccam, EPOLL_CTL_ADD, prg.pipe.freecccam[0], &ev) == -1 ) mlogf(LOGERROR,0,"epoll_ctl freecccam error -1");

	while (!prg.restart) {
		int ready = epoll_wait( prg.epoll.freecccam, evlist, MAX_EPOLL_EVENTS, 1002);
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

		for (i=0; i < ready; i++) {
			if ( evlist[i].events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR) ) { // EPOLLRDHUP
				if (evlist[i].data.ptr == NULL) mlogf(LOGERROR,DBG_ERROR,"Err! epoll_wait() pipe\n"); // error !!!
				else freecccam_disconnect_cli(evlist[i].data.ptr);
			}
			else if ( evlist[i].events & (EPOLLIN|EPOLLPRI) ) {
				if (evlist[i].data.ptr == NULL) freecccam_recv_pipe();
				else freecccam_cli_recvmsg(evlist[i].data.ptr);
			}
		}
	}
	return NULL;
}

#else

void *freecccam_recvmsg_thread(void *param)
{
	struct pollfd pfd[MAX_PFD];
	int pfdcount;
#ifndef PUBLIC
	prctl(PR_SET_NAME,"FreeCCcam RecvMSG",0,0,0);
#endif
	while(1) {
		pfdcount = 0;
		// PIPE
		pfd[pfdcount].fd = prg.pipe.freecccam[0];
		pfd[pfdcount++].events = POLLIN | POLLPRI;
		struct cccam_server_data *freecccam = &cfg.freecccam.server;
		if ( !IS_DISABLED(freecccam->flags)&&(freecccam->handle>0) ) {
			struct cc_client_data *cli = freecccam->client;
			while (cli && (pfdcount<MAX_PFD)) {
				if ( !IS_DISABLED(cli->flags)&&(cli->handle>0) ) {
					cli->ipoll = pfdcount;
					pfd[pfdcount].fd = cli->handle;
					pfd[pfdcount++].events = POLLIN | POLLPRI;
				} else cli->ipoll = -1;
				cli = cli->next;
			}
		}

		int retval = poll(pfd, pfdcount, 3008); // for 3seconds

		if ( retval>0 ) {

			// CCcam Clients
			struct cccam_server_data *freecccam = &cfg.freecccam.server;
			if ( !IS_DISABLED(freecccam->flags)&&(freecccam->handle>0) ) {
				//pthread_mutex_lock(&prg.lockcccli);
				struct cc_client_data *cli = freecccam->client;
				while (cli) {
					if ( !IS_DISABLED(cli->flags)&&(cli->handle>0)&&(cli->ipoll>=0)&&(cli->handle==pfd[cli->ipoll].fd) ) {
						if ( pfd[cli->ipoll].revents & (POLLHUP|POLLNVAL) ) freecccam_disconnect_cli(cli);
						else if ( pfd[cli->ipoll].revents & (POLLIN|POLLPRI) ) {
							freecccam_cli_recvmsg(cli);
						}
						///else if ( (GetTickCount()-cccli->lastactivity) > 600000 ) freecccam_disconnect_cli(cccli);
					}
					cli = cli->next;
				}
				//pthread_mutex_unlock(&prg.lockcccli);
			}

			//
			if ( pfd[0].revents & (POLLIN|POLLPRI) ) freecccam_recv_pipe();
		}
		else if ( retval<0 ) {
			mlogf(LOGERROR,0, " thread receive messages: poll error %d(errno=%d)\n", retval, errno);
		}

	}
	return NULL;
}

#endif

///////////////////////////////////////////////////////////////////////////////
// FREECCCAM SERVER: START/STOP
///////////////////////////////////////////////////////////////////////////////

int start_thread_freecccam()
{
	pthread_t tid;
#ifndef MONOTHREAD_ACCEPT
	create_thread(&tid, freecccam_accept_thread,NULL);
#endif

	create_thread(&tid, freecccam_recvmsg_thread,NULL);
	return 0;
}

