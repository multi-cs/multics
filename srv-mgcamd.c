///////////////////////////////////////////////////////////////////////////////
// TOOLS
///////////////////////////////////////////////////////////////////////////////

void mgcamd_srv_accept2(struct mgcamdserver_data *mgcamd);

struct mgcamdserver_data *getmgcamdserverbyid(uint32_t id)
{
	struct mgcamdserver_data *mgcamd = cfg.mgcamd.server;
	while (mgcamd) {
		if (!(mgcamd->flags&FLAG_DELETE))
			if (mgcamd->id==id) return mgcamd;
		mgcamd = mgcamd->next;
	}
	return NULL;
}

struct mg_client_data *getmgcamdclientbyid(uint32_t id)
{
	struct mgcamdserver_data *mgcamd = cfg.mgcamd.server;
	while (mgcamd) {
		if (!(mgcamd->flags&FLAG_DELETE)) {
			struct mg_client_data *cli = mgcamd->client;
			while (cli) {
				if (!(cli->flags&FLAG_DELETE))
					if (cli->id==id) return cli;
				cli = cli->next;
			}
		}
		mgcamd = mgcamd->next;
	}
	return NULL;
}

struct mg_client_data *getmgcamdclientbyname(struct mgcamdserver_data *mgcamd, char *name)
{
	if (!(mgcamd->flags&FLAG_DELETE)) {
		uint32_t hash = hashCode( (unsigned char *)name, strlen(name) );
		struct mg_client_data *cli = mgcamd->client;
		while (cli) {
			if (!(cli->flags&FLAG_DELETE))
				if (cli->userhash==hash)
					if ( !strcmp(cli->user,name) ) return cli;
			cli = cli->next;
		}
	}
	return NULL;
}


void mg_sendcard_add(struct cardserver_data *cs, struct mgcamdserver_data *mgcamd, struct mg_client_data *cli)
{
	uint8_t buf[4];
	struct cs_custom_data clicd; // Custom data
	if ( cs && cs->option.fsharemgcamd ) {
		int len;
		for ( len=0; len<cs->card.nbprov; len++) {
			clicd.sid = mgcamd->port;
			clicd.caid = cs->card.caid; 
			clicd.provid = cs->card.prov[len].id;
			buf[0] = EXT_ADD_CARD; buf[1]=0; buf[2]=0;
			if ( card_sharelimits(cli->sharelimits, clicd.caid, clicd.provid) )
				if ( !cs_message_send(cli->handle, &clicd, buf, 3, cli->sessionkey) ) { mg_disconnect_cli( cli ); return; }
		}
	}
}

void mg_sendcard_del(struct cardserver_data *cs, struct mgcamdserver_data *mgcamd, struct mg_client_data *cli)
{
	uint8_t buf[4];
	struct cs_custom_data clicd; // Custom data
	if ( cs && cs->option.fsharemgcamd ) {
		int len;
		for ( len=0; len<cs->card.nbprov; len++) {
			clicd.sid = mgcamd->port;
			clicd.caid = cs->card.caid; 
			clicd.provid = cs->card.prov[len].id;
			buf[0] = EXT_REMOVE_CARD; buf[1]=0; buf[2]=0;
			if ( card_sharelimits(cli->sharelimits, clicd.caid, clicd.provid) )
				cs_message_send(cli->handle, &clicd, buf, 3, cli->sessionkey);
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
// DISCONNECT
///////////////////////////////////////////////////////////////////////////////

#ifdef ECMLIST
/*
void mg_ecmlist_add(struct mg_client_data *cli)
{
	pthread_mutex_lock(&prg.lockecm);

	ECM_DATA *ecm = cli->ecm.request;

	cli->nextEcm = ecm->client.mgcamd;
	ecm->client.mgcamd = cli;

	pthread_mutex_unlock(&prg.lockecm);
}
*/

void mg_ecmlist_del(struct mg_client_data *cli)
{
	ECM_DATA *ecm = cli->ecm.request;
	if (ecm) {
		pthread_mutex_lock(&prg.lockecm);
		struct mg_client_data *list = ecm->client.mgcamd;
		if (list) {
			if (list==cli) {
				ecm->client.mgcamd = cli->nextEcm;
			}
			else {
				while (list->next) {
					if (list->nextEcm==cli) {
						list->nextEcm = cli->nextEcm;
						break;
					}
					list = list->next;
				}
			}
		}
		pthread_mutex_unlock(&prg.lockecm);
	}
	cli->nextEcm = NULL;
}
#endif

void mg_disconnect_cli(struct mg_client_data *cli)
{
	cli->connection.status = 0;
	uint32_t ticks = GetTickCount();
	cli->connection.uptime += ticks - cli->connection.time;
	cli->connection.lastseen = ticks; // Last Seen
	close(cli->handle);
	cli->handle = -1;
	cli->parent->clipfd.update = 1;
	mlogf(LOGINFO,getdbgflag(DBG_MGCAMD,0,cli->id)," mgcamd: client '%s' disconnected\n", cli->user);
	cli->ecm.request = NULL;
	cli->ecm.busy = 0;
}

///////////////////////////////////////////////////////////////////////////////
// CONNECT
///////////////////////////////////////////////////////////////////////////////

void *mg_connect_cli(struct connect_cli_data *param)
{
    char passwdcrypt[120];
	unsigned char keymod[14];
	int i,index;
	unsigned char sessionkey[16];
	struct cs_custom_data clicd;
	unsigned char buf[CWS_NETMSGSIZE];

	struct mgcamdserver_data *mgcamd = param->server;
	int sock = param->sock;
	uint32_t ip = param->ip;
	free(param);

#ifdef IPLIST
	struct ip_hacker_data *ipdata = iplist_find( mgcamd->iplist, ip );
	if (ipdata) iplist_newlogin( ipdata );
#endif

	// Create random deskey
	for (i=0; i<14; i++) keymod[i] = 0xff & rand();
	// Create Multics ID
	keymod[3] = (keymod[0]^'M') + keymod[1] + keymod[2];
	keymod[7] = keymod[4] + (keymod[5]^'C') + keymod[6];
	keymod[11] = keymod[8] + keymod[9] + (keymod[10]^'S');
	// send random des key
	if ( !send_nonb(sock, keymod, 14, 500) ) {
		mlogf(LOGERROR,getdbgflag(DBG_MGCAMD,0,0)," mgcamd: error sending init sequence\n");
		close(sock);
		return NULL;
	}

	// Calc SessionKey
	des_login_key_get(keymod, mgcamd->key, 14, sessionkey);

//STAT: LOGIN INFO
	// 3. login info
	i = cs_message_receive(sock, &clicd, buf, sessionkey,5000);
	if (i<=0) {
		if (i==-2) mlogf(LOGERROR,getdbgflag(DBG_MGCAMD,0,0)," mgcamd: (%s) new connection closed, wrong des key\n", ip2string(ip));
		else mlogf(LOGERROR,getdbgflag(DBG_MGCAMD,0,0)," mgcamd: (%s) new connection closed, receive timeout\n", ip2string(ip));
		close(sock);
		return NULL;
	}

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
		mlogf(LOGERROR,getdbgflag(DBG_MGCAMD,0,0)," mgcamd: wrong username length (%s)\n", ip2string(ip));
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

	pthread_mutex_lock(&prg.lockclimg);
	index = 3;
	struct mg_client_data *cli = mgcamd->client;
	int found = 0;
	char *name = (char*)(buf+index);
	uint32_t hash = hashCode( (unsigned char *)name, strlen(name) );
	while (cli) {
		if (cli->userhash==hash)
		if (!strcmp(cli->user, name)) {
			if (IS_DISABLED(cli->flags)) { // Connect only enabled clients
				mlogf(LOGWARNING,getdbgflag(DBG_MGCAMD,0,cli->id)," mgcamd: connection refused for client '%s' (%s), client disabled\n", cli->user, ip2string(ip));
				pthread_mutex_unlock(&prg.lockclimg);
				close(sock);
				return NULL;
			}
			found=1;
			break;
		}
		cli = cli->next;
	}
	if (!found) {
		buf[0] = MSG_CLIENT_2_SERVER_LOGIN_NAK;
		buf[1] = 0;
		buf[2] = 0;
		//cs_message_send(sock, NULL, buf, 3, sessionkey);
		mlogf(LOGWARNING,getdbgflag(DBG_MGCAMD,0,0)," mgcamd: unknown user '%s' (%s)\n", &buf[3], ip2string(ip));
		pthread_mutex_unlock(&prg.lockclimg);
		close(sock);
		return NULL;
	}

	// Check for Host
	if (cli->host) {
		struct host_data *host = cli->host;
		host->clip = ip;
		if ( host->ip && (host->ip!=ip) ) {
			uint sec = getseconds()+60;
			if ( host->checkiptime > sec ) host->checkiptime = sec;
			mlogf(LOGWARNING,getdbgflag(DBG_MGCAMD,0,cli->id)," mgcamd: Client '%s' (%s), ip refused\n",cli->user, ip2string(ip)); 
			cli->nbloginerror++;
			pthread_mutex_unlock(&prg.lockclimg);
			close(sock);
			return NULL;
		}
	}

	// Check password
	index += strlen(cli->user) +1;
	__md5_crypt(cli->pass, "$1$abcdefgh$",passwdcrypt);
	if (!strcmp(passwdcrypt,(char*)&buf[index])) {
		if (cli->ip!=ip) cli->nbdiffip++;
		//Check Reconnection
		if (cli->connection.status>0) {
			if ( (GetTickCount()-cli->connection.time) > 60000 ) {
				mg_disconnect_cli(cli);
				if (cli->ip==ip) mlogf(LOGWARNING,getdbgflag(DBG_MGCAMD,0,cli->id)," mgcamd: Client '%s' (%s) already connected\n",cli->user, ip2string(ip));
				else {
					mlogf(LOGWARNING,getdbgflag(DBG_MGCAMD,0,cli->id)," mgcamd: Client '%s' (%s) already connected with different ip, Connections closed (%s)\n", cli->user, ip2string(cli->ip), ip2string(ip));
					cli->nbloginerror++;
					pthread_mutex_unlock(&prg.lockclimg);
					close(sock);
					return NULL;
				}
			}
			else {
				mlogf(LOGWARNING,getdbgflag(DBG_MGCAMD,0,cli->id)," mgcamd: Client '%s' just connected, new connection closed (%s)\n", cli->user, ip2string(ip));
				cli->nbloginerror++;
				pthread_mutex_unlock(&prg.lockclimg);
				close(sock);
				return NULL;
			}
		}

		cli->nblogin++;

#ifdef IPLIST
		if (ipdata) iplist_goodlogin(ipdata);
#endif
		// Store program id
		cli->progid = clicd.sid;

		buf[0] = MSG_CLIENT_2_SERVER_LOGIN_ACK;
		buf[1] = 0;
		buf[2] = 0;

		//clicd.msgid = 0;
		clicd.sid = 0x6E73;
		clicd.caid = 0;
		clicd.provid = 0x14000000; // mgcamd protocol version?
		cs_message_send(sock, &clicd, buf, 3, sessionkey);
		//
		des_login_key_get( mgcamd->key, (unsigned char*)passwdcrypt, strlen(passwdcrypt),sessionkey);
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
		mlogf(LOGINFO,getdbgflag(DBG_MGCAMD,0,cli->id)," mgcamd: client '%s' connected (%s)\n", cli->user, ip2string(ip));
		pthread_mutex_unlock(&prg.lockclimg);
#ifdef EPOLL_MGCAMD
		pipe_pointer( prg.pipe.mgcamd[1], PIPE_CLI_CONNECTED, cli );
#else
		pipe_wakeup( prg.pipe.mgcamd[1] );
#endif
		// update pfd data
		cli->parent->clipfd.update = 1;
	}
	else {
		// send NAK
		buf[0] = MSG_CLIENT_2_SERVER_LOGIN_NAK;
		buf[1] = 0;
		buf[2] = 0;
		//cs_message_send(sock, NULL, buf, 3, sessionkey);
		mlogf(LOGWARNING,getdbgflag(DBG_MGCAMD,0,cli->id)," mgcamd: client '%s' wrong password (%s)\n", cli->user, ip2string(ip));
		cli->nbloginerror++;
		pthread_mutex_unlock(&prg.lockclimg);
		close(sock);
	}
	return NULL;
}

void mgcamd_srv_accept(struct mgcamdserver_data *srv)
{
	struct sockaddr_in newaddr;
	socklen_t socklen = sizeof(struct sockaddr);
	int newfd = accept( srv->handle, (struct sockaddr*)&newaddr, /*(socklen_t*)*/&socklen);
	if ( newfd<=0 ) {
		if ( (errno!=EAGAIN) && (errno!=EINTR) ) mlogf(LOGERROR,getdbgflag(DBG_MGCAMD,0,0)," Mgcamd%d: Accept failed (errno=%d)\n", srv->id,errno);
	}
	else {
		SetSocketReuseAddr(newfd);
		uint32_t newip = newaddr.sin_addr.s_addr;
#ifdef IPLIST
		struct ip_hacker_data *ipdata = iplist_find( srv->iplist, newip );
		if (!ipdata) {
			ipdata = iplist_add( newip );
			ipdata->next = srv->iplist;
			srv->iplist = ipdata;
		}
#endif
		if ( isblockedip(newip) ) {
			mlogf(LOGWARNING,getdbgflag(DBG_MGCAMD,0,0)," Mgcamd%d: New Connection (%s) closed, ip blocked\n", srv->id, ip2string(newip) );
			close(newfd);
		}
#ifdef IPLIST
		else if ( !iplist_accept( ipdata ) ) {
			mlogf(LOGWARNING,getdbgflag(DBG_MGCAMD,srv->id,0)," Mgcamd%d: New Connection (%s) closed, ip temporary blocked\n", srv->id, ip2string(newip) );
			close(newfd);
		}
#endif
		else {
			pthread_t srv_tid;
			if (cfg.mgcamd.keepalive) SetSocketKeepalive(newfd);
			SetSocketNoDelay(newfd);
			SetSoketNonBlocking(newfd);
			//mlogf(LOGDEBUG,getdbgflag(DBG_MGCAMD,0,0)," Mgcamd%d: new connection (%s)\n", srv->id, ip2string(newip) );
			struct connect_cli_data *newdata = malloc( sizeof(struct connect_cli_data) );
			newdata->server = srv; 
			newdata->sock = newfd; 
			newdata->ip = newaddr.sin_addr.s_addr;
			if ( !create_thread(&srv_tid, (threadfn)mg_connect_cli,newdata) ) {
				free( newdata );
				close( newfd );
			}
			usleep(cfg.delay.connect);
		}
	}
}

#ifndef MONOTHREAD_ACCEPT

void *mgcamd_accept_thread(void *param)
{
#ifndef PUBLIC
	prctl(PR_SET_NAME,"MGcamd Accept",0,0,0);
#endif
	sleep(5);

	while(!prg.restart) {

		struct pollfd pfd[18];
		int pfdcount = 0;

		struct mgcamdserver_data *mgcamd = cfg.mgcamd.server;
		while (mgcamd) {
			if ( !IS_DISABLED(mgcamd->flags) && (mgcamd->handle>0) ) {
				mgcamd->ipoll = pfdcount;
				pfd[pfdcount].fd = mgcamd->handle;
				pfd[pfdcount++].events = POLLIN | POLLPRI;
			} else mgcamd->ipoll = -1;
			mgcamd = mgcamd->next;
		}

		if (pfdcount) {
			int retval = poll(pfd, pfdcount, 3006);
			if ( retval>0 ) {
				struct mgcamdserver_data *mgcamd = cfg.mgcamd.server;
				while (mgcamd) {
					if ( !IS_DISABLED(mgcamd->flags) && (mgcamd->handle>0) && (mgcamd->ipoll>=0) && (mgcamd->handle==pfd[mgcamd->ipoll].fd) ) {
						if ( pfd[mgcamd->ipoll].revents & (POLLIN|POLLPRI) ) mgcamd_srv_accept2(mgcamd);
					}
					mgcamd = mgcamd->next;
				}
			}
			else if (retval<0) usleep(96000);
		} else sleep(1);
	}
	return NULL;
}

#endif


////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

#include "status_connect_mgcamd.c"

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////////////////////////////////////////
// MGCAMD SERVER:  SEND DCW TO CLIENTS
///////////////////////////////////////////////////////////////////////////////

void mg_senddcw_cli(struct mg_client_data *cli)
{
	if (cli->ecm.status==STAT_DCW_SENT) {
		mlogf(LOGWARNING,getdbgflag(DBG_MGCAMD,0,cli->id)," +> cw send failed to mgcamd client '%s', cw already sent\n", cli->user); 
		return;
	}
	if (cli->handle==INVALID_SOCKET) {
		mlogf(LOGWARNING,getdbgflag(DBG_MGCAMD,0,cli->id)," +> cw send failed to mgcamd client '%s', client disconnected\n", cli->user); 
		return;
	}
	if (!cli->ecm.busy) {
		mlogf(LOGWARNING,getdbgflag(DBG_MGCAMD,0,cli->id)," +> cw send failed to mgcamd client '%s', no ecm request\n", cli->user); 
		return;
	}

	uint8_t buf[CC_MAXMSGSIZE];
	uint32_t ticks = GetTickCount();
	ECM_DATA *ecm = cli->ecm.request;
	if (!ecm) return;
	struct cs_custom_data clicd; // Custom data
	//FREEZE
	int enablefreeze;
	if ( (cli->lastecm.caid==ecm->caid)&&(cli->lastecm.prov==ecm->provid)&&(cli->lastecm.sid==ecm->sid) ) {
		if (cli->lastecm.hash!=ecm->hash)
		if ( (cli->lastecm.status=1)&&(cli->lastdcwtime+200<ticks) ) enablefreeze = 1;
	} else cli->zap++;
	// Store Last ECM
	cli->lastecm.caid = ecm->caid;
	cli->lastecm.prov = ecm->provid;
	cli->lastecm.sid = ecm->sid;
	cli->lastecm.hash = ecm->hash;
	cli->lastecm.tag = ecm->ecm[0];
	cli->lastecm.decodetime = ticks-cli->ecm.recvtime;
	cli->lastecm.request = cli->ecm.request;
	// Store action
	cli->ecm.request = NULL;
	cli->ecm.busy = 0;
	cli->ecm.status = STAT_DCW_SENT;
	// Get Custom data
	clicd.msgid = cli->ecm.climsgid;
	clicd.sid = ecm->sid;
	clicd.caid = ecm->caid;
	clicd.provid = ecm->provid;
	// Send
	if ( (ecm->hash==cli->ecm.hash)&&(ecm->dcwstatus==STAT_DCW_SUCCESS) ) {
		cli->lastecm.dcwsrctype = ecm->dcwsrctype;
		cli->lastecm.dcwsrcid = ecm->dcwsrcid;
		cli->lastecm.status=1;
		cli->ecmok++;
		cli->ecmoktime += ticks-cli->ecm.recvtime;
		buf[0] = ecm->ecm[0];
		buf[1] = 0;
		buf[2] = 0x10;
		memcpy( &buf[3], ecm->cw, 16 );
		if ( !cs_message_send( cli->handle, &clicd, buf, 19, cli->sessionkey) ) mg_disconnect_cli( cli );
		else mlogf(LOGINFO,getdbgflagpro(DBG_MGCAMD,0,cli->id,ecm->cs->id)," => cw to mgcamd client '%s' ch %04x:%06x:%04x (%dms)\n", cli->user, ecm->caid,ecm->provid,ecm->sid, ticks-cli->ecm.recvtime);
		cli->lastdcwtime = ticks;
	}
	else { //if (ecm->data->dcwstatus==STAT_DCW_FAILED)
		if (enablefreeze) cli->freeze++;
		cli->lastecm.status=0;
		cli->lastecm.dcwsrctype = DCW_SOURCE_NONE;
		cli->lastecm.dcwsrcid = 0;
		buf[0] = ecm->ecm[0];
		buf[1] = 0;
		buf[2] = 0;
		if ( !cs_message_send(  cli->handle, &clicd, buf, 3, cli->sessionkey) ) mg_disconnect_cli( cli );
		else mlogf(LOGINFO,getdbgflagpro(DBG_MGCAMD,0,cli->id,ecm->cs->id)," |> decode failed to mgcamd client '%s' ch %04x:%06x:%04x (%dms)\n", cli->user, ecm->caid,ecm->provid,ecm->sid, ticks-cli->ecm.recvtime);
	}
}

///////////////////////////////////////////////////////////////////////////////

// Check sending cw to clients
#ifdef ECMLIST
void mg_check_sendcw(ECM_DATA *ecm)
{
	struct mg_client_data *cli = ecm->client.mgcamd;
	while (cli) {
		struct mg_client_data *next = cli->nextEcm;
		if ( !IS_DISABLED(cli->flags)&&(cli->connection.status>0)&&(cli->ecm.busy)&&(cli->ecm.request==ecm) ) {
			mg_senddcw_cli( cli );
		}
		cli->nextEcm = NULL;
		cli = next;
	}
	ecm->client.mgcamd = NULL;
}
#else
void mg_check_sendcw(ECM_DATA *ecm)
{
	struct mgcamdserver_data *mgcamd = cfg.mgcamd.server;
	while (mgcamd) {
		if ( !IS_DISABLED(mgcamd->flags) && (mgcamd->handle>0) ) {
			struct mg_client_data *cli = mgcamd->client;
			while (cli) {
				if ( !IS_DISABLED(cli->flags)&&(cli->handle!=INVALID_SOCKET)&&(cli->ecm.busy)&&(cli->ecm.request==ecm)&&(cli->ecm.status==STAT_ECM_SENT) ) {
					mg_senddcw_cli( cli );
				}
				cli = cli->next;
			}
		}
		mgcamd = mgcamd->next;
	}
}
#endif

///////////////////////////////////////////////////////////////////////////////
// RECEIVE MESSAGES
///////////////////////////////////////////////////////////////////////////////

void mg_store_ecmclient( ECM_DATA *ecm, struct mg_client_data *cli, int climsgid)
{
	cli->ecm.recvtime = GetTickCount();
	cli->ecm.busy = 1;
	cli->ecm.request = ecm;
	cli->ecm.hash = ecm->hash;
    cli->ecm.climsgid = climsgid;
    cli->ecm.status = STAT_ECM_SENT;
	ecm_addip(ecm, cli->ip);
}

void mg_cli_recvmsg(struct mg_client_data *cli)
{
	if (cli->handle<=0) return;
	// Get Message
	struct cardserver_data *cs = NULL;
	uint8_t buf[CC_MAXMSGSIZE];
	unsigned char ecmdata[CWS_NETMSGSIZE]; // for other use
	int ecmlen;
	struct cs_custom_data clicd; // Custom data
    int len = cs_msg_peek( cli->handle, &clicd, buf, cli->sessionkey );
	if (len==0) mg_disconnect_cli(cli);
	else if (len<0) {
		mlogf(LOGERROR,getdbgflag(DBG_MGCAMD,cli->id,0)," mgcamd: client '%s' read failed %d (%d)\n", cli->user, len, errno);
		mg_disconnect_cli(cli);
	}
	else {
		// Parse 
		uint32_t ticks = GetTickCount();
		cli->lastactivity = ticks;
		struct mgcamdserver_data *mgcamd = cli->parent;

		switch ( buf[0] ) {

			case EXT_GET_VERSION:
				memset( buf, 0, sizeof(buf) );
				buf[0] = EXT_GET_VERSION; buf[1]=0; buf[2]=0;
				buf[3] = 0x31;
				buf[4] = 0x2e;
				buf[5] = 0x36;
				buf[6] = 0x37;// 1.67
				if ( !cs_message_send(cli->handle, 0, buf, 7, cli->sessionkey) ) { mg_disconnect_cli( cli ); return; }
				break;

			case MSG_CARD_DATA_REQ:
				memset( buf, 0, sizeof(buf) );
				buf[0] = MSG_CARD_DATA; buf[1]=0; buf[2]=0;
				buf[3] = 2;
				buf[4] = 0;
				buf[5] = 0;
				buf[14] = 1;
				if ( !cs_message_send(cli->handle, &clicd, buf, 15+11, cli->sessionkey) ) { mg_disconnect_cli( cli ); return; }
				if (cli->csport[0]) {
					int i;
					for (i=0;i<MAX_CSPORTS;i++) {
						if (!cli->csport[i]) break;
						cs = getcsbyport(cli->csport[i]);
						if ( cs && cs->option.fsharemgcamd && !(cli->flags&FLAG_EXPIRED) )
						for (len=0; len<cs->card.nbprov; len++) {
							clicd.sid = mgcamd->port;
							clicd.caid = cs->card.caid; 
							clicd.provid = cs->card.prov[len].id;
							buf[0] = EXT_ADD_CARD; buf[1]=0; buf[2]=0;
							if ( card_sharelimits(cli->sharelimits, clicd.caid, clicd.provid) )
								if ( !cs_message_send(cli->handle, &clicd, buf, 3, cli->sessionkey) ) { mg_disconnect_cli( cli ); return; }
						}
					}
				}
				else if (mgcamd->csport[0]) {
					int i;
					for(i=0;i<MAX_CSPORTS;i++) {
						if (!mgcamd->csport[i]) break;
						cs = getcsbyport(mgcamd->csport[i]);
						if ( cs && cs->option.fsharemgcamd && !(cli->flags&FLAG_EXPIRED) )
						for (len=0; len<cs->card.nbprov; len++) {
							clicd.sid = mgcamd->port;
							clicd.caid = cs->card.caid; 
							clicd.provid = cs->card.prov[len].id;
							buf[0]=EXT_ADD_CARD; buf[1]=0; buf[2]=0;
							if ( card_sharelimits(cli->sharelimits, clicd.caid, clicd.provid) )
								if ( !cs_message_send(cli->handle, &clicd, buf, 3, cli->sessionkey) ) { mg_disconnect_cli( cli ); return; }
						}
					}
				}
				else {
					cs = cfg.cardserver;
					while (cs) {
						if ( cs->option.fsharemgcamd && !(cli->flags&FLAG_EXPIRED) )
						for (len=0; len<cs->card.nbprov; len++) {
							clicd.sid = mgcamd->port;
							clicd.caid = cs->card.caid; 
							clicd.provid = cs->card.prov[len].id;
							buf[0]=EXT_ADD_CARD; buf[1]=0; buf[2]=0;
							if ( card_sharelimits(cli->sharelimits, clicd.caid, clicd.provid) )
								if ( !cs_message_send(cli->handle, &clicd, buf, 3, cli->sessionkey) ) {	mg_disconnect_cli( cli ); return; }
						}
						cs = cs->next;
					}
				}
				mlogf(LOGINFO,getdbgflag(DBG_MGCAMD,0,cli->id)," mgcamd: send card data to client '%s'\n", cli->user);
				cli->cardsent = 1;
				break;

			case 0x80:
			case 0x81:
				//debugdump(buf, len, "ECM: ");
				cli->lastecmtime = ticks;
				//cli->ecmnb++; new var for not accepted ecm's
				cli->ecmnb++;
				ecmlen = len;
				memcpy( ecmdata, buf, len);
				uint32_t provid = ecm_getprovid( ecmdata, clicd.caid );
				if (provid!=0) clicd.provid = provid;
#ifdef ECMLIST
				if (cli->ecm.busy) {
					if (cli->nextEcm && cli->ecm.request) mg_ecmlist_del( cli );
					cli->ecmdenied++;
				}
				cli->nextEcm = NULL;
#endif
				cli->ecm.busy = 0;
				cli->ecm.request = NULL;
				// Check for CAID&SID
				if ( !clicd.caid ) {
					cli->ecmdenied++;
					// send decode failed
					buf[1] = 0; buf[2] = 0;
					if ( !cs_message_send( cli->handle, &clicd, buf, 3, cli->sessionkey) ) { mg_disconnect_cli( cli ); return; }
					mlogf(LOGINFO,getdbgflag(DBG_MGCAMD,0,cli->id)," <|> decode failed to mgcamd client '%s' ch %04x:%06x:%04x Invalid CAID\n", cli->user,clicd.caid,clicd.provid,clicd.sid);
					break;
				}
				int i,j,port;
				if (cli->csport[0]) {
					for(i=0; i<MAX_CSPORTS; i++) {
						port = cli->csport[i];
						if (!port) break;
						cs = getcsbyport(port);
						if (cs)
						if (cs->option.fsharemgcamd)
						if (clicd.caid==cs->card.caid) {
							for (j=0; j<cs->card.nbprov;j++) if (clicd.provid==cs->card.prov[j].id) break;
							if (j<cs->card.nbprov) break;
						}
					}
					if (!port || !cs) {
						cli->ecmdenied++;
						// send decode failed
						buf[1] = 0; buf[2] = 0;
						if ( !cs_message_send( cli->handle, &clicd, buf, 3, cli->sessionkey) ) { mg_disconnect_cli( cli ); return; }
						mlogf(LOGINFO,getdbgflag(DBG_MGCAMD,0,cli->id)," <|> decode failed to client '%s' ch %04x:%06x:%04x, Invalid CAID/PROVIDER\n", cli->user,clicd.caid,clicd.provid,clicd.sid);
						break;
					}
				}
				else {
					cs = cfg.cardserver;
					while (cs) {
						if (cs->option.fsharemgcamd)
						if (clicd.caid==cs->card.caid) {
							for (j=0; j<cs->card.nbprov;j++) if (clicd.provid==cs->card.prov[j].id) break;
							if (j<cs->card.nbprov) break;
						}
						cs = cs->next;
					}
					if (!cs) {
						cli->ecmdenied++;
						// send decode failed
						buf[1] = 0; buf[2] = 0;
						if ( !cs_message_send( cli->handle, &clicd, buf, 3, cli->sessionkey) ) { mg_disconnect_cli( cli ); return; }
						mlogf(LOGINFO,getdbgflag(DBG_MGCAMD,0,cli->id)," <|> decode failed to client '%s' ch %04x:%06x:%04x, Invalid CAID/PROVIDER\n", cli->user,clicd.caid,clicd.provid,clicd.sid);
						break;
					}
				}
				// Check for Accepted sids
				uint8_t cw1cycle;
				if ( !accept_sid(cs, clicd.provid, clicd.sid, ecm_getchid(ecmdata,clicd.caid), ecmlen, &cw1cycle) ) {
					cli->ecmdenied++;
					cs->ecmdenied++;
					// send decode failed
					buf[1] = 0; buf[2] = 0;
					if ( !cs_message_send( cli->handle, &clicd, buf, 3, cli->sessionkey) ) { mg_disconnect_cli( cli ); return; }
					mlogf(LOGINFO,getdbgflagpro(DBG_MGCAMD,0,cli->id,cs->id)," <|> decode failed to mgcamd client '%s' ch %04x:%06x:%04x SID not accepted\n", cli->user,clicd.caid,clicd.provid,clicd.sid);
					break;
				}
				if ( !accept_ecmlen(len) ) {
					cli->ecmdenied++;
					cs->ecmdenied++;
					// send decode failed
					buf[1] = 0; buf[2] = 0;
					if ( !cs_message_send( cli->handle, &clicd, buf, 3, cli->sessionkey) ) { mg_disconnect_cli( cli ); return; }
					mlogf(LOGINFO,getdbgflagpro(DBG_MGCAMD,0,cli->id,cs->id)," <|> decode failed to mgcamd client '%s' ch %04x:%06x:%04x, ecm length error(%d)\n", cli->user,clicd.caid,clicd.provid,clicd.sid,len);
					break;
				}
				// ACCEPTED
				pthread_mutex_lock(&prg.lockecm); //###
				// Search for ECM
				ECM_DATA *ecm = search_ecmdata_any(cs, ecmdata, ecmlen, clicd.sid, clicd.caid); // dont get failed ecm request from cache
				if (ecm) {
					ecm->lastrecvtime = ticks;
					if (ecm->dcwstatus==STAT_DCW_FAILED) {
						if (ecm->period > cs->option.dcw.retry) {
							// send decode failed
							buf[1] = 0; buf[2] = 0;
							cs_message_send(cli->handle, &clicd, buf, 3, cli->sessionkey);
							mlogf(LOGINFO,getdbgflagpro(DBG_MGCAMD,0,cli->id,cs->id)," <|> decode failed to mgcamd client '%s' ch %04x:%06x:%04x, already failed\n", cli->user,clicd.caid,clicd.provid,clicd.sid);
						}
						else {
							ecm->period++; // RETRY
							mg_store_ecmclient(ecm, cli, clicd.msgid);
							mlogf(LOGINFO,getdbgflagpro(DBG_MGCAMD,0,cli->id, cs->id)," <- ecm from mgcamd client '%s' ch %04x:%06x:%04x:%08x**\n",cli->user,clicd.caid,clicd.provid,clicd.sid,ecm->hash);
#ifdef ECMLIST
							// Add to ECM list
							cli->nextEcm = ecm->client.mgcamd;
							ecm->client.mgcamd = cli;
#endif
							ecm->dcwstatus = STAT_DCW_WAIT;
							ecm->cachestatus = 0; //ECM_CACHE_NONE; // Resend Request
							ecm->checktime = 1; // Check NOW
							pipe_wakeup( prg.pipe.ecm[1] );
						}
					}
					else {
						//TODO: Add another card for sending ecm
						mg_store_ecmclient(ecm, cli, clicd.msgid);
						mlogf(LOGINFO,getdbgflagpro(DBG_MGCAMD,0,cli->id, cs->id)," <- ecm from mgcamd client '%s' ch %04x:%06x:%04x:%08x*\n",cli->user,clicd.caid,clicd.provid,clicd.sid,ecm->hash);
						if (cli->dcwcheck) {
							if ( !ecm->lastdecode.ecm && (ecm->lastdecode.ecm!=ecm) ) {
								checkfreeze_checkECM( ecm, cli->lastecm.request);
								if (ecm->lastdecode.ecm) pipe_cache_find(ecm, cs);
							}
						}
						// Check for Success/Timeout
						if (!ecm->checktime) {
							mg_senddcw_cli(cli);
							pthread_mutex_unlock(&prg.lockecm); //###
							break;
							if ( cli->dcwcheck && !cs->option.dcw.halfnulled && (ecm->dcwstatus==STAT_DCW_SUCCESS) && !checkfreeze_setdcw(ecm,ecm->cw) ) { // ??? last ecm is wrong
								ecm->dcwstatus = STAT_DCW_WAIT;
								memset( ecm->cw, 0, 16 );
								ecm->checktime = 1; // Wakeup Now
								pipe_wakeup( prg.pipe.ecm[1] );
							}
							else {
								mg_senddcw_cli(cli);
								pthread_mutex_unlock(&prg.lockecm); //###
								break;
							}
						}
#ifdef ECMLIST
						// Add to ECM list
						cli->nextEcm = ecm->client.mgcamd;
						ecm->client.mgcamd = cli;
#endif
					}
				}
				else {
					cs->ecmaccepted++;
					// Setup ECM Request for Server(s)
					ecm = store_ecmdata(cs, ecmdata, ecmlen, clicd.sid,clicd.caid,clicd.provid);
					mg_store_ecmclient(ecm, cli, clicd.msgid);
					mlogf(LOGINFO,getdbgflagpro(DBG_MGCAMD,0,cli->id, cs->id)," <- ecm from mgcamd client '%s' ch %04x:%06x:%04x:%08x\n",cli->user,clicd.caid,clicd.provid,clicd.sid,ecm->hash);
#ifdef ECMLIST
					// Add to ECM list
					cli->nextEcm = ecm->client.mgcamd;
					ecm->client.mgcamd = cli;
#endif
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
						mlogf(LOGINFO,0," <- ecm from Mgcamd client '%s' ch %04x:%06x:%04x %02x:%08x\n", cli->user, ecm->caid, ecm->provid, ecm->sid, ecm->ecm[0], ecm->hash);
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
					mlogf(LOGWARNING,getdbgflagpro(DBG_MGCAMD,0,cli->id,ecm->cs->id)," <!= wrong cw from Client '%s' ch %04x:%06x:%04x\n", cli->user, ecm->caid,ecm->provid,ecm->sid, ticks-cli->lastecmtime);
					pthread_mutex_unlock(&prg.lockecm);
					break;
				}
				if ( (ecm->caid!=clicd.caid) || (ecm->sid!=clicd.sid) || (ecm->provid!=clicd.provid) || (cli->ecm.climsgid!=clicd.msgid) ) {
					mlogf(LOGWARNING,getdbgflagpro(DBG_MGCAMD,0,cli->id,ecm->cs->id)," <!= wrong cw from Client '%s' ch %04x:%06x:%04x\n", cli->user, ecm->caid,ecm->provid,ecm->sid, ticks-cli->lastecmtime);
					pthread_mutex_unlock(&prg.lockecm);
					break;
				}
				if ( (buf[0]&0x81)!=ecm->ecm[0] ) {
					mlogf(LOGWARNING,getdbgflagpro(DBG_MGCAMD,0,cli->id,ecm->cs->id)," <!= wrong cw from Client '%s' ch %04x:%06x:%04x\n", cli->user, ecm->caid,ecm->provid,ecm->sid, ticks-cli->lastecmtime);
					pthread_mutex_unlock(&prg.lockecm);
					break;
				}
				if (buf[2]!=0x10) {
					mlogf(LOGWARNING,getdbgflagpro(DBG_MGCAMD,0,cli->id,ecm->cs->id)," <!= wrong cw from Client '%s' ch %04x:%06x:%04x\n", cli->user, ecm->caid,ecm->provid,ecm->sid, ticks-cli->lastecmtime);
					pthread_mutex_unlock(&prg.lockecm);
					break;
				}
				// Check for DCW
				cs= ecm->cs;
				int isnanoe0=ecm_isnanoe0(ecm->ecm,ecm->caid);
				if (!acceptDCW(&buf[3], isnanoe0)) {
					mlogf(LOGWARNING,getdbgflagpro(DBG_MGCAMD,0,cli->id,ecm->cs->id)," <!= wrong cw from Client '%s' ch %04x:%06x:%04x\n", cli->user, ecm->caid,ecm->provid,ecm->sid, ticks-cli->lastecmtime);
					pthread_mutex_unlock(&prg.lockecm);
					break;
				}
				mlogf(LOGINFO,getdbgflagpro(DBG_MGCAMD,0,cli->id,ecm->cs->id)," <= cw from mgcamd client '%s' ch %04x:%06x:%04x (%dms)\n", cli->user, ecm->caid,ecm->provid,ecm->sid, ticks-cli->lastecmtime);
				if (ecm->dcwstatus!=STAT_DCW_SUCCESS) {
					static char msg[] = "Good dcw from mgcamd Client";
					ecm->statusmsg = msg;
					// Store ECM Answer
					ecm_setdcw( ecm, &buf[3], DCW_SOURCE_MGCLIENT, cli->id );
				}
				else {	//TODO: check same dcw between cards
					if ( memcmp(&ecm->cw, &buf[3],16) ) mlogf(LOGWARNING,getdbgflagpro(DBG_MGCAMD,0,cli->id,ecm->cs->id)," !!! different dcw from mgcamd client '%s'\n", cli->user);
				}
				pthread_mutex_unlock(&prg.lockecm); //###
				break;
#endif

			default:
				if (buf[0]==MSG_KEEPALIVE) {
#ifdef SRV_CSCACHE
					// Check for Cache client??
					if (clicd.sid==(('C'<<8)|'H')) { clicd.caid = ('O'<<8)|'K'; cli->cachedcw++; }
#endif
					if ( !cs_message_send(cli->handle, &clicd, buf, 3, cli->sessionkey) ) mg_disconnect_cli( cli );
				}
				else {
					mlogf(LOGWARNING,getdbgflag(DBG_MGCAMD,0,cli->id)," mgcamd: unknown message type '%02x' from client '%s'\n",buf[0],cli->user);
					buf[1]=0; buf[2]=0;
					if ( !cs_message_send( cli->handle, &clicd, buf, 3, cli->sessionkey) ) mg_disconnect_cli( cli );
				}
				break;
		} // Switch
	}
}


///////////////////////////////////////////////////////////////////////////////
// THREAD RECV MSG
///////////////////////////////////////////////////////////////////////////////

void mg_recv_pipe()
{
	struct mgcamdserver_data *mgcamd;
	struct cardserver_data *cs;

	struct mg_client_data *cli;

	uint8_t buf[1024];
	struct pollfd pfd[2];
	do {
		int len = pipe_recv( prg.pipe.mgcamd[0], buf);
		if (len>0) {
			switch(buf[0]) {
				case PIPE_WAKEUP:  // ADD NEW CLIENT
					//mlogf(LOGTRACE,0," wakeup csmsg\n");
					break;
#ifdef EPOLL_MGCAMD
				case PIPE_CLI_CONNECTED:  // ADD NEW FD
					memcpy( &cli, buf+1, sizeof(void*) );
					// Add to events
					struct epoll_event ev; // epoll event
					ev.events = EPOLLIN;
					ev.data.fd = cli->handle;
					ev.data.ptr = cli;
					if ( epoll_ctl(prg.epoll.mgcamd, EPOLL_CTL_ADD, cli->handle, &ev) == -1 ) mlogf(LOGERROR,DBG_ERROR,"Err! EPOLL_CTL_ADD %s (%d)\n", cli->user, cli->handle);
					//else mlogf(LOGDUMP,0,"EPOLL_CTL_ADD %s (%d)\n", cli->user, cli->handle);
					break;
#endif
				case PIPE_CARD_DEL:
					memcpy( &cs, buf+1, sizeof(void*) );
					if (cs) {
						mgcamd = cfg.mgcamd.server;
						while (mgcamd) {
							if ( !IS_DISABLED(mgcamd->flags)&&(mgcamd->handle>0) ) {
								struct mg_client_data *cli = mgcamd->client;
								while (cli) {
									if ( !IS_DISABLED(cli->flags)&&(cli->handle>0) ) {
										mg_sendcard_del(cs, mgcamd, cli);
									}
									cli = cli->next;
								}
							}
							mgcamd = mgcamd->next;
						}
					}
					break;

				case PIPE_CARD_ADD:
					memcpy( &cs, buf+1, sizeof(void*) );
					if (cs) {
						mgcamd = cfg.mgcamd.server;
						while (mgcamd) {
							if ( !IS_DISABLED(mgcamd->flags)&&(mgcamd->handle>0) ) {
								struct mg_client_data *cli = mgcamd->client;
								while (cli) {
									if ( !IS_DISABLED(cli->flags)&&(cli->handle>0) ) {
										mg_sendcard_add(cs, mgcamd, cli);
									}
									cli = cli->next;
								}
							}
							mgcamd = mgcamd->next;
						}
					}
					break;

			}
		}
		pfd[0].fd = prg.pipe.mgcamd[0];
		pfd[0].events = POLLIN | POLLPRI;
	} while (poll(pfd, 1, 3)>0);
}

///////////////////////////////////////////////////////////////////////////////

#ifdef EPOLL_MGCAMD

void *mg_recvmsg_thread(void *param)
{
	int i;

#ifndef PUBLIC
	cfg.mgcamd.pid_recvmsg = syscall(SYS_gettid);
	prg.pid_mg_msg = syscall(SYS_gettid);
	prctl(PR_SET_NAME,"Mgcamd RecvMSG",0,0,0);
#endif
	struct epoll_event evlist[MAX_EPOLL_EVENTS]; // epoll recv events

	prg.epoll.mgcamd = epoll_create( MAX_EPOLL_EVENTS );
	// Add PIPE
	struct epoll_event ev; // epoll event
	ev.events = EPOLLIN | EPOLLPRI | EPOLLRDHUP;
	ev.data.ptr = NULL;
	if ( epoll_ctl(prg.epoll.mgcamd, EPOLL_CTL_ADD, prg.pipe.mgcamd[0], &ev) == -1 ) mlogf(LOGERROR,0,"epoll_ctl error mgcamd rcvmsg -1");

	while(1) {
		int ready = epoll_wait( prg.epoll.mgcamd, evlist, MAX_EPOLL_EVENTS, 1003);
		if (ready == -1) {
			if ( (errno==EINTR)||(errno==EAGAIN) ) {
				usleep(cfg.delay.thread);
				continue;
			}
			else {
				usleep(99000);
				mlogf(LOGERROR,DBG_ERROR,"Err! epoll_wait (%d)", errno);
				continue;
			}
		}
		else if (ready==0) continue; // timeout

		usleep(cfg.delay.thread);
		for (i=0; i < ready; i++) {
			if ( evlist[i].events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR) ) { // EPOLLRDHUP
				if (evlist[i].data.ptr == NULL) mlogf(LOGERROR,DBG_ERROR,"Err! epoll_wait() pipe\n"); // error !!!
				else mg_disconnect_cli(evlist[i].data.ptr);
			}
			else if ( evlist[i].events & (EPOLLIN|EPOLLPRI) ) {
				if (evlist[i].data.ptr == NULL) mg_recv_pipe();
				else mg_cli_recvmsg(evlist[i].data.ptr);
			}
		}
	}
	return NULL;
}

#else

void *mg_recvmsg_thread(void *param)
{
	struct pollfd pfd[MAX_PFD];
	int pfdcount;

#ifndef PUBLIC
	cfg.mgcamd.pid_recvmsg = syscall(SYS_gettid);
	prg.pid_mg_msg = syscall(SYS_gettid);
	prctl(PR_SET_NAME,"MGcamd RecvMSG",0,0,0);
#endif

	while (1) {
		pfdcount = 0;
		// PIPE
		pfd[pfdcount].fd = prg.pipe.mgcamd[0];
		pfd[pfdcount++].events = POLLIN | POLLPRI;

		struct mgcamdserver_data *mgcamd = cfg.mgcamd.server;
		while (mgcamd) {
			if ( !IS_DISABLED(mgcamd->flags)&&(mgcamd->handle>0) ) {
				if (mgcamd->clipfd.update||mgcamd->clipfd.count<0) {
					mgcamd->clipfd.count = 0;
					struct mg_client_data *cli = mgcamd->client;
					while (cli && (mgcamd->clipfd.count<MGCAMD_MAX_PFD)) {
						if ( !IS_DISABLED(cli->flags) && (cli->handle>0) && !(cli->flags&FLAG_WORKTHREAD) ) {
							cli->ipoll = mgcamd->clipfd.count;
							mgcamd->clipfd.pfd[mgcamd->clipfd.count].fd = cli->handle;
							mgcamd->clipfd.pfd[mgcamd->clipfd.count++].events = POLLIN | POLLPRI;
						} else cli->ipoll = -1;
						cli = cli->next;
					}
					mgcamd->clipfd.update = 0;
					//mlogf(LOGDUMP,getdbgflag(DBG_ERROR,0,0), " mgcamd clients poll updated %d\n", mgcamd->clipfd.count);
				}
				mgcamd->clipfd.ipoll = pfdcount;
				if (mgcamd->clipfd.count>0) {
					memcpy( &pfd[pfdcount], mgcamd->clipfd.pfd, mgcamd->clipfd.count * sizeof(struct pollfd) );
					pfdcount += mgcamd->clipfd.count;
				}
			}
			mgcamd = mgcamd->next;
		}

		int retval = poll(pfd, pfdcount, 3010); // for 3seconds

		if ( retval>0 ) {
			usleep(cfg.delay.thread);

			struct mgcamdserver_data *mgcamd = cfg.mgcamd.server;
			while (mgcamd) {
				if ( !IS_DISABLED(mgcamd->flags)&&(mgcamd->handle>0)&&(mgcamd->clipfd.count>0) ) {
					pthread_mutex_lock(&prg.lockclimg);
					struct mg_client_data *mgcli = mgcamd->client;
					while (mgcli) {
						if ( !IS_DISABLED(mgcli->flags)&&(mgcli->handle>0)&&(mgcli->ipoll>=0)&&(mgcli->handle==pfd[mgcamd->clipfd.ipoll+mgcli->ipoll].fd) ) {
							if ( pfd[mgcamd->clipfd.ipoll+mgcli->ipoll].revents & (POLLHUP|POLLNVAL) ) mg_disconnect_cli(mgcli);
							else if ( pfd[mgcamd->clipfd.ipoll+mgcli->ipoll].revents & (POLLIN|POLLPRI) ) {
								mg_cli_recvmsg(mgcli);
							}
							///else if ( (GetTickCount()-mgcli->lastactivity) > 600000 ) mg_disconnect_cli(mgcli);
						}
						mgcli = mgcli->next;
					}
					pthread_mutex_unlock(&prg.lockclimg);
				}
				mgcamd = mgcamd->next;
			}
			//
			if ( pfd[0].revents & (POLLIN|POLLPRI) ) mg_recv_pipe();
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
// MGCAMD SERVER: START/STOP
///////////////////////////////////////////////////////////////////////////////

int start_thread_mgcamd()
{
	pthread_t tid;
#ifndef MONOTHREAD_ACCEPT
	create_thread(&tid, mgcamd_accept_thread,NULL);
	create_thread(&tid, mgcamd_connector_thread,NULL);
#endif

	create_thread(&cfg.mgcamd.tid_recvmsg, mg_recvmsg_thread,NULL);
	return 0;
}

