///////////////////////////////////////////////////////////////////////////////
// File: srv-cccam.c
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// PROTO
///////////////////////////////////////////////////////////////////////////////

void cc_senddcw_cli(struct cc_client_data *cli);
void cccam_srv_accept2(struct cccam_server_data *cccam);


struct cccam_server_data *getcccamserverbyid(uint32_t id)
{
	struct cccam_server_data *cccam = cfg.cccam.server;
	while (cccam) {
		if (!(cccam->flags&FLAG_DELETE))
			if (cccam->id==id) return cccam;
		cccam = cccam->next;
	}
	return NULL;
}

struct cc_client_data *getcccamclientbyid(uint32_t id)
{
	struct cccam_server_data *cccam = cfg.cccam.server;
	while (cccam) {
		if (!(cccam->flags&FLAG_DELETE)) {
			struct cc_client_data *cli = cccam->client;
			while (cli) {
				if (!(cli->flags&FLAG_DELETE))
					if (cli->id==id) return cli;
				cli = cli->next;
			}
			cli = cccam->cacheexclient;
			while (cli) {
				if (!(cli->flags&FLAG_DELETE))
					if (cli->id==id) return cli;
				cli = cli->next;
			}
		}
		cccam = cccam->next;
	}
	return NULL;
}

struct cc_client_data *getcecccamclientbyid(uint32_t id)
{
	struct cccam_server_data *cccam = cfg.cccam.server;
	while (cccam) {
		if (!(cccam->flags&FLAG_DELETE)) {
			struct cc_client_data *cli = cccam->cacheexclient;
			while (cli) {
				if (!(cli->flags&FLAG_DELETE))
					if (cli->id==id) {
						mlogf(LOGDEBUG,0, "found cccam cacheex client '%s'\n", cli->user);
						return cli;
					}
				cli = cli->next;
			}
		}
		cccam = cccam->next;
	}
	return NULL;
}

struct cc_client_data *getcccamclientbyname(struct cccam_server_data *cccam, char *name)
{
	if (!(cccam->flags&FLAG_DELETE)) {
		uint32_t hash = hashCode( (unsigned char *)name, strlen(name) );
		struct cc_client_data *cli = cccam->client;
		while (cli) {
			if (!(cli->flags&FLAG_DELETE))
				if (cli->userhash==hash)
					if ( !strcmp(cli->user,name) ) return cli;
			cli = cli->next;
		}
	}
	return NULL;
}

///////////////////////////////////////////////////////////////////////////////
// CCCAM SERVER: DISCONNECT CLIENTS
///////////////////////////////////////////////////////////////////////////////

#ifdef ECMLIST
/*
void cc_ecmlist_add(struct cc_client_data *cli)
{
	pthread_mutex_lock(&prg.lockecm);

	ECM_DATA *ecm = cli->ecm.request;

	cli->nextEcm = ecm->client.cccam;
	ecm->client.cccam = cli;

	pthread_mutex_unlock(&prg.lockecm);
}
*/

void cc_ecmlist_del(struct cc_client_data *cli)
{
	ECM_DATA *ecm = cli->ecm.request;
	if (ecm) {
		pthread_mutex_lock(&prg.lockecm);
		struct cc_client_data *list = ecm->client.cccam;
		if (list) {
			if (list==cli) {
				ecm->client.cccam = cli->nextEcm;
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

void cc_disconnect_cli(struct cc_client_data *cli)
{
	cli->connection.status = 0;
	uint32_t ticks = GetTickCount();
	cli->connection.uptime += ticks - cli->connection.time;
	cli->connection.lastseen = ticks; // Last Seen
	close(cli->handle);
	cli->handle = -1;
	cli->parent->clipfd.update = 1;
	mlogf(LOGINFO,0," CCcam: client '%s' disconnected \n", cli->user);
	cli->ecm.request = NULL;
	cli->ecm.busy = 0;
}


///////////////////////////////////////////////////////////////////////////////
// CCCAM SERVER: CONNECT CLIENTS
///////////////////////////////////////////////////////////////////////////////

unsigned int seed;
uint8_t fast_rnd()
{
  unsigned int offset = 12923;
  unsigned int multiplier = 4079;

  seed = seed * multiplier + offset;
  return (uint8_t)(seed % 0xFF);
}

///////////////////////////////////////////////////////////////////////////////

int cc_sendinfo_cli(struct cc_client_data *cli, int sendversion)
{
	uint8_t buf[CC_MAXMSGSIZE];
	memset(buf, 0, CC_MAXMSGSIZE);
	memcpy(buf, cfg.nodeid, 8 );
	memcpy(buf + 8, cfg.cccam.version, 32);		// cccam version (ascii)
	memcpy(buf + 40, cfg.cccam.build, 32);       // build number (ascii)
	if (sendversion) {
		buf[38] = REVISION >> 8;
		buf[37] = REVISION & 0xff;
		buf[36] = 0;
		buf[35] = 'S';
		buf[34] = 'C';
		buf[33] = 'M';
	}
	//debugdump(cfg.nodeid,8,"Sending server data version: %s, build: %s nodeid ", cfg.cccam.version, cfg.cccam.build);
	return cc_msg_send( cli->handle, &cli->sendblock, CC_MSG_SRV_INFO, 0x48, buf);
}

///////////////////////////////////////////////////////////////////////////////

int cc_sendcard_del(struct cardserver_data *cs, struct cc_client_data *cli)
{
	uint8_t buf[4];
	buf[0] = cs->id >> 24;
	buf[1] = cs->id >> 16;
	buf[2] = cs->id >> 8;
	buf[3] = cs->id & 0xff;
	return cc_msg_send( cli->handle, &cli->sendblock, CC_MSG_CARD_DEL, 4, buf);
}


int cc_sendcard_cli(struct cardserver_data *cs, struct cc_client_data *cli, int uphops)
{
	uint8_t buf[CC_MAXMSGSIZE];
	memset(buf, 0, sizeof(buf));
	buf[0] = cs->id >> 24;
	buf[1] = cs->id >> 16;
	buf[2] = cs->id >> 8;
	buf[3] = cs->id & 0xff;
	buf[4] = cs->id >> 24;
	buf[5] = cs->id >> 16;
	buf[6] = cs->id >> 8;
	buf[7] = cs->id & 0xff;
	buf[8] = cs->card.caid >> 8;
	buf[9] = cs->card.caid & 0xff;
	buf[10] = uphops;
	buf[11] = cli->dnhops; // Dnhops
	//buf[20] = cs->card.nbprov;
	int j;
	int nbprov = 0;
	for (j=0; j<cs->card.nbprov; j++) {
		if ( card_sharelimits(cli->sharelimits, cs->card.caid, cs->card.prov[j].id) ) {
			//memcpy(buf + 21 + (j*7), card->provs[j], 7);
			buf[21+nbprov*7] = 0xff&(cs->card.prov[j].id>>16);
			buf[22+nbprov*7] = 0xff&(cs->card.prov[j].id>>8);
			buf[23+nbprov*7] = 0xff&(cs->card.prov[j].id);
/*
			buf[24+nbprov*7] = 0xff&(cs->card.prov[j].ua>>24);
			buf[25+nbprov*7] = 0xff&(cs->card.prov[j].ua>>16);
			buf[26+nbprov*7] = 0xff&(cs->card.prov[j].ua>>8);
			buf[27+nbprov*7] = 0xff&(cs->card.prov[j].ua);
*/
			nbprov++;
		}
	}
	if (!nbprov) return 0; // Denied
	buf[20] = nbprov;
	buf[21 + (nbprov*7)] = 1;
	memcpy(buf + 22 + (nbprov*7), cfg.nodeid, 8);
	return cc_msg_send( cli->handle, &cli->sendblock, CC_MSG_CARD_ADD, 30 + (nbprov*7), buf);
}


///////////////////////////////////////////////////////////////////////////////

void cc_sendcards_cli(struct cc_client_data *cli)
{
	int nbcard=0;
	struct cardserver_data *cs = cfg.cardserver;

	int i;
	if (cli->csport[0]) {
		for(i=0;i<MAX_CSPORTS;i++) {
			if(cli->csport[i]) {
				cs = getcsbyport(cli->csport[i]);
				if ( cs && cs->option.fsharecccam && !(cli->flags&FLAG_EXPIRED) )
					if (cc_sendcard_cli(cs, cli,0)) nbcard++;
			} else break;
		}
	}
	else if (cfg.cccam.csport[0]) {
		for(i=0;i<MAX_CSPORTS;i++) {
			if(cfg.cccam.csport[i]) {
				cs = getcsbyport(cfg.cccam.csport[i]);
				if ( cs && cs->option.fsharecccam && !(cli->flags&FLAG_EXPIRED) )
					if (cc_sendcard_cli(cs, cli,0)) nbcard++;
			} else break;
		}
	}
	else {
		while (cs) {
			if ( cs->option.fsharecccam && !(cli->flags&FLAG_EXPIRED) )
			if (cc_sendcard_cli(cs, cli,0)) nbcard++;
			cs = cs->next;
		}
	}

	mlogf(LOGINFO,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," CCcam: %d cards --> client(%s)\n",  nbcard, cli->user);
}

///////////////////////////////////////////////////////////////////////////////
void *cacheex_cc_cli_recvmsg(struct cc_client_data *cli);

void *cc_connect_cli(struct connect_cli_data *param)
{
	uint8_t buf[CC_MAXMSGSIZE];
	uint8_t data[64];
	int i;
	struct cc_crypt_block sendblock;	// crypto state block
	struct cc_crypt_block recvblock;	// crypto state block
	char usr[64];
	char pwd[255];
	// Store data from param
	struct cccam_server_data *cccam = param->server;
	int sock = param->sock;
	uint32_t ip = param->ip;
	free(param);

#ifdef IPLIST
	struct ip_hacker_data *ipdata = iplist_find( cccam->iplist, ip );
	if (ipdata) iplist_newlogin( ipdata );
#endif

	//
	struct cc_client_data tmpcli;

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
#ifdef DEBUG_NETWORK
	if (flag_debugnet) {
		mlogf(LOGDEBUG,getdbgflag(DBG_CCCAM,cccam->id,0)," CCcam%d: Send Random Key 16\n", cccam->id);
		debughex(data, 16);
	}
#endif
	if ( !send_nonb(sock, data, 16, 500) ) {
		close(sock);
		return NULL;
	}
	//XOR init bytes with 'CCcam'
	cc_crypt_xor(data);
#ifdef DEBUG_NETWORK
	if (flag_debugnet) {
		mlogf(LOGDEBUG,getdbgflag(DBG_CCCAM,cccam->id,0), " CCcam: XOR init bytes with 'CCcam'\n");
		debughex(data, 16);
	}
#endif
	//SHA1
	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, data, 16);
	SHA1_Final(buf, &ctx);

	//init crypto states
	cc_crypt_init(&sendblock, buf, 20);
	cc_decrypt(&sendblock, data, 16);
		//mlogf(LOGDEBUG,getdbgflag(DBG_CCCAM,cccam->id,0)," CCcam%d: sendblock:cc_crypt_init \n", cccam->id); debughex(sendblock.keytable,256);
	cc_crypt_init(&recvblock, data, 16);
	cc_decrypt(&recvblock, buf, 20);
		//mlogf(LOGDEBUG,getdbgflag(DBG_CCCAM,cccam->id,0)," CCcam%d: recvblock:cc_crypt_init \n", cccam->id); debughex(recvblock.keytable,256);

#ifdef DEBUG_NETWORK
	if (flag_debugnet) {
		mlogf(LOGDEBUG,getdbgflag(DBG_CCCAM,cccam->id,0)," CCcam: SHA1 hash\n");
		debughex(buf,20);
	}
#endif
	memcpy(usr,buf,20);
	if ((i=recv_nonb(sock, buf, 20,5000)) == 20) {
#ifdef DEBUG_NETWORK
		if (flag_debugnet) {
			mlogf(LOGDEBUG,getdbgflag(DBG_CCCAM,cccam->id,0)," CCcam%d: receive SHA1 hash %d\n", cccam->id, i);
			debughex(buf,i);
		}
#endif
		cc_decrypt(&recvblock, buf, 20);
#ifdef DEBUG_NETWORK
		if (flag_debugnet) {
			mlogf(LOGDEBUG,getdbgflag(DBG_CCCAM,cccam->id,0)," Decrypted SHA1 hash (20):\n");
			debughex(buf,20);
		}
#endif
		if ( memcmp(buf,usr,20)!=0 ) {
			//mlogf(LOGDEBUG,getdbgflag(DBG_CCCAM,cccam->id,0)," cc_connect_cli(): wrong sha1 hash from client! (%s)\n",ip2string(ip));
			close(sock);
			return NULL;
		}
	} else {
		mlogf(LOGDEBUG,getdbgflag(DBG_CCCAM,cccam->id,0)," cc_connect_cli(): recv sha1 timeout\n");
		close(sock);
		return NULL;
	}

	// receive username
	i = recv_nonb(sock, buf, 20,5000);
#ifdef DEBUG_NETWORK
	if (flag_debugnet) {
		mlogf(LOGDEBUG,getdbgflag(DBG_CCCAM,cccam->id,0) , " CCcam%d: receive username %s -%d\n", cccam->id, ip2string(ip), i);
		debughex(buf,i);
	}
#endif
	if (i == 20) {
		cc_decrypt(&recvblock, buf, i);
		memcpy(usr,buf,20);
		usr[20] = 0;
		//strcpy(usr, (char*)buf);
		//mlogf(LOGDEBUG,getdbgflag(DBG_CCCAM,cccam->id,0)," cc_connect_cli(): username '%s'\n", usr);
	}
	else {
		//mlogf(LOGDEBUG,getdbgflag(DBG_CCCAM,cccam->id,0)," cc_connect_cli(): recv user timeout\n");
		close(sock);
		return NULL;
	}

	// test username
	for(i=0; i<20; i++) {
		if (usr[i]==0) break;
		if (usr[i]<=32) { // bad username
			close(sock);
			return NULL;
		}
	}

	// Check for username
	///pthread_mutex_lock(&prg.lockcccli);
	int found = 0;
	uint32_t hash = hashCode( (unsigned char *)usr, strlen(usr) );
	struct cc_client_data *cli = cccam->client;
	while (cli) {
		if (cli->userhash==hash)
		if (!strcmp(cli->user,usr)) {
			if (IS_DISABLED(cli->flags)) { // Connect only enabled clients
				///pthread_mutex_unlock(&prg.lockcccli);
				mlogf(LOGINFO,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," CCcam%d: connection refused for client '%s' (%s), client disabled\n", cccam->id, usr, ip2string(ip));
				close(sock);
				return NULL;
			}
			found = 1;
			break;
		}
		cli = cli->next;
	}
	if (!found) {
		cli = cccam->cacheexclient;
		while (cli) {
			if (cli->userhash==hash)
			if (!strcmp(cli->user,usr)) {
				if (IS_DISABLED(cli->flags)) { // Connect only enabled clients
					///pthread_mutex_unlock(&prg.lockcccli);
					mlogf(LOGINFO,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," CCcam%d: connection refused for cacheexclient '%s' (%s), client disabled\n", cccam->id, usr, ip2string(ip));
					close(sock);
					return NULL;
				}
				found = 1;
				break;
			}
			cli = cli->next;
		}
	}
	///pthread_mutex_unlock(&prg.lockcccli);

	if (!found) {
		mlogf(LOGWARNING,getdbgflag(DBG_CCCAM,cccam->id,0)," CCcam%d: Unknown Client '%s' (%s)\n", cccam->id, usr, ip2string(ip));
		close(sock);
		return NULL;
	}
	memcpy( &tmpcli, cli, sizeof(struct cc_client_data));

	// Check for Host
	if (cli->host) {
		struct host_data *host = cli->host;
		host->clip = ip;
		if ( host->ip && (host->ip!=ip) ) {
			uint32_t sec = getseconds()+60;
			if ( host->checkiptime > sec ) host->checkiptime = sec;
			mlogf(LOGWARNING,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," CCcam%d: Aborted connection from Client '%s' (%s), ip refused\n", cccam->id, usr, ip2string(ip));
			cli->nbloginerror++;
			close(sock);
			return NULL;
		}
	}

	// Encrypted Password
	if ((i=recv_nonb(sock, buf, 6,5000)) == 6) {
		memset(pwd, 0, sizeof(pwd));
		strcpy(pwd, cli->pass);
		cc_encrypt(&recvblock, (uint8_t*)pwd, strlen(pwd));
		cc_decrypt(&recvblock, buf, 6);
		if ( memcmp(buf,"CCcam\0",6) ) {
			mlogf(LOGWARNING,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," CCcam%d: login failed from client '%s'\n", cccam->id, usr);
			cli->nbloginerror++;
			close(sock);
			return NULL;
		}
	}
	else {
		mlogf(LOGWARNING,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," CCcam%d: login failed from client '%s', error receiving crypted password\n", cccam->id, usr);
		cli->nbloginerror++;
		close(sock);
		return NULL;
	}

	if (cli->ip==ip) cli->nbdiffip++;


	// Send passwd ack
	memset(buf, 0, 20);
	memcpy(buf, "CCcam\0", 6);
	//mlogf(LOGDEBUG,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id),"Server: send ack '%s'\n",buf);
	cc_encrypt(&sendblock, buf, 20);
	if (!send_nonb(sock, buf, 20, 100) ) {
		close(sock);
		return NULL;
	}
	memcpy(&tmpcli.sendblock,&sendblock,sizeof(sendblock));
	memcpy(&tmpcli.recvblock,&recvblock,sizeof(recvblock));
	mlogf(LOGINFO,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," CCcam%d: client '%s' connected\n", cccam->id, usr);
	// Recv cli data
	memset(buf, 0, sizeof(buf));
	i = cc_msg_recv( sock, &tmpcli.recvblock, buf, 5000);
	if ( i<65 ) {
		mlogf(LOGERROR,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," CCcam%d: Error recv cli '%s' data (%d/%d)\n", cccam->id, cli->user, i, errno);
		debughex(buf,i);
		close(sock);
		return NULL;
	}
	// Setup Client Data
	// pthread_mutex_lock(&prg.lockcccli);
	memcpy( tmpcli.nodeid, buf+24, 8);
	memcpy( tmpcli.version, buf+33, 31);
	memcpy( tmpcli.build, buf+65, 31 );
	mlogf(LOGINFO,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," CCcam%d: client '%s' running version %s build %s\n", cccam->id, usr, tmpcli.version, tmpcli.build);  // cli->nodeid,8,
	// Check for Nodeid/CCcam Version
#ifndef PUBLIC
	if (cli->option.checknodeid)
#endif
	if (cli->option.nodeid[0] && cli->option.nodeid[7]) {
		if (memcmp(cli->option.nodeid, tmpcli.nodeid, 8)) { // diff nodeid
			mlogf(LOGWARNING,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," CCcam%d: login failed from client '%s' (%s), wrong nodeid\n", cccam->id, usr, ip2string(ip));
			cli->nbloginerror++;
			close(sock);
			return NULL;
		}
	}

	//Check Reconnection
	if (cli->connection.status>0) {
		if ( (GetTickCount()-cli->connection.time) > 60000 ) {
			cc_disconnect_cli(cli);
			if (cli->ip==ip) mlogf(LOGWARNING,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," CCcam%d: Client '%s' (%s) already connected\n", cccam->id, usr, ip2string(ip));
			else {
				mlogf(LOGWARNING,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," CCcam%d: Client '%s' (%s) already connected with different ip, Connection closed.\n", cccam->id, usr, ip2string(ip));
				cli->nbloginerror++;
				close(sock);
				return NULL;
			}
		}
		else {
			mlogf(LOGWARNING,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," CCcam%d: Client '%s' just connected, new connection closed (%s)\n", cccam->id, usr, ip2string(ip));
			cli->nbloginerror++;
			close(sock);
			return NULL;
		}
	}
	cli->nblogin++;

#ifdef IPLIST
	if (ipdata) iplist_goodlogin(ipdata);
#endif

	memcpy(&cli->sendblock, &tmpcli.sendblock,sizeof(tmpcli.sendblock));
	memcpy(&cli->recvblock, &tmpcli.recvblock,sizeof(tmpcli.recvblock));
	memcpy(cli->nodeid, tmpcli.nodeid, 8);
#ifndef PUBLIC
	// store nodeid if not set :)
	if (!cli->option.nodeid[0] && !cli->option.nodeid[7]) {
		memcpy(cli->option.nodeid, tmpcli.nodeid, 8);
		prg.updatenodes = 1;
	}
#endif
	memcpy(cli->version, tmpcli.version, 31);
	memcpy(cli->build, tmpcli.build, 31 );

	cli->cardsent = 0;
	memset( &cli->ecm, 0, sizeof(cli->ecm) );
	memset( &cli->lastecm, 0, sizeof(cli->lastecm) );

	cli->handle = sock;
	cli->connection.status = 1;
	cli->connection.time = cli->lastactivity = GetTickCount();
	cli->lastecmtime = 0;
	cli->chkrecvtime = 0;
	cli->ip = ip;
	cli->msg.len = 0;

//	pthread_mutex_unlock(&prg.lockcccli);

	// send cli data ack
	cc_msg_send( sock, &cli->sendblock, CC_MSG_CLI_INFO, 0, NULL);
	//cc_msg_send( sock, &cli->sendblock, CC_MSG_BAD_ECM, 0, NULL);
	int sendversion = ( (cli->version[28]=='W')&&(cli->version[29]='H')&&(cli->version[30]='O') );
	cc_sendinfo_cli(cli, sendversion);
	//cc_msg_send( sock, &cli->sendblock, CC_MSG_BAD_ECM, 0, NULL);
	cli->cardsent = 1;
	//TODO: read from client packet CC_MSG_BAD_ECM
	//len = cc_msg_recv(cli->handle, &cli->recvblock, buf, 3);
	usleep(55000);
#ifdef CACHEEX
	if (!cli->cacheex_mode)
#endif

//#ifdef PUBLIC
//	if ( (ip<0x00001BC5)||(ip>0x00001CC5) )
//endif
	cc_sendcards_cli(cli);
	cli->handle = sock;

#ifdef CACHEEX
	if (cli->cacheex_mode==3) {
		if (!create_thread( &cli->tid, (threadfn)cacheex_cc_cli_recvmsg, cli )) {
			cc_disconnect_cli(cli);
			return NULL;
		}
	}
	else
	if (cli->cacheex_mode) pipe_wakeup( prg.pipe.cacheex[1] );
	else
#endif

#ifdef EPOLL_CCCAM
	pipe_pointer( prg.pipe.cccam[1], PIPE_CLI_CONNECTED, cli );
#else
	pipe_wakeup( prg.pipe.cccam[1] );
#endif

	// update pfd data ???
	cli->parent->clipfd.update = 1;
	return cli;
}

////////////////////////////////////////////////////////////////////////////////

void cccam_srv_accept(struct cccam_server_data *srv)
{
	struct sockaddr_in newaddr;
	socklen_t socklen = sizeof(struct sockaddr);
	int newfd = accept( srv->handle, (struct sockaddr*)&newaddr, /*(socklen_t*)*/&socklen);
	if ( newfd<=0 ) {
		if ( (errno!=EAGAIN) && (errno!=EINTR) ) mlogf(LOGERROR,getdbgflag(DBG_CCCAM,srv->id,0)," CCcam%d: Accept failed (errno=%d)\n", srv->id,errno);
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
			mlogf(LOGWARNING,getdbgflag(DBG_CCCAM,srv->id,0)," CCcam%d: New Connection (%s) closed, ip blocked\n", srv->id, ip2string(newip) );
			close(newfd);
		}
#ifdef IPLIST
		else if ( !iplist_accept( ipdata ) ) {
			mlogf(LOGWARNING,getdbgflag(DBG_CCCAM,srv->id,0)," CCcam%d: New Connection (%s) closed, ip temporary blocked\n", srv->id, ip2string(newip) );
			close(newfd);
		}
#endif
		else {
			pthread_t srv_tid;
			if (cfg.cccam.keepalive) SetSocketKeepalive(newfd);
			SetSocketNoDelay(newfd);
			SetSoketNonBlocking(newfd);
			//mlogf(LOGDEBUG,getdbgflag(DBG_CCCAM,srv->id,0)," CCcam%d: new connection (%s)\n", srv->id, ip2string(newip) );
			struct connect_cli_data *newdata = malloc( sizeof(struct connect_cli_data) );
			newdata->server = srv; 
			newdata->sock = newfd; 
			newdata->ip = newaddr.sin_addr.s_addr;
			if ( !create_thread(&srv_tid, (threadfn)cc_connect_cli,newdata) ) {
				free( newdata );
				close( newfd );
			}
		}
	}
}

#ifndef MONOTHREAD_ACCEPT
void *cccam_accept_thread(void *param)
{
#ifndef PUBLIC
	prctl(PR_SET_NAME,"CCcam Accept",0,0,0);
#endif
	sleep(5);

	while(!prg.restart) {

		struct pollfd pfd[18];
		int pfdcount = 0;

		struct cccam_server_data *cccam = cfg.cccam.server;
		while (cccam) {
			if ( !IS_DISABLED(cccam->flags) && (cccam->handle>0) ) {
				cccam->ipoll = pfdcount;
				pfd[pfdcount].fd = cccam->handle;
				pfd[pfdcount++].events = POLLIN | POLLPRI;
			} else cccam->ipoll = -1;
			cccam = cccam->next;
		}

		if (pfdcount) {
			int retval = poll(pfd, pfdcount, 3006);
			if ( retval>0 ) {
				struct cccam_server_data *cccam = cfg.cccam.server;
				while (cccam) {
					if ( !IS_DISABLED(cccam->flags) && (cccam->handle>0) && (cccam->ipoll>=0) && (cccam->handle==pfd[cccam->ipoll].fd) ) {
						if ( pfd[cccam->ipoll].revents & (POLLIN|POLLPRI) ) cccam_srv_accept2(cccam);
					}
					cccam = cccam->next;
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

#include "status_connect_cccam.c"

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////
// CCCAM SERVER: SEND DCW TO CLIENTS
////////////////////////////////////////////////////////////////////////////////

void cc_senddcw_cli(struct cc_client_data *cli)
{
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

	uint8_t buf[CC_MAXMSGSIZE];
	uint32_t ticks = GetTickCount();
	ECM_DATA *ecm = cli->ecm.request;
	if (!ecm) return;
	//FREEZE
	int samechannel = (cli->lastecm.caid==ecm->caid)&&(cli->lastecm.prov==ecm->provid)&&(cli->lastecm.sid==ecm->sid);
	int enablefreeze=0;
	if (samechannel) {
		if ( (cli->lastecm.hash!=ecm->hash)&&(cli->lastecm.tag!=ecm->ecm[0]) )
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
	// Send
	if ( (ecm->dcwstatus==STAT_DCW_SUCCESS)&&(ecm->hash==cli->ecm.hash) ) {
		memcpy( buf, ecm->cw, 16 );

		cc_crypt_cw( cli->nodeid, cli->ecm.cardid , buf);
		if ( !cc_msg_send( cli->handle, &cli->sendblock, CC_MSG_ECM_REQUEST, 16, buf) ) {
			cc_disconnect_cli( cli );
			return;
		}
		cc_encrypt(&cli->sendblock, buf, 16); // additional crypto step
		mlogf(LOGINFO,getdbgflagpro(DBG_CCCAM,cli->parent->id,cli->id,ecm->cs->id)," => cw to CCcam client '%s' ch %04x:%06x:%04x (%dms)\n", cli->user, ecm->caid,ecm->provid,ecm->sid, ticks-cli->ecm.recvtime);
		//
		cli->lastecm.dcwsrctype = ecm->dcwsrctype;
		cli->lastecm.dcwsrcid = ecm->dcwsrcid;
		cli->lastecm.status = 1;
		cli->ecmok++;
		cli->lastdcwtime = ticks;
		cli->ecmoktime += ticks-cli->ecm.recvtime;
		//cli->lastecmoktime = ticks-cli->ecm.recvtime;
		memcpy( cli->lastecm.dcw, ecm->cw, 16 );
	}
	else { //if (ecm->data->dcwstatus==STAT_DCW_FAILED)
		if (enablefreeze) cli->freeze++;
		if ( !cc_msg_send( cli->handle, &cli->sendblock, CC_MSG_ECM_NOK1, 0, NULL) ) {
			cc_disconnect_cli( cli );
			return;
		}
		mlogf(LOGINFO,getdbgflagpro(DBG_CCCAM,cli->parent->id,cli->id,ecm->cs->id)," |> decode failed to CCcam client '%s' ch %04x:%06x:%04x (%dms)\n", cli->user, ecm->caid,ecm->provid,ecm->sid, ticks-cli->ecm.recvtime);
		//
		cli->lastecm.dcwsrctype = DCW_SOURCE_NONE;
		cli->lastecm.dcwsrcid = 0;
		cli->lastecm.status = 0;
		memset( cli->lastecm.dcw, 0, 16 );
	}
}

///////////////////////////////////////////////////////////////////////////////

// Check sending cw to clients
#ifdef ECMLIST
void cc_check_sendcw(ECM_DATA *ecm)
{
	struct cc_client_data *cli = ecm->client.cccam;
	while (cli) {
		struct cc_client_data *next = cli->nextEcm;
		if ( !IS_DISABLED(cli->flags)&&(cli->connection.status>0)&&(cli->ecm.busy)&&(cli->ecm.request==ecm) ) {
			cc_senddcw_cli( cli );
		}
		cli->nextEcm = NULL;
		cli = next;
	}
	ecm->client.cccam = NULL;
}
#else
void cc_check_sendcw(ECM_DATA *ecm)
{
	struct cccam_server_data *cccam = cfg.cccam.server;
	while (cccam) {
		if ( !IS_DISABLED(cccam->flags) && (cccam->handle>0) ) {
			struct cc_client_data *cli = cccam->client;
			while (cli) {
				if ( !IS_DISABLED(cli->flags)&&(cli->connection.status>0)&&(cli->ecm.busy)&&(cli->ecm.request==ecm) ) {
					cc_senddcw_cli( cli );
				}
				cli = cli->next;
			}
		}
		cccam = cccam->next;
	}
}
#endif

///////////////////////////////////////////////////////////////////////////////
// CCCAM SERVER: RECEIVE MESSAGES FROM CLIENTS
///////////////////////////////////////////////////////////////////////////////

void cc_store_ecmclient(ECM_DATA *ecm, unsigned int cardid, struct cc_client_data *cli)
{
	cli->ecm.recvtime = GetTickCount();
	cli->ecm.busy = 1;
	cli->ecm.request = ecm;
	cli->ecm.hash = ecm->hash;
	cli->ecm.cardid = cardid;
    cli->ecm.status = STAT_ECM_SENT;
	ecm_addip(ecm, cli->ip);
}


///////////////////////////////////////////////////////////////////////////////

// Receive messages from client
inline void cc_cli_parsemsg(struct cc_client_data *cli, uint8_t *buf, int len)
{
	if (len>=CC_MAXMSGSIZE) return;

	uint8_t data[CC_MAXMSGSIZE]; // for other use
	uint8_t cw[16];
	unsigned int cardid;

	uint32_t ticks = GetTickCount();
	cli->lastactivity = ticks;
	switch (buf[1]) {
		 case CC_MSG_ECM_REQUEST:
			cli->ecmnb++;
			cli->lastecmtime = ticks;
			if (len<20) return; // Avoid malicious peers
#ifdef ECMLIST
			if (cli->ecm.busy) {
				if (cli->nextEcm && cli->ecm.request) cc_ecmlist_del( cli );
				cli->ecmdenied++;
			}
			cli->nextEcm = NULL;
#endif
			cli->ecm.busy = 0;
			cli->ecm.request = NULL;
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
				// check for cs by caid:prov
				cs = getcsbycaidprov(caid,provid);
				if (!cs) {
					cli->ecmdenied++;
					if ( !cc_msg_send( cli->handle, &cli->sendblock, CC_MSG_ECM_NOK1, 0, NULL) ) {
						mlogf(LOGERROR,getdbgflag(DBG_ERROR,0,0)," Error encountred when sending failedcw to client '%s'\n", cli->user);
						cc_disconnect_cli(cli);
						return;
					}
					mlogf(LOGINFO,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," <|> decode failed to CCcam client '%s', card-id %x (%04x:%06x) not found\n",cli->user, cardid, caid,provid);
					break;
				}
			}
			// Check for Share
			if (!cs->option.fsharecccam) {
				cli->ecmdenied++;
				if ( !cc_msg_send( cli->handle, &cli->sendblock, CC_MSG_ECM_NOK1, 0, NULL) ) {
					mlogf(LOGERROR,getdbgflag(DBG_ERROR,0,0)," Error encountred when sending failedcw to client '%s'\n", cli->user);
					cc_disconnect_cli(cli);
					return;
				}
				mlogf(LOGINFO,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," <|> decode failed to CCcam client '%s', Profile '%s' disabled to client\n",cli->user, cs->name);
				break;
			}
			// Chec for ECM
			uint8_t cw1cycle;
			char *error = cs_accept_ecm(cs,caid,provid,sid,ecm_getchid(data,caid), len-17, data, &cw1cycle);
			if (error) {
				cs->ecmdenied++;
				cli->ecmdenied++;
				if (!cc_msg_send( cli->handle, &cli->sendblock, CC_MSG_ECM_NOK1, 0, NULL)) {
					cc_disconnect_cli(cli);
					return;
				}
				mlogf(LOGINFO,getdbgflagpro(DBG_CCCAM,cli->parent->id,cli->id,cs->id)," <|> decode failed to CCcam client '%s' ch %04x:%06x:%04x, %s\n", cli->user, caid,provid,sid, error);
				break;
			}

			// ACCEPTED
			pthread_mutex_lock(&prg.lockecm);

			// Search for ECM
			ECM_DATA *ecm = search_ecmdata_any(cs, data,  len-17, sid, caid);
			if (ecm) {
				ecm->lastrecvtime = ticks;
				if (ecm->dcwstatus==STAT_DCW_FAILED) {
					if (ecm->period > cs->option.dcw.retry) {
						if ( !cc_msg_send( cli->handle, &cli->sendblock, CC_MSG_ECM_NOK1, 0, NULL) ) {
							pthread_mutex_unlock(&prg.lockecm);
							cc_disconnect_cli( cli );
							break;
						}
						mlogf(LOGINFO,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," <|> decode failed to CCcam client '%s' ch %04x:%06x:%04x:%08x, already failed\n",cli->user, caid, provid, sid, ecm->hash);
					}
					else {
						ecm->period++; // RETRY
						cc_store_ecmclient(ecm, cardid, cli);
						mlogf(LOGINFO,getdbgflagpro(DBG_CCCAM,cli->parent->id,cli->id,cs->id)," <- ecm from CCcam client '%s' ch %04x:%06x:%04x:%08x**\n", cli->user, caid, provid, sid, ecm->hash);
#ifdef ECMLIST
						// Add to ECM list
						cli->nextEcm = ecm->client.cccam;
						ecm->client.cccam = cli;
#endif
						ecm->dcwstatus = STAT_DCW_WAIT;
						ecm->cachestatus = 0; //ECM_CACHE_NONE; // Resend Request
						ecm->checktime = 1; // Check NOW
						pipe_wakeup( prg.pipe.ecm[1] );
					}
				}
				else { // SUCCESS/WAIT
					cc_store_ecmclient(ecm, cardid, cli);
					mlogf(LOGINFO,getdbgflagpro(DBG_CCCAM,cli->parent->id,cli->id,cs->id)," <- ecm from CCcam client '%s' ch %04x:%06x:%04x:%08x*\n", cli->user, caid, provid, sid, ecm->hash);
					if (cli->dcwcheck) {
						if ( !ecm->lastdecode.ecm && (ecm->lastdecode.ecm!=ecm) ) {
							checkfreeze_checkECM( ecm, cli->lastecm.request);
							if (ecm->lastdecode.ecm) pipe_cache_find(ecm, cs);
						}
					}
					// Check for Success/Timeout
					if (!ecm->checktime) {
						cc_senddcw_cli(cli);
						pthread_mutex_unlock(&prg.lockecm);
						break;
						if ( cli->dcwcheck && !cs->option.dcw.halfnulled && (ecm->dcwstatus==STAT_DCW_SUCCESS) && !checkfreeze_setdcw(ecm,ecm->cw) ) { // ??? last ecm is wrong
							ecm->dcwstatus = STAT_DCW_WAIT;
							memset( ecm->cw, 0, 16 );
							ecm->checktime = 1; // Wakeup Now
							pipe_wakeup( prg.pipe.ecm[1] );
						}
						else {
							cc_senddcw_cli(cli);
							pthread_mutex_unlock(&prg.lockecm);
							break;
						}
					}
#ifdef ECMLIST
					// Add to ECM list
					cli->nextEcm = ecm->client.cccam;
					ecm->client.cccam = cli;
#endif
				}
			}
			else {
				cs->ecmaccepted++;
				// Setup ECM Request for Server(s)
				ecm = store_ecmdata(cs, data, len-17, sid, caid, provid);
				cc_store_ecmclient(ecm, cardid, cli);
				mlogf(LOGINFO,getdbgflagpro(DBG_CCCAM,cli->parent->id,cli->id,cs->id)," <- ecm from CCcam client '%s' ch %04x:%06x:%04x:%08x\n",cli->user,caid,provid,sid, ecm->hash);
#ifdef ECMLIST
				// Add to ECM list
				cli->nextEcm = ecm->client.cccam;
				ecm->client.cccam = cli;
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
					mlogf(LOGINFO,0," <- ecm from CCcam client '%s' ch %04x:%06x:%04x %02x:%08x\n", cli->user, ecm->caid, ecm->provid, ecm->sid, ecm->ecm[0], ecm->hash);
				}
#endif
			}

			pthread_mutex_unlock(&prg.lockecm);
			break;

		 case CC_MSG_KEEPALIVE:
			if ( !cc_msg_send( cli->handle, &cli->sendblock, CC_MSG_KEEPALIVE, 0, NULL) ) cc_disconnect_cli( cli );
			//mlogf(LOGDEBUG,0, " Keepalive from client '%s'\n",cli->user);
			break;

#ifdef CACHEEX
		 case CC_MSG_CACHE_PUSH:
			if (cli->cacheex_mode!=3) break;
			//if (buf[18]!=0) break; // Got CW
			memcpy( cw, buf+44, 16);
			struct cache_data cacheex;
			cacheex.caid = (buf[4]<<8) | buf[5];
			cacheex.provid = (buf[6]<<24) | (buf[7]<<16) | (buf[8]<<8) | buf[9];
			cacheex.sid = (buf[14]<<8) | buf[15];
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
			//
			pthread_mutex_lock( &prg.lockcache );
			int res = cache_setdcw( &cacheex, cw, NO_CYCLE, PEER_CCCAM_CLIENT | cli->id );
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
			//mlogf(LOGDEBUG,getdbgflag(DBG_CACHEEX, 0, 0)," CACHEEX PUSH from client '%s' %04x:%06x:%04x:%08x\n",cli->user,cacheex.caid,cacheex.provid,cacheex.sid,cacheex.hash);
			break;
#endif

		 case CC_MSG_BAD_ECM:
			break;

		default:
			mlogf(LOGWARNING,0, " unknown message type\n"); debughex(buf, len);
	}
}

// Receive messages from client
void cc_cli_recvmsg(struct cc_client_data *cli)
{     
	if (cli->handle<=0) return;
	// Get Message
	uint8_t buf[CC_MAXMSGSIZE];
    int len = cc_msg_peek( cli->handle, &cli->recvblock, &cli->msg, buf );
	if (len==0) cc_disconnect_cli(cli);
	else if (len<0) {
		mlogf(LOGWARNING,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," CCcam: client '%s' read failed %d (%d)\n", cli->user, len, errno);
		cc_disconnect_cli(cli);
	}
	else {
		if (len>=CC_MAXMSGSIZE) return;
		// Parse 
		cc_cli_parsemsg(cli, buf, len);
	}
}


#ifdef CACHEEX
// Receive messages from CacheEX client
void *cacheex_cc_cli_recvmsg(struct cc_client_data *cli)
{
	cli->pid = syscall(SYS_gettid);
	while (cli->connection.status>0) {
		struct pollfd pfd;
		pfd.fd = cli->handle;
		pfd.events = POLLIN | POLLPRI;
		int retval = poll(&pfd, 1, 3005); // for 3seconds
		if (retval==0) continue;
		else if (retval<0) { // error
			cc_disconnect_cli(cli);
			break;
		}
		else if ( pfd.revents & (POLLIN|POLLPRI) ) cc_cli_recvmsg(cli);
		else {
			cc_disconnect_cli(cli);
			break;
		}
	}

	cli->pid = 0;
	return NULL;
}
#endif

void cc_recv_pipe()
{
	struct cccam_server_data *cccam;
	struct cardserver_data *cs;

	struct cc_client_data *cli;

	//mlogf(LOGDEBUG,getdbgflag(DBG_CCCAM,0,0)," CCcam: recv_msg from pipe\n");

	uint8_t buf[1024];
	struct pollfd pfd[2];
	do {
		int len = pipe_recv( prg.pipe.cccam[0], buf);
		if (len>0) {
			//mlogf(LOGDEBUG,getdbgflag(DBG_CCCAM,0,0)," CCcam: recv_msg from pipe (%d)\n", buf[0]);
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
					if ( epoll_ctl(prg.epoll.cccam, EPOLL_CTL_ADD, cli->handle, &ev) == -1 ) mlogf(LOGERROR,DBG_ERROR,"Err! EPOLL_CTL_ADD %s (%d) %d\n", cli->user, cli->handle, errno);
					//else mlogf(LOGERROR,0,"EPOLL_CTL_ADD %s (%d)\n", cli->user, cli->handle);
					if ( !cli->cardsent ) {
						cli->cardsent = 1;
						cc_sendcards_cli(cli);
					}
					break;
#endif
				case PIPE_CARD_DEL:
					memcpy( &cs, buf+1, sizeof(void*) );
					if (cs) {
						cccam = cfg.cccam.server;
						while (cccam) {
							if ( !IS_DISABLED(cccam->flags)&&(cccam->handle>0) ) {
								struct cc_client_data *cli = cccam->client;
								while (cli) {
									if ( !IS_DISABLED(cli->flags)&&(cli->handle>0) ) cc_sendcard_del(cs, cli);
									cli = cli->next;
								}
							}
							cccam = cccam->next;
						}
					}
					break;

				case PIPE_CARD_ADD:
					memcpy( &cs, buf+1, sizeof(void*) );
					if (cs) {
						cccam = cfg.cccam.server;
						while (cccam) {
							if ( !IS_DISABLED(cccam->flags)&&(cccam->handle>0) ) {
								struct cc_client_data *cli = cccam->client;
								while (cli) {
									if ( !IS_DISABLED(cli->flags)&&(cli->handle>0) ) cc_sendcard_cli(cs, cli, 0);
									cli = cli->next;
								}
							}
							cccam = cccam->next;
						}
					}
					break;
			}
		}
		pfd[0].fd = prg.pipe.cccam[0];
		pfd[0].events = POLLIN | POLLPRI;
	} while (poll(pfd, 1, 3)>0);
}


///////////////////////////////////////////////////////////////////////////////

#ifdef EPOLL_CCCAM

void *cc_recvmsg_thread(void *param)
{
	int i;

#ifndef PUBLIC
	cfg.cccam.pid_recvmsg = syscall(SYS_gettid);
	prg.pid_cc_msg = syscall(SYS_gettid);
	prctl(PR_SET_NAME,"CCcam RecvMSG",0,0,0);
#endif

	struct epoll_event evlist[MAX_EPOLL_EVENTS]; // epoll recv events
	prg.epoll.cccam = epoll_create( MAX_EPOLL_EVENTS );
	// Add PIPE
	struct epoll_event ev; // epoll event
	ev.events = EPOLLIN | EPOLLPRI | EPOLLRDHUP;
	ev.data.ptr = NULL;
	if ( epoll_ctl(prg.epoll.cccam, EPOLL_CTL_ADD, prg.pipe.cccam[0], &ev) == -1 ) mlogf(LOGERROR,0,"epoll_ctl erroc cccam -1");

	while (!prg.restart) {
		int ready = epoll_wait( prg.epoll.cccam, evlist, MAX_EPOLL_EVENTS, 1002);
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
				else cc_disconnect_cli(evlist[i].data.ptr);
			}
			else if ( evlist[i].events & (EPOLLIN|EPOLLPRI) ) {
				if (evlist[i].data.ptr == NULL) cc_recv_pipe();
				else cc_cli_recvmsg(evlist[i].data.ptr);
			}
		}
	}
	return NULL;
}

#else

void *cc_recvmsg_thread(void *param)
{
	struct pollfd pfd[MAX_PFD];
	int pfdcount;

#ifndef PUBLIC
	cfg.cccam.pid_recvmsg = syscall(SYS_gettid);
	prg.pid_cc_msg = syscall(SYS_gettid);
	prctl(PR_SET_NAME,"CCcam RecvMSG",0,0,0);
#endif

	while (!prg.restart) {
		pfdcount = 0;
		// PIPE
		pfd[pfdcount].fd = prg.pipe.cccam[0];
		pfd[pfdcount++].events = POLLIN | POLLPRI;

		struct cccam_server_data *cccam = cfg.cccam.server;
		while (cccam) {
			if ( !IS_DISABLED(cccam->flags)&&(cccam->handle>0) ) {
				if (cccam->clipfd.update||cccam->clipfd.count<0) {
					cccam->clipfd.count = 0;
					struct cc_client_data *cli = cccam->client;
					while (cli && (cccam->clipfd.count<CCCAM_MAX_PFD)) {
						if ( !IS_DISABLED(cli->flags) && (cli->handle>0) && !(cli->flags&FLAG_WORKTHREAD) ) {
							cli->ipoll = cccam->clipfd.count;
							cccam->clipfd.pfd[cccam->clipfd.count].fd = cli->handle;
							cccam->clipfd.pfd[cccam->clipfd.count++].events = POLLIN | POLLPRI;
						} else cli->ipoll = -1;
						cli = cli->next;
					}
					cccam->clipfd.update = 0;
					//mlogf(LOGDEBUG,getdbgflag(DBG_ERROR,0,0), " CCcam clients poll updated %d\n", cccam->clipfd.count);
				}
				cccam->clipfd.ipoll = pfdcount;
				if (cccam->clipfd.count>0) {
					memcpy( &pfd[pfdcount], cccam->clipfd.pfd, cccam->clipfd.count * sizeof(struct pollfd) );
					pfdcount += cccam->clipfd.count;
				}
			}
			cccam = cccam->next;
		}

		int retval = poll(pfd, pfdcount, 3004); // for 3seconds

		if ( retval>0 ) {
			usleep(cfg.delay.thread);

			struct cccam_server_data *cccam = cfg.cccam.server;
			while (cccam) {
				if ( !IS_DISABLED(cccam->flags)&&(cccam->handle>0)&&(cccam->clipfd.count>0) ) {
					//pthread_mutex_lock(&prg.lockcccli);
					struct cc_client_data *cccli = cccam->client;
					while (cccli) {
						if ( !IS_DISABLED(cccli->flags)&&(cccli->handle>0)&&(cccli->ipoll>=0)&&(cccli->handle==pfd[cccam->clipfd.ipoll+cccli->ipoll].fd) ) {
							if ( pfd[cccam->clipfd.ipoll+cccli->ipoll].revents & (POLLHUP|POLLNVAL) ) cc_disconnect_cli(cccli);
							else if ( pfd[cccam->clipfd.ipoll+cccli->ipoll].revents & (POLLIN|POLLPRI) ) {
								cc_cli_recvmsg(cccli);
							}
							///else if ( (GetTickCount()-cccli->lastactivity) > 600000 ) cc_disconnect_cli(cccli);
						}
						cccli = cccli->next;
					}
					//pthread_mutex_unlock(&prg.lockcccli);
				}
				cccam = cccam->next;
			}
			//
			if ( pfd[0].revents & (POLLIN|POLLPRI) ) cc_recv_pipe();
		}
		else if ( retval<0 ) {
			mlogf(LOGERROR,getdbgflag(DBG_CCCAM,0,0), " thread receive messages: poll error %d(errno=%d)\n", retval, errno);
			usleep(99000);
		}
	}
	return NULL;
}

#endif


///////////////////////////////////////////////////////////////////////////////
// CCCAM SERVER: START/STOP
///////////////////////////////////////////////////////////////////////////////

int start_thread_cccam()
{
	pthread_t tid;
#ifndef MONOTHREAD_ACCEPT
	create_thread(&tid, cccam_accept_thread,NULL);
	create_thread(&tid, cccam_connector_thread,NULL);
#endif

	create_thread(&cfg.cccam.tid_recvmsg, cc_recvmsg_thread,NULL);
	return 0;
}


