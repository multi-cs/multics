struct cccam_connect_status_data {
	struct cccam_connect_status_data *prev;
	struct cccam_connect_status_data *next;
	int status;
	uint32_t time;
	int fd;
	uint32_t ip;
	struct cccam_server_data *server;
	struct cc_crypt_block sendblock;	// crypto state block
	struct cc_crypt_block recvblock;	// crypto state block
	char data[64];
	struct cc_client_data *cli;
};

struct cccam_connect_status_data *cccam_connector = NULL;

void cccam_connector_add( struct cccam_connect_status_data *new )
{
	new->prev = NULL;
	new->next = cccam_connector;
	if (cccam_connector) cccam_connector->prev = new;
	//
	cccam_connector = new;
}

void cccam_connector_del ( struct cccam_connect_status_data *old )
{
	if (old->next) old->next->prev = old->prev;
	if (old->prev) old->prev->next = old->next;
	else cccam_connector = old->next;
	free( old );
}

int cc_connector_recvmsg(struct cccam_connect_status_data *connector)
{
	struct cc_client_data *cli;
	uint8_t buf[CC_MAXMSGSIZE];
	uint8_t tmp[255];
	int i;
	// Store data from param
	struct cccam_server_data *cccam = connector->server;

	//mlogf(LOGDEBUG,0," cc_connector_recvmsg: Status=%d FD=%d\n", connector->status, connector->fd);

	switch (connector->status) {


		case 0:
			// create & send random seed
			for(i=0; i<12; i++ ) tmp[i]=fast_rnd();
			// Create Multics ID
			tmp[3] = (tmp[0]^'M') + tmp[1] + tmp[2];
			tmp[7] = tmp[4] + (tmp[5]^'C') + tmp[6];
			tmp[11] = tmp[8] + tmp[9] + (tmp[10]^'S');
			//Create checksum for "O" cccam:
			for (i = 0; i < 4; i++) {
				tmp[12 + i] = (tmp[i] + tmp[4 + i] + tmp[8 + i]) & 0xff;
			}
			//mlogf(LOGDEBUG,getdbgflag(DBG_CCCAM,cccam->id,0)," CCcam%d: Send Random Key 16\n", cccam->id); debughex(tmp, 16);
			if ( !send_nonb(connector->fd, tmp, 16, 500) ) {
				close(connector->fd);
				connector->status = -1;
				return -1;
			}

			//XOR init bytes with 'CCcam'
			cc_crypt_xor(tmp);
			//mlogf(LOGDEBUG,0, " CCcam: XOR init bytes with 'CCcam'\n"); debughex(tmp, 16);
			//SHA1
			SHA_CTX ctx;
			SHA1_Init(&ctx);
			SHA1_Update(&ctx, tmp, 16);
			SHA1_Final(buf, &ctx);
			//init crypto states
			cc_crypt_init(&connector->sendblock, buf, 20);
			cc_decrypt(&connector->sendblock, tmp, 16);
				//mlogf(LOGDEBUG,getdbgflag(DBG_CCCAM,cccam->id,0)," CCcam%d: sendblock:cc_crypt_init \n", cccam->id); debughex(connector->sendblock.keytable,256);
			cc_crypt_init(&connector->recvblock, tmp, 16);
			cc_decrypt(&connector->recvblock, buf, 20);
				//mlogf(LOGDEBUG,getdbgflag(DBG_CCCAM,cccam->id,0)," CCcam%d: recvblock:cc_crypt_init \n", cccam->id); debughex(connector->recvblock.keytable,256);

			//mlogf(LOGDEBUG,getdbgflag(DBG_CCCAM,cccam->id,0)," CCcam: SHA1 hash\n"); debughex(buf,20);
			memcpy(connector->data,buf,20);
			connector->status++;
			break;


		case 1:
			if ((i=recv(connector->fd, buf, 20, MSG_NOSIGNAL|MSG_DONTWAIT)) == 20) {
				//mlogf(LOGDEBUG,getdbgflag(DBG_CCCAM,cccam->id,0)," CCcam%d: receive SHA1 hash %d\n", cccam->id, i); debughex(buf,i);
				cc_decrypt(&connector->recvblock, buf, 20);
				//mlogf(LOGDEBUG,getdbgflag(DBG_CCCAM,cccam->id,0)," Decrypted SHA1 hash (20):\n"); debughex(buf,20);
				if ( memcmp(buf,connector->data,20)!=0 ) {
					//mlogf(LOGDEBUG,getdbgflag(DBG_CCCAM,cccam->id,0)," cc_connect_cli(): wrong sha1 hash from client! (%s)\n",ip2string(connector->ip));
					close(connector->fd);
					connector->status = -1;
					return -1;
				}
			} else {
				//mlogf(LOGDEBUG,getdbgflag(DBG_CCCAM,cccam->id,0)," cc_connect_cli(): recv sha1 timeout\n");
				close(connector->fd);
				connector->status = -1;
				return -1;
			}
			connector->status++;
			break;


		case 2:
			// receive username
			i = recv(connector->fd, buf, 20, MSG_NOSIGNAL|MSG_DONTWAIT);
			//mlogf(LOGDEBUG,getdbgflag(DBG_CCCAM,cccam->id,0) , " CCcam%d: receive username %s -%d\n", cccam->id, ip2string(connector->ip), i); debughex(buf,i);

			char usr[64];
			memset(usr, 0, sizeof(usr));
			if (i == 20) {
				cc_decrypt(&connector->recvblock, buf, i);
				memcpy(usr,buf,20);
				usr[20] = 0;
				//strcpy(usr, (char*)buf);
				//mlogf(LOGDEBUG,0," cccam_connector: username '%s'\n", usr);
			}
			else {
				//mlogf(LOGDEBUG,getdbgflag(DBG_CCCAM,cccam->id,0)," cc_connect_cli(): recv user timeout\n");
				close(connector->fd);
				connector->status = -1;
				return -1;
			}
			// test username
			for(i=0; i<20; i++) {
				if (usr[i]==0) break;
				if (usr[i]<=32) { // bad username
					close(connector->fd);
					connector->status = -1;
					return -1;
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
						mlogf(LOGINFO,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," CCcam%d: connection refused for client '%s' (%s), client disabled\n", cccam->id, usr, ip2string(connector->ip));
						close(connector->fd);
						connector->status = -1;
						return -1;
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
							mlogf(LOGINFO,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," CCcam%d: connection refused for cacheexclient '%s' (%s), client disabled\n", cccam->id, usr, ip2string(connector->ip));
							close(connector->fd);
							connector->status = -1;
							return -1;
						}
						found = 1;
						break;
					}
					cli = cli->next;
				}
			}
			///pthread_mutex_unlock(&prg.lockcccli);
			if (!found) {
				mlogf(LOGWARNING,getdbgflag(DBG_CCCAM,cccam->id,0)," CCcam%d: Unknown Client '%s' (%s)\n", cccam->id, usr, ip2string(connector->ip));
				close(connector->fd);
				connector->status = -1;
				return -1;
			}
			// Check for Host
			if (cli->host) {
				struct host_data *host = cli->host;
				host->clip = connector->ip;
				if ( host->ip && (host->ip!=connector->ip) ) {
					uint32_t sec = getseconds()+60;
					if ( host->checkiptime > sec ) host->checkiptime = sec;
					mlogf(LOGWARNING,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," CCcam%d: Aborted connection from Client '%s' (%s), ip refused\n", cccam->id, usr, ip2string(connector->ip));
					cli->nbloginerror++;
					close(connector->fd);
					connector->status = -1;
					return -1;
				}
			}

			connector->cli = cli;
			connector->status++;
			break;


		case 3:
			// Encrypted Password
			cli = connector->cli;
			if ((i=recv(connector->fd, buf, 6, MSG_NOSIGNAL|MSG_DONTWAIT)) == 6) {
				memset(tmp, 0, sizeof(tmp));
				strcpy(tmp, cli->pass);
				cc_encrypt(&connector->recvblock, (uint8_t*)tmp, strlen(tmp));
				cc_decrypt(&connector->recvblock, buf, 6);
				if ( memcmp(buf,"CCcam\0",6) ) {
					mlogf(LOGWARNING,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," CCcam%d: login failed from client '%s'\n", cccam->id, cli->user);
					cli->nbloginerror++;
					close(connector->fd);
					connector->status = -1;
					return -1;
				}
			}
			else {
				mlogf(LOGWARNING,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," CCcam%d: login failed from client '%s', error receiving crypted password\n", cccam->id, cli->user);
				cli->nbloginerror++;
				close(connector->fd);
				connector->status = -1;
				return -1;
			}
			if (cli->ip==connector->ip) cli->nbdiffip++;
			// Send passwd ack
			memset(buf, 0, 20);
			memcpy(buf, "CCcam\0", 6);
			//mlogf(LOGDEBUG,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id),"Server: send ack '%s'\n",buf);
			cc_encrypt(&connector->sendblock, buf, 20);
			if (!send_nonb(connector->fd, buf, 20, 100) ) {
				close(connector->fd);
				connector->status = -1;
				return -1;
			}
			mlogf(LOGINFO,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," CCcam%d: client '%s' connected\n", cccam->id, cli->user);

			connector->status++;
			break;



		case 4:
			cli = connector->cli;
			// Recv cli data
			memset(buf, 0, sizeof(buf));
			i = cc_msg_recv( connector->fd, &connector->recvblock, buf, 5000);
			if ( i<65 ) {
				mlogf(LOGERROR,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," CCcam%d: Error recv cli '%s' data (%d/%d)\n", cccam->id, cli->user, i, errno);
				debughex(buf,i);
				close(connector->fd);
				connector->status = -1;
				return -1;
			}
			// Check for Nodeid/CCcam Version
#ifndef PUBLIC
			if (cli->option.checknodeid)
#endif
			if (cli->option.nodeid[0] && cli->option.nodeid[7]) {
				if (memcmp(cli->option.nodeid, buf+24, 8)) { // diff nodeid
					mlogf(LOGWARNING,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," CCcam%d: login failed from client '%s' (%s), wrong nodeid\n", cccam->id, cli->user, ip2string(connector->ip));
					cli->nbloginerror++;
					close(connector->fd);
					connector->status = -1;
					return -1;
				}
			}
			//Check Reconnection
			if (cli->connection.status>0) {
				if ( (GetTickCount()-cli->connection.time) > 60000 ) {
					cc_disconnect_cli(cli);
					if (cli->ip==connector->ip) mlogf(LOGWARNING,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," CCcam%d: Client '%s' (%s) already connected\n", cccam->id, cli->user, ip2string(connector->ip));
					else {
						mlogf(LOGWARNING,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," CCcam%d: Client '%s' (%s) already connected with different ip, Connection closed.\n", cccam->id, cli->user, ip2string(connector->ip));
						cli->nbloginerror++;
						close(connector->fd);
						connector->status = -1;
						return -1;
					}
				}
				else {
					mlogf(LOGWARNING,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," CCcam%d: Client '%s' just connected, new connection closed (%s)\n", cccam->id, cli->user, ip2string(connector->ip));
					cli->nbloginerror++;
					close(connector->fd);
					connector->status = -1;
					return -1;
				}
			}
			// Get Saved Data
			memcpy(&cli->sendblock, &connector->sendblock,sizeof(connector->sendblock));
			memcpy(&cli->recvblock, &connector->recvblock,sizeof(connector->recvblock));
#ifndef PUBLIC
			// store nodeid if not set :)
			if (!cli->option.nodeid[0] && !cli->option.nodeid[7]) {
				memcpy(cli->option.nodeid, buf+24, 8);
				prg.updatenodes = 1;
			}
#endif
			memcpy(cli->nodeid, buf+24, 8);
			memcpy(cli->version, buf+33, 31);
			memcpy(cli->build, buf+65, 31 );
			mlogf(LOGINFO,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," CCcam%d: client '%s' running version %s build %s\n", cccam->id, cli->user, cli->version, cli->build);  // cli->nodeid,8,

			cli->nblogin++;
			cli->cardsent = 0;
			memset( &cli->ecm, 0, sizeof(cli->ecm) );
			memset( &cli->lastecm, 0, sizeof(cli->lastecm) );
			cli->handle = connector->fd;
			cli->connection.status = 1;
			cli->connection.time = cli->lastactivity = GetTickCount();
			cli->lastecmtime = 0;
			cli->chkrecvtime = 0;
			cli->ip = connector->ip;
			cli->msg.len = 0;

//	pthread_mutex_unlock(&prg.lockcccli);
			// send cli data ack
			cc_msg_send( connector->fd, &cli->sendblock, CC_MSG_CLI_INFO, 0, NULL);
			//cc_msg_send( connector->fd, &cli->sendblock, CC_MSG_BAD_ECM, 0, NULL);
			int sendversion = ( (cli->version[28]=='W')&&(cli->version[29]='H')&&(cli->version[30]='O') );
			cc_sendinfo_cli(cli, sendversion);
			//cc_msg_send( connector->fd, &cli->sendblock, CC_MSG_BAD_ECM, 0, NULL);
			cli->handle = connector->fd;

#ifdef CACHEEX
			if (cli->cacheex_mode) {
				if (cli->cacheex_mode==3) {
					if (!create_thread( &cli->tid, (threadfn)cacheex_cc_cli_recvmsg, cli )) {
						cc_disconnect_cli(cli);
						connector->status = -1;
						return -1;
					}
				}
				else pipe_wakeup( prg.pipe.cacheex[1] );
			}
			else
#endif
#ifdef EPOLL_CCCAM
			pipe_pointer( prg.pipe.cccam[1], PIPE_CLI_CONNECTED, cli );
#else
			pipe_wakeup( prg.pipe.cccam[1] );
#endif



			cli->cardsent = 1;
			//TODO: read from client packet CC_MSG_BAD_ECM
			//len = cc_msg_recv(cli->handle, &cli->recvblock, buf, 3);
#ifdef CACHEEX
			if (!cli->cacheex_mode)
#endif
			cc_sendcards_cli(cli);


			// update pfd data ???
			cli->parent->clipfd.update = 1;
			connector->status = -1;
			// del from events
			struct epoll_event ev; // epoll event
			ev.events = EPOLLIN;
			ev.data.fd = connector->fd;
			ev.data.ptr = connector;
			if ( epoll_ctl(prg.epoll.con.cccam, EPOLL_CTL_DEL, connector->fd, &ev) == -1 ) mlogf(LOGERROR,DBG_ERROR,"Err! EPOLL_CTL_DEL %d\n", errno);
			break;
	}
	return connector->status;
}



void *cccam_connector_thread(void *param)
{
	prctl(PR_SET_NAME,"CCcam Conn",0,0,0);

	int i;
	struct epoll_event evlist[MAX_EPOLL_EVENTS]; // epoll recv events
	//Create epoll
	prg.epoll.con.cccam = epoll_create( MAX_EPOLL_EVENTS );

	// Add PIPE
	struct epoll_event ev; // epoll event
	ev.events = EPOLLIN | EPOLLPRI | EPOLLRDHUP;
	ev.data.ptr = NULL;
	if ( epoll_ctl(prg.epoll.con.cccam, EPOLL_CTL_ADD, prg.pipe.con.cccam[0], &ev) == -1 ) mlogf(LOGERROR,0,"epoll_ctl error cccam -1");

	while (!prg.restart) {

		int ready = epoll_wait( prg.epoll.con.cccam, evlist, MAX_EPOLL_EVENTS, 1002);
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
			struct cccam_connect_status_data *connector = evlist[i].data.ptr;

			if ( evlist[i].events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR) ) { // EPOLLRDHUP
				if (connector == NULL) mlogf(LOGERROR,DBG_ERROR,"Err! epoll_wait() pipe\n"); // error !!!
				else {
					close( connector->fd );
					cccam_connector_del( connector );
				}
			}
			else if ( evlist[i].events & (EPOLLIN|EPOLLPRI) ) {

				if (connector == NULL) {
					struct cccam_connect_status_data *connector;
					uint8_t buf[1024];
					struct pollfd pfd[2];
					do {
						int len = pipe_recv( prg.pipe.con.cccam[0], buf);
						if (len>0) {
							//mlogf(LOGDEBUG,getdbgflag(DBG_CCCAM,0,0)," CCcam: recv_msg from pipe (%d)\n", buf[0]);
							switch(buf[0]) {
								case PIPE_WAKEUP:  // ADD NEW CLIENT
									//mlogf(LOGTRACE,0," wakeup csmsg\n");
									break;
								case PIPE_CLI_CONNECTED:  // ADD NEW FD
									memcpy( &connector, buf+1, sizeof(void*) );
									// Add to events
									struct epoll_event ev; // epoll event
									ev.events = EPOLLIN;
									ev.data.fd = connector->fd;
									ev.data.ptr = connector;
									if ( epoll_ctl(prg.epoll.con.cccam, EPOLL_CTL_ADD, connector->fd, &ev) == -1 ) mlogf(LOGERROR,DBG_ERROR,"Err! EPOLL_CTL_ADD %d\n", errno);
									cccam_connector_add( connector );
									cc_connector_recvmsg( connector );
									break;
							}
						}
						pfd[0].fd = prg.pipe.con.cccam[0];
						pfd[0].events = POLLIN | POLLPRI;
					} while (poll(pfd, 1, 3)>0);
				}

				else if ( cc_connector_recvmsg( connector ) == -1 ) {
					cccam_connector_del( connector );
				}
			}
		}
	}
	return NULL;
}


void cccam_srv_accept2(struct cccam_server_data *srv)
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
		if ( isblockedip(newip) ) {
			mlogf(LOGWARNING,getdbgflag(DBG_CCCAM,srv->id,0)," CCcam%d: New Connection (%s) closed, ip blocked\n", srv->id, ip2string(newip) );
			close(newfd);
		}
		else {
			pthread_t srv_tid;
			if (cfg.cccam.keepalive) SetSocketKeepalive(newfd);
			SetSocketNoDelay(newfd);
			SetSoketNonBlocking(newfd);
			struct cccam_connect_status_data *connector = malloc( sizeof(struct cccam_connect_status_data) );
			memset( connector, 0, sizeof(struct cccam_connect_status_data) );
			connector->status = 0;
			connector->time = GetTickCount();
			connector->fd = newfd;
			connector->ip = newip;
			connector->server = srv;
			pipe_pointer( prg.pipe.con.cccam[1], PIPE_CLI_CONNECTED, connector );
		}
	}
}

