struct mgcamd_connect_status_data {
	struct mgcamd_connect_status_data *prev;
	struct mgcamd_connect_status_data *next;
	int status;
	uint32_t time;
	int fd;
	uint32_t ip;
	struct mgcamdserver_data *server;
	unsigned char sessionkey[16];

	char data[64];
};

struct mgcamd_connect_status_data *mgcamd_connector = NULL;

void mgcamd_connector_add( struct mgcamd_connect_status_data *new )
{
	new->prev = NULL;
	new->next = mgcamd_connector;
	if (mgcamd_connector) mgcamd_connector->prev = new;
	//
	mgcamd_connector = new;
}

void mgcamd_connector_del ( struct mgcamd_connect_status_data *old )
{
	if (old->next) old->next->prev = old->prev;
	if (old->prev) old->prev->next = old->next;
	else mgcamd_connector = old->next;
	free( old );
}

int mgcamd_connector_recvmsg(struct mgcamd_connect_status_data *connector)
{
	struct mg_client_data *cli;
	uint8_t buf[CC_MAXMSGSIZE];
	struct cs_custom_data clicd;
	uint8_t tmp[255];
	int i;
	unsigned char keymod[14];
	// Store data from param
	struct mgcamdserver_data *mgcamd = connector->server;

	//mlogf(LOGDEBUG,0," cc_connector_recvmsg: Status=%d FD=%d\n", connector->status, connector->fd);

	switch (connector->status) {

		case 0:
			// Create random deskey
			for (i=0; i<14; i++) keymod[i] = 0xff & rand();
			// Create Multics ID
			keymod[3] = (keymod[0]^'M') + keymod[1] + keymod[2];
			keymod[7] = keymod[4] + (keymod[5]^'C') + keymod[6];
			keymod[11] = keymod[8] + keymod[9] + (keymod[10]^'S');
			// send random des key
			if ( !send_nonb(connector->fd, keymod, 14, 500) ) {
				mlogf(LOGERROR,getdbgflag(DBG_MGCAMD,0,0)," mgcamd: error sending init sequence\n");
				close(connector->fd);
				connector->status = -1;
				return -1;
			}
			// Calc SessionKey
			des_login_key_get(keymod, mgcamd->key, 14, connector->sessionkey);
			connector->status++;
			break;

		case 1:
			// 3. login info
			i = cs_message_receive(connector->fd, &clicd, buf, connector->sessionkey,3000);
			if (i<=0) {
				if (i==-2) mlogf(LOGWARNING,getdbgflag(DBG_MGCAMD,0,0)," mgcamd: (%s) new connection closed, wrong des key\n", ip2string(connector->ip));
				else mlogf(LOGERROR,getdbgflag(DBG_MGCAMD,0,0)," mgcamd: (%s) new connection closed, receive timeout (got %d)\n", ip2string(connector->ip), i);
				close(connector->fd);
				connector->status = -1;
				return -1;
			}
			if (buf[0]!=MSG_CLIENT_2_SERVER_LOGIN) {
				close(connector->fd);
				connector->status = -1;
				return -1;
			}
			// Check username length
			if ( strlen( (char*)buf+3 )>63 ) {
				/*
				buf[0] = MSG_CLIENT_2_SERVER_LOGIN_NAK;
				buf[1] = 0;
				buf[2] = 0;
				cs_message_send(connector->fd, NULL, buf, 3, connector->sessionkey);
				*/
				mlogf(LOGERROR,getdbgflag(DBG_MGCAMD,0,0)," mgcamd: wrong username length (%s)\n", ip2string(connector->ip));
				close(connector->fd);
				connector->status = -1;
				return -1;
			}

			// test username
			for(i=3; i<(3+64); i++) {
				if (buf[i]==0) break;
				if (buf[i]<=32) { // bad username
					close(connector->fd);
					connector->status = -1;
					return -1;
				}
			}
			int index = 3;
			struct mg_client_data *cli = mgcamd->client;
			int found = 0;
			char *name = (char*)(buf+index);
			uint32_t hash = hashCode( (unsigned char *)name, strlen(name) );
			while (cli) {
				if (cli->userhash==hash)
				if (!strcmp(cli->user, name)) {
					if (IS_DISABLED(cli->flags)) { // Connect only enabled clients
						mlogf(LOGINFO,getdbgflag(DBG_MGCAMD,0,cli->id)," mgcamd: connection refused for client '%s' (%s), client disabled\n", cli->user, ip2string(connector->ip));
						close(connector->fd);
						connector->status = -1;
						return -1;
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
				//cs_message_send(connector->fd, NULL, buf, 3, connector->sessionkey);
				mlogf(LOGWARNING,getdbgflag(DBG_MGCAMD,0,0)," mgcamd: unknown user '%s' (%s)\n", &buf[3], ip2string(connector->ip));
				close(connector->fd);
				connector->status = -1;
				return -1;
			}
			// Check for Host
			if (cli->host) {
				struct host_data *host = cli->host;
				host->clip = connector->ip;
				if ( host->ip && (host->ip!=connector->ip) ) {
					uint sec = getseconds()+60;
					if ( host->checkiptime > sec ) host->checkiptime = sec;
					mlogf(LOGWARNING,getdbgflag(DBG_MGCAMD,0,cli->id)," mgcamd: Client '%s' (%s), ip refused\n",cli->user, ip2string(connector->ip)); 
					cli->nbloginerror++;
					close(connector->fd);
					connector->status = -1;
					return -1;
				}
			}
			// Check password
			index += strlen(cli->user) +1;
		    char passwdcrypt[120];
			__md5_crypt(cli->pass, "$1$abcdefgh$",passwdcrypt);
			if ( strcmp(passwdcrypt,(char*)&buf[index]) ) {
				// send NAK
				buf[0] = MSG_CLIENT_2_SERVER_LOGIN_NAK;
				buf[1] = 0;
				buf[2] = 0;
				//cs_message_send(connector->fd, NULL, buf, 3, connector->sessionkey);
				mlogf(LOGWARNING,getdbgflag(DBG_MGCAMD,0,cli->id)," mgcamd: client '%s' wrong password (%s)\n", cli->user, ip2string(connector->ip));
				cli->nbloginerror++;
				close(connector->fd);
				connector->status = -1;
				return -1;
			}

			if (cli->ip!=connector->ip) cli->nbdiffip++;
			//Check Reconnection
			if (cli->connection.status>0) {
				if ( (GetTickCount()-cli->connection.time) > 60000 ) {
					mg_disconnect_cli(cli);
					if (cli->ip==connector->ip) mlogf(LOGWARNING,getdbgflag(DBG_MGCAMD,0,cli->id)," mgcamd: Client '%s' (%s) already connected\n",cli->user, ip2string(connector->ip));
					else {
						mlogf(LOGWARNING,getdbgflag(DBG_MGCAMD,0,cli->id)," mgcamd: Client '%s' (%s) already connected with different ip, Connections closed (%s)\n", cli->user, ip2string(cli->ip), ip2string(connector->ip));
						cli->nbloginerror++;
						close(connector->fd);
						connector->status = -1;
					return -1;
					}
				}
				else {
					mlogf(LOGWARNING,getdbgflag(DBG_MGCAMD,0,cli->id)," mgcamd: Client '%s' just connected, new connection closed (%s)\n", cli->user, ip2string(connector->ip));
					cli->nbloginerror++;
					close(connector->fd);
					connector->status = -1;
					return -1;
				}
			}
			// OK
			cli->nblogin++;
			// Store program id
			cli->progid = clicd.sid;
			// Send ACK
			buf[0] = MSG_CLIENT_2_SERVER_LOGIN_ACK;
			buf[1] = 0;
			buf[2] = 0;
			//clicd.msgid = 0;
			clicd.sid = 0x6E73;
			clicd.caid = 0;
			clicd.provid = 0x14000000; // mgcamd protocol version?
			cs_message_send(connector->fd, &clicd, buf, 3, connector->sessionkey);
			//
			des_login_key_get( mgcamd->key, (unsigned char*)passwdcrypt, strlen(passwdcrypt),connector->sessionkey);
			memcpy( &cli->sessionkey, &connector->sessionkey, 16);
			// Setup User data
			cli->msg.len = 0;
			cli->handle = connector->fd;
			cli->ip = connector->ip;
			memset( &cli->ecm, 0, sizeof(cli->ecm) );
			cli->connection.status = 1;
			cli->connection.time = GetTickCount();
			cli->lastactivity = GetTickCount();
			cli->lastecmtime = 0;
			cli->chkrecvtime = 0;
			mlogf(LOGINFO,getdbgflag(DBG_MGCAMD,0,cli->id)," mgcamd: client '%s' connected (%s)\n", cli->user, ip2string(connector->ip));
#ifdef EPOLL_MGCAMD
			pipe_pointer( prg.pipe.mgcamd[1], PIPE_CLI_CONNECTED, cli );
#else
			pipe_wakeup( prg.pipe.mgcamd[1] );
#endif
			// update pfd data ???
			cli->parent->clipfd.update = 1;
			connector->status = -1;
			// del from events
			struct epoll_event ev; // epoll event
			ev.events = EPOLLIN;
			ev.data.fd = connector->fd;
			ev.data.ptr = connector;
			if ( epoll_ctl(prg.epoll.con.mgcamd, EPOLL_CTL_DEL, connector->fd, &ev) == -1 ) mlogf(LOGERROR,DBG_ERROR,"Err! EPOLL_CTL_DEL %d\n", errno);
			break;
	}
	return connector->status;
}



void *mgcamd_connector_thread(void *param)
{
	prctl(PR_SET_NAME,"Mgcamd Conn",0,0,0);

	int i;
	struct epoll_event evlist[MAX_EPOLL_EVENTS]; // epoll recv events
	//Create epoll
	prg.epoll.con.mgcamd = epoll_create( MAX_EPOLL_EVENTS );

	// Add PIPE
	struct epoll_event ev; // epoll event
	ev.events = EPOLLIN | EPOLLPRI | EPOLLRDHUP;
	ev.data.ptr = NULL;
	if ( epoll_ctl(prg.epoll.con.mgcamd, EPOLL_CTL_ADD, prg.pipe.con.mgcamd[0], &ev) == -1 ) mlogf(LOGERROR,0,"epoll_ctl error mgcamd -1");

	while (!prg.restart) {

		int ready = epoll_wait( prg.epoll.con.mgcamd, evlist, MAX_EPOLL_EVENTS, 1002);
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
			struct mgcamd_connect_status_data *connector = evlist[i].data.ptr;

			if ( evlist[i].events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR) ) { // EPOLLRDHUP
				if (connector == NULL) mlogf(LOGERROR,DBG_ERROR,"Err! epoll_wait() pipe\n"); // error !!!
				else {
					close( connector->fd );
					mgcamd_connector_del( connector );
				}
			}
			else if ( evlist[i].events & (EPOLLIN|EPOLLPRI) ) {

				if (connector == NULL) {
					struct mgcamd_connect_status_data *connector;
					uint8_t buf[1024];
					struct pollfd pfd[2];
					do {
						int len = pipe_recv( prg.pipe.con.mgcamd[0], buf);
						if (len>0) {
							//mlogf(LOGDEBUG,getdbgflag(DBG_MGCAMD,0,0)," mgcamd: recv_msg from pipe (%d)\n", buf[0]);
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
									if ( epoll_ctl(prg.epoll.con.mgcamd, EPOLL_CTL_ADD, connector->fd, &ev) == -1 ) mlogf(LOGERROR,DBG_ERROR,"Err! EPOLL_CTL_ADD %d\n", errno);
									mgcamd_connector_add( connector );
									mgcamd_connector_recvmsg( connector );
									break;
							}
						}
						pfd[0].fd = prg.pipe.con.mgcamd[0];
						pfd[0].events = POLLIN | POLLPRI;
					} while (poll(pfd, 1, 3)>0);
				}

				else if ( mgcamd_connector_recvmsg( connector ) == -1 ) {
					mgcamd_connector_del( connector );
				}
			}
		}
	}
	return NULL;
}


void mgcamd_srv_accept2(struct mgcamdserver_data *srv)
{
	struct sockaddr_in newaddr;
	socklen_t socklen = sizeof(struct sockaddr);
	int newfd = accept( srv->handle, (struct sockaddr*)&newaddr, /*(socklen_t*)*/&socklen);
	if ( newfd<=0 ) {
		if ( (errno!=EAGAIN) && (errno!=EINTR) ) mlogf(LOGERROR,getdbgflag(DBG_MGCAMD,srv->id,0)," mgcamd%d: Accept failed (errno=%d)\n", srv->id,errno);
	}
	else {
		SetSocketReuseAddr(newfd);
		uint32_t newip = newaddr.sin_addr.s_addr;
		if ( isblockedip(newip) ) {
			mlogf(LOGWARNING,getdbgflag(DBG_MGCAMD,srv->id,0)," mgcamd%d: New Connection (%s) closed, ip blocked\n", srv->id, ip2string(newip) );
			close(newfd);
		}
		else {
			pthread_t srv_tid;
			if (cfg.mgcamd.keepalive) SetSocketKeepalive(newfd);
			SetSocketNoDelay(newfd);
			SetSoketNonBlocking(newfd);
			struct mgcamd_connect_status_data *connector = malloc( sizeof(struct mgcamd_connect_status_data) );
			memset( connector, 0, sizeof(struct mgcamd_connect_status_data) );
			connector->status = 0;
			connector->time = GetTickCount();
			connector->fd = newfd;
			connector->ip = newip;
			connector->server = srv;
			pipe_pointer( prg.pipe.con.mgcamd[1], PIPE_CLI_CONNECTED, connector );
		}
	}
}

