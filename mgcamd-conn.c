
///////////////////////////////////////////////////////////////////////////////
// CONNECT
///////////////////////////////////////////////////////////////////////////////

struct connect_fd_data {
	int status;
	int fd;
	uint32_t ip;
	struct mgcamdserver_data *mgcamd;
	unsigned char sessionkey[16];
}

int mg_connector( struct connect_fd_data *con )
{

	if (con->status==0) { // Start Connection
		unsigned char keymod[14];
		int i;
		// Create random deskey
		for (i=0; i<14; i++) keymod[i] = 0xff & rand();
		// Create Multics ID
		keymod[3] = (keymod[0]^'M') + keymod[1] + keymod[2];
		keymod[7] = keymod[4] + (keymod[5]^'C') + keymod[6];
		keymod[11] = keymod[8] + keymod[9] + (keymod[10]^'S');
		// send random des key
		if ( !send_nonb(con->fd, keymod, 14, 500) ) {
			mlogf(LOGERROR,getdbgflag(DBG_MGCAMD,0,0)," mgcamd: error sending init sequence\n");
			goto logout;
		}
		// Calc SessionKey
		des_login_key_get(keymod, con->mgcamd->key, 14, con->sessionkey);
		con->status++;
		return;
	}

	else if (con->status==1) { // Get LOGIN INFO
		struct cs_custom_data clicd;
		unsigned char buf[CWS_NETMSGSIZE];
		// 3. login info
		int i = cs_message_receive(con->fd, &clicd, buf, con->sessionkey,5000);
		if (i<=0) {
			if (i==-2) mlogf(LOGWARNING,getdbgflag(DBG_MGCAMD,0,0)," mgcamd: (%s) new connection closed, wrong des key\n", ip2string(ip));
			else mlogf(LOGWARNING,getdbgflag(DBG_MGCAMD,0,0)," mgcamd: (%s) new connection closed, receive timeout\n", ip2string(ip));
			goto logout;
		}
		if (buf[0]!=MSG_CLIENT_2_SERVER_LOGIN) {
			goto logout;
		}
		// Check username length
		if ( strlen( (char*)buf+3 )>63 ) {
			mlogf(LOGWARNING,getdbgflag(DBG_MGCAMD,0,0)," mgcamd: wrong username length (%s)\n", ip2string(ip));
			goto logout;
		}
		// test username
		for (i=3; i<(3+64); i++) {
			if (buf[i]==0) break;
			if (buf[i]<=32) { // bad username
				goto logout;
			}
		}
		pthread_mutex_lock(&prg.lockclimg);
		int index = 3;
		struct mg_client_data *cli = mgcamd->client;
		int found = 0;
		char *name = (char*)(buf+index);
		uint32_t hash = hashCode( (unsigned char *)name, strlen(name) );
		while (cli) {
			if (cli->userhash==hash)
			if (!strcmp(cli->user, name)) {
				if (IS_DISABLED(cli->flags)) { // Connect only enabled clients
					mlogf(LOGINFO,getdbgflag(DBG_MGCAMD,0,cli->id)," mgcamd: connection refused for client '%s' (%s), client disabled\n", cli->user, ip2string(ip));
					pthread_mutex_unlock(&prg.lockclimg);
					goto logout;
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
			//cs_message_send(con->fd, NULL, buf, 3, con->sessionkey);
			mlogf(LOGWARNING,getdbgflag(DBG_MGCAMD,0,0)," mgcamd: unknown user '%s' (%s)\n", &buf[3], ip2string(ip));
			pthread_mutex_unlock(&prg.lockclimg);
			goto logout;
		}
		// Check for Host
		if (cli->host) {
			struct host_data *host = cli->host;
			host->clip = ip;
			if ( host->ip && (host->ip!=ip) ) {
				uint32_t sec = getseconds()+60;
				if ( host->checkiptime > sec ) host->checkiptime = sec;
				mlogf(LOGWARNING,getdbgflag(DBG_MGCAMD,0,cli->id)," mgcamd: Client '%s' (%s), ip refused\n",cli->user, ip2string(ip)); 
				cli->nbloginerror++;
				pthread_mutex_unlock(&prg.lockclimg);
				goto logout;
			}
		}
		// Check password
	    char passwdcrypt[120];
		index += strlen(cli->user) +1;
		__md5_crypt(cli->pass, "$1$abcdefgh$",passwdcrypt);

		if ( strcmp(passwdcrypt,(char*)&buf[index]) ) {
			// send NAK
			buf[0] = MSG_CLIENT_2_SERVER_LOGIN_NAK;
			buf[1] = 0;
			buf[2] = 0;
			//cs_message_send(con->fd, NULL, buf, 3, con->sessionkey);
			mlogf(LOGWARNING,getdbgflag(DBG_MGCAMD,0,cli->id)," mgcamd: client '%s' wrong password (%s)\n", cli->user, ip2string(ip));
			cli->nbloginerror++;
			pthread_mutex_unlock(&prg.lockclimg);
			goto logout;
		}

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
					goto logout;
				}
			}
			else {
				mlogf(LOGINFO,getdbgflag(DBG_MGCAMD,0,cli->id)," mgcamd: Client '%s' just connected, new connection closed (%s)\n", cli->user, ip2string(ip));
				cli->nbloginerror++;
				pthread_mutex_unlock(&prg.lockclimg);
				goto logout;
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
		cs_message_send(con->fd, &clicd, buf, 3, con->sessionkey);
		//
		des_login_key_get( mgcamd->key, (unsigned char*)passwdcrypt, strlen(passwdcrypt),con->sessionkey);
		memcpy( &cli->sessionkey, &con->sessionkey, 16);
		// Setup User data
		cli->msg.len = 0;
		cli->handle = con->fd;
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
		goto login;
	}

logout:
	close(con->fd);
login:
	free( con );
}



void *mg_connector_thread(void *param)
{
	struct epoll_event evlist[MAX_EPOLL_EVENTS]; // epoll recv events
	struct epoll_event ev; // epoll event

	prg.epoll.mgcon = epoll_create( MAX_EPOLL_EVENTS );

	// Add PIPE
	ev.events = EPOLLIN | EPOLLPRI | EPOLLRDHUP;
	ev.data.ptr = NULL;
	if ( epoll_ctl(prg.epoll.mgcon, EPOLL_CTL_ADD, mgcamd->handle, &ev) == -1 ) mlogf(LOGERROR,0,"epoll_ctl error mgconnectorthread -1");

	while(1) {
		int ready = epoll_wait( prg.epoll.mgcon, evlist, MAX_EPOLL_EVENTS, 1003);
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
						if ( pfd[mgcamd->ipoll].revents & (POLLIN|POLLPRI) ) mgcamd_srv_accept(mgcamd);
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



