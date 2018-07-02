///////////////////////////////////////////////////////////////////////////////
// THREAD CONNECT TO SERVERS
///////////////////////////////////////////////////////////////////////////////

void *cs_connect_srv_th(struct server_data *srv)
{
	int fd;
	// --->> FAST THREAD
	srv->connection.status = -1; // we are connecting
	srv->connection.time = GetTickCount();
	struct host_data *host = srv->host;
	uint32_t ip = host->ip;
	if (!ip) ip = host->clip;
	fd = CreateClientSockTcp(ip, srv->port);
	if (fd<0) {
		// Setup Host Checking ip time
		if ( host->checkiptime > (getseconds()+60) ) host->checkiptime = getseconds()+60;
		//
		srv->error = errno;
		mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," server: socket connection failed to server (%s:%d)\n", srv->host->name,srv->port);
		if (errno==ECONNREFUSED) {
			static char msg[]= "No-one listening on the remote address";
			srv->statmsg = msg;
		}
		else if (errno==ENETUNREACH) {
			static char msg[]= "Network is unreachable";
			srv->statmsg = msg;
		}
		else if (errno==ETIMEDOUT) {
			static char msg[]= "Timeout while attempting connection";
			srv->statmsg = msg;
		}
		else {
			static char msg[]= "socket connection failed";
			srv->statmsg = msg;
		}
		if (srv->connection.delay<90000) srv->connection.delay = srv->connection.delay + 10000;
		srv->connection.status = 0;
		return NULL;
	}

	//SetSocketKeepalive(fd);
	SetSocketNoDelay(fd);
	SetSoketNonBlocking(fd);

	if (srv->connection.delay<90000) srv->connection.delay = srv->connection.delay + 15000;
	srv->error = 0; // No error

	if (srv->type==TYPE_NEWCAMD) {
		//mlogf(LOGDEBUG,0," Connecting to Newcamd server (%s:%d) ...\n", srv->host->name,srv->port);
		if ( cs_connect_srv(srv,fd)!=0 ) {
			mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," server: connection failed to newcamd server (%s:%d)\n", srv->host->name,srv->port);
			srv->connection.status = 0;
			close(fd);
		}
	}
#ifdef CCCAM_CLI
	else if (srv->type==TYPE_CCCAM) {
		//mlogf(LOGDEBUG,0," Connecting to CCcam server (%s:%d) ...\n", srv->host->name,srv->port);
		if ( cc_connect_srv(srv,fd)!=0 ) {
			mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," server: connection failed to CCcam server (%s:%d)\n", srv->host->name,srv->port);
			srv->connection.status = 0;
			close(fd);
		}
	}
#endif
#ifdef RADEGAST_CLI
	else if (srv->type==TYPE_RADEGAST) {
		//mlogf(LOGDEBUG,0," Connecting to Radegast server (%s:%d) ...\n", srv->host->name,srv->port);
		if ( rdgd_connect_srv(srv,fd)!=0 ) {
			mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," server: connection failed to Radegast server (%s:%d)\n", srv->host->name,srv->port);
			srv->connection.status = 0;
			close(fd);
		}
	}
#endif
#ifdef CS378X_CLI
	else if (srv->type==TYPE_CS378X) {
		//mlogf(LOGDEBUG,0," Connecting to CS378X server (%s:%d) ...\n", srv->host->name,srv->port);
		if ( cs378x_connect_srv(srv,fd)!=0 ) {
			mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," server: connection failed to cs378x server (%s:%d)\n", srv->host->name,srv->port);
			srv->connection.status = 0;
			close(fd);
		}
	}
#endif
	else close(fd);

	return NULL;
}


#ifdef CAMD35_CLI
void *camd35_connect_srv_th(struct server_data *srv)
{
	if (srv->type!=TYPE_CAMD35) return NULL;

	//mlogf(LOGDEBUG,0," Connecting to camd35 server (%s:%d) ...\n", srv->host->name,srv->port);

	srv->connection.status = -1;
	srv->connection.time = GetTickCount();
	struct host_data *host = srv->host;
	uint32_t ip = host->ip;
	if (!ip) ip = host->clip;
	
	int fd =  CreateClientSockUdp( 0, 0 ); //srv->port, ip);
	if (fd<0) {
		static char msg[]= "socket creation failed";
		srv->statmsg = msg;
		srv->connection.delay += 10000;
		srv->connection.status = 0;
		return NULL;
	}
	if (srv->connection.delay<90000) srv->connection.delay += 15000;
	srv->error = 0; // No error

	if ( camd35_connect_srv(srv,fd)!=0 ) {
		mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," server: connection failed to camd35 server (%s:%d)\n", srv->host->name,srv->port);
		srv->connection.status = 0;
		close( fd );
	}

	return NULL;
}
#endif


void connect_server(struct server_data *srv)
{
	uint32_t ticks = GetTickCount();
	pthread_t srv_tid;

	while (srv) {
		if ( !IS_DISABLED(srv->flags) ) {
			if ( ( (srv->host->ip)||(srv->host->clip) ) && !isblockedip(srv->host->ip) ) {
				if ( !srv->connection.status ) {
					if ( (srv->connection.time+srv->connection.delay) < ticks ) {
#ifdef CAMD35_CLI
						if (srv->type==TYPE_CAMD35) create_thread(&srv_tid, (threadfn)camd35_connect_srv_th, srv);
						else
#endif
						create_thread(&srv_tid, (threadfn)cs_connect_srv_th, srv); // Lock server
					}
				}
			}
			else {
				static char msg[]= "Invalid Address";
				srv->statmsg = msg;
			}
		}
		else {
			static char msg[]= "Disabled";
			srv->statmsg = msg;
		}
		srv = srv->next;
	}
}

void *connect_servers(void *param)
{
#ifndef PUBLIC
	prg.pid_srv = syscall(SYS_gettid);
	prctl(PR_SET_NAME,"Server Conn",0,0,0);
#endif
	while (!prg.restart) {
		pthread_mutex_lock(&prg.locksrvth);

		connect_server(cfg.server);

		sleep(1);

		connect_server(cfg.cacheexserver);

		pthread_mutex_unlock(&prg.locksrvth);
		sleep(3);
	}
	return NULL;
}


int start_thread_srv()
{
	create_thread(&prg.tid_srv, (threadfn)connect_servers,NULL);
	return 0;
}

