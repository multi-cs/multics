
int srv_sharelimits(struct server_data *srv, uint16_t caid, uint32_t provid)
{
	int i;
	int uphops1 = 10; // for 0:0
	int uphops2 = 10; // for caid:0
	for (i=0; i<100; i++) {
		if (srv->sharelimits[i].caid==0xffff) break;
		if (!srv->sharelimits[i].caid) {
			if (!srv->sharelimits[i].provid) uphops1 = srv->sharelimits[i].uphops;
		}
		else if (srv->sharelimits[i].caid==caid) {
			if (srv->sharelimits[i].provid==provid) return srv->sharelimits[i].uphops;
			else if (!srv->sharelimits[i].provid) uphops2 = srv->sharelimits[i].uphops;
		}
	}
	if (uphops2<uphops1) return uphops2; else return uphops1;// Max UPHOPS
}

struct server_data *getsrvbyid(uint32_t id)
{
	if (!id) return NULL;
	struct server_data *srv = cfg.server;
	while (srv) {
		if (srv->id==id) return srv;
		srv = srv->next;
	}
	srv = cfg.cacheexserver;
	while (srv) {
		if (srv->id==id) return srv;
		srv = srv->next;
	}
	return NULL;
}

struct server_data *getcesrvbyid(uint32_t id)
{
	if (!id) return NULL;
	struct server_data *srv = cfg.cacheexserver;
	while (srv) {
		if (srv->id==id) return srv;
		srv = srv->next;
	}
	return NULL;
}

char *getsrvtype(struct server_data *srv)
{
	static char *_cccam = "CCcam";
	static char *_newcamd = "newcamd";
	static char *_radegast = "radegast";
	static char *_camd35 = "camd35";
	static char *_cs378x = "cs378x";
	if (srv->type==TYPE_CCCAM) return _cccam;
	else if (srv->type==TYPE_NEWCAMD) return _newcamd;
	else if (srv->type==TYPE_RADEGAST) return _radegast;
	else if (srv->type==TYPE_CAMD35) return _camd35;
	else if (srv->type==TYPE_CS378X) return _cs378x;
	else return NULL;
}

void disconnect_srv(struct server_data *srv)
{
	static char msg[]= "Disconnected";
	srv->statmsg = msg;
	// close handle
	close(srv->handle);
	srv->handle = -1;
	// Set connection data
	srv->connection.status = 0;
	uint32_t ticks = GetTickCount();
	srv->connection.uptime += ticks - srv->connection.time;
	srv->connection.lastseen = ticks; // Last Seen
	srv->connection.delay = 0;
	// Remove Cards & ecm requests
#ifdef CACHEEX
	if (!srv->cacheex_mode)
#endif
	{
		if (srv->busy) ecm_setsrvflag(srv->ecm.request, srv->id, ECM_SRV_EXCLUDE);
		pthread_mutex_lock( &srv->lock );
		free_cardlist(srv->card);
		srv->card = NULL;
		pthread_mutex_unlock( &srv->lock );
	}
	// update server data
	srv->busy = 0;
	srv->host->checkiptime = 15; // maybe ip changed
	memset( &srv->keepalive, 0, sizeof(srv->keepalive) );
	// Debug
	mlogf(LOGINFO, getdbgflag(DBG_SERVER,0,srv->id)," %s server (%s:%d) disconnected\n", getsrvtype(srv), srv->host->name, srv->port);
}

