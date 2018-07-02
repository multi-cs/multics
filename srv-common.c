
#ifdef CACHEEX
#ifdef CS378X_SRV
void forward_cs378x(ECM_DATA *ecm)
{
	struct server_data *srv = cfg.cacheexserver;
	while (srv) {
		if ( (srv->type==TYPE_CS378X) && (srv->cacheex_mode==2) && (srv->handle>0) && (srv->cacheex_forward) ) {
			if ( acceptshare( srv->sharelimits, ecm->caid, ecm->provid) ) {
				if (srv->cacheex_forward==2)
					cs378x_sendecm_extrasrv(srv, ecm);
				else
					cs378x_sendecm_srv(srv, ecm);
				srv->lastecmtime = GetTickCount();
				srv->ecmnb++;
				srv->busy=1;
				srv->ecm.msgid++;
				if (srv->ecm.msgid>0xfff) srv->ecm.msgid = 1;
				srv->ecm.request = ecm;
				srv->cacheex.push[0]++;
			}
		}
		srv = srv->next;
	}
}
#endif
#endif

///////////////////////////////////////////////////////////////////////////////
//
///////////////////////////////////////////////////////////////////////////////

#ifdef MONOTHREAD_ACCEPT

void *connect_cli_thread(void *param)
{
#ifndef PUBLIC
	prg.pid_connect = syscall(SYS_gettid);
	prctl(PR_SET_NAME,"Accept",0,0,0);
#endif

	while(!prg.restart) {

		struct pollfd pfd[MAX_PFD];
		int pfdcount = 0;

#ifdef FREECCCAM_SRV
		if ( !IS_DISABLED(cfg.freecccam.server.flags)&&(cfg.freecccam.server.handle>0) ) {
				cfg.freecccam.server.ipoll = pfdcount;
				pfd[pfdcount].fd = cfg.freecccam.server.handle;
				pfd[pfdcount++].events = POLLIN | POLLPRI;
		} else cfg.freecccam.server.ipoll = -1;
#endif

#ifdef CCCAM_SRV
		struct cccam_server_data *cccam = cfg.cccam.server;
		while (cccam) {
			if ( !IS_DISABLED(cccam->flags) && (cccam->handle>0) ) {
				cccam->ipoll = pfdcount;
				pfd[pfdcount].fd = cccam->handle;
				pfd[pfdcount++].events = POLLIN | POLLPRI;
			} else cccam->ipoll = -1;
			cccam = cccam->next;
		}
#endif

#ifdef MGCAMD_SRV
		struct mgcamdserver_data *mgcamd = cfg.mgcamd.server;
		while (mgcamd) {
			if ( !IS_DISABLED(mgcamd->flags) && (mgcamd->handle>0) ) {
				mgcamd->ipoll = pfdcount;
				pfd[pfdcount].fd = mgcamd->handle;
				pfd[pfdcount++].events = POLLIN | POLLPRI;
			} else mgcamd->ipoll = -1;
			mgcamd = mgcamd->next;
		}
#endif

#ifdef CS378X_SRV
		struct camd35_server_data *cs378x = cfg.cs378x.server;
		while (cs378x) {
			if ( !IS_DISABLED(cs378x->flags) && (cs378x->handle>0) ) {
				cs378x->ipoll = pfdcount;
				pfd[pfdcount].fd = cs378x->handle;
				pfd[pfdcount++].events = POLLIN | POLLPRI;
			} else cs378x->ipoll = -1;
			cs378x = cs378x->next;
		}
#endif

		struct cardserver_data *cs = cfg.cardserver;
		while(cs) {
			if ( cs->option.fsharenewcamd && !IS_DISABLED(cs->newcamd.flags) && (cs->newcamd.handle>0) ) {
				cs->newcamd.ipoll = pfdcount;
				pfd[pfdcount].fd = cs->newcamd.handle;
				pfd[pfdcount++].events = POLLIN | POLLPRI;
			} else cs->newcamd.ipoll = -1;
			cs = cs->next;
		}


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

#ifdef CCCAM_SRV
			struct cccam_server_data *cccam = cfg.cccam.server;
			while (cccam) {
				if ( !IS_DISABLED(cccam->flags) && (cccam->handle>0) && (cccam->ipoll>=0) && (cccam->handle==pfd[cccam->ipoll].fd) ) {
					if ( pfd[cccam->ipoll].revents & (POLLIN|POLLPRI) ) cccam_srv_accept2(cccam);
				}
				cccam = cccam->next;
			}
#endif

#ifdef MGCAMD_SRV
			struct mgcamdserver_data *mgcamd = cfg.mgcamd.server;
			while (mgcamd) {
				if ( !IS_DISABLED(mgcamd->flags) && (mgcamd->handle>0) && (mgcamd->ipoll>=0) && (mgcamd->handle==pfd[mgcamd->ipoll].fd) ) {
					if ( pfd[mgcamd->ipoll].revents & (POLLIN|POLLPRI) ) mgcamd_srv_accept(mgcamd);
				}
				mgcamd = mgcamd->next;
			}
#endif

#ifdef CS378X_SRV
			struct camd35_server_data *cs378x = cfg.cs378x.server;
			while (cs378x) {
				if ( !IS_DISABLED(cs378x->flags) && (cs378x->handle>0) && (cs378x->ipoll>=0) && (cs378x->handle==pfd[cs378x->ipoll].fd) ) {
					if ( pfd[cs378x->ipoll].revents & (POLLIN|POLLPRI) ) cs378x_srv_accept(cs378x);
				}
				cs378x = cs378x->next;
			}
#endif

#ifdef FREECCCAM_SRV
			if ( !IS_DISABLED(cfg.freecccam.server.flags) && (cfg.freecccam.server.handle>0) && (cfg.freecccam.server.ipoll>=0) && (cfg.freecccam.server.handle==pfd[cfg.freecccam.server.ipoll].fd) ) {
				if ( pfd[cfg.freecccam.server.ipoll].revents & (POLLIN|POLLPRI) ) freecccam_srv_accept( &cfg.freecccam.server );
			}
#endif

		}
		else if (retval<0) usleep(96000);
	}
	return NULL;
}

#endif

