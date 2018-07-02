///////////////////////////////////////////////////////////////////////////////
// PROTO
///////////////////////////////////////////////////////////////////////////////

void *rdgd_connect_cli_thread(void *param);
void rdgd_getclimsg();
uint rdgd_check_sendcw();


///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

void rdgd_senddcw_cli(struct rdgd_client_data *cli)
{
	unsigned char buf[CWS_NETMSGSIZE];

	if (cli->ecm.status==STAT_DCW_SENT) {
		mlogf(LOGWARNING,0, " +> cw send failed to radegast client (%s), cw already sent\n", ip2string(cli->ip));
		return;
	}
	if (cli->handle==INVALID_SOCKET) {
		mlogf(LOGWARNING,0, " +> cw send failed to radegast client (%s), client disconnected\n", ip2string(cli->ip));
		return;
	}
	if (!cli->ecm.busy) {
		mlogf(LOGWARNING,0, " +> cw send failed to radegast client (%s), no ecm request\n", ip2string(cli->ip));
		return;
	}

	ECM_DATA *ecm = getecmbyid(cli->ecm.id);
	if (ecm) {
		cli->ecm.lastcaid = ecm->caid;
		cli->ecm.lastprov = ecm->provid;
		cli->ecm.lastsid = ecm->sid;
		cli->ecm.lastdecodetime = GetTickCount()-cli->ecm.recvtime;
	}

	if ( ecm && (ecm->dcwstatus==STAT_DCW_SUCCESS) ) {
		cli->ecm.lastdcwsrctype = ecm->dcwsrctype;
		cli->ecm.lastdcwsrcid = ecm->dcwsrcid;
		cli->ecm.laststatus=1;
		cli->ecmok++;
		cli->ecmoktime += GetTickCount()-cli->ecm.recvtime;
		// Send DCW
		buf[0] = 0x02;
		buf[1] = 0x12;
		buf[2] = 0x05;
		buf[3] = 0x10;
		memcpy( &buf[4], ecm->cw, 16 );
		rdgd_message_send( cli->handle, buf, 0x14);
		mlogf(LOGINFO,0, " => cw to client (%s) ch %04x:%06x:%04x (%dms)\n", ip2string(cli->ip), ecm->caid,ecm->provid,ecm->sid, GetTickCount()-cli->ecm.recvtime);
		cli->lastdcwtime = GetTickCount();
	}
	else { //if (ecm->data->dcwstatus==STAT_DCW_FAILED)
		cli->ecm.laststatus=0;
		cli->ecm.lastdcwsrctype = DCW_SOURCE_NONE;
		cli->ecm.lastdcwsrcid = 0;
		buf[0] = 0x02;
		buf[1] = 0x02;
		buf[2] = 0x04;
		buf[3] = 0x00;
		rdgd_message_send( cli->handle, buf, 4);
		mlogf(LOGINFO,0, " |> decode failed to client (%s) ch %04x:%06x:%04x (%dms)\n", ip2string(cli->ip), ecm->caid,ecm->provid,ecm->sid, GetTickCount()-cli->ecm.recvtime);
	}
	cli->ecm.busy=0;
	cli->ecm.status = STAT_DCW_SENT;
}



///////////////////////////////////////////////////////////////////////////////

void rdgd_disconnect_cli(struct cardserver_data *cs,struct rdgd_client_data *cli)
{
	if (cli)
	if (cli->handle>0) {
		//pthread_mutex_lock(&prg.lockrdgdcli);
		mlogf(LOGINFO,0, " radegast: client (%s) disconnected\n", ip2string(cli->ip));
		close(cli->handle);
		// Remove
		struct rdgd_client_data *n = cs->radegast.client;
		if (n) {
			if (n==cli) {
				cs->radegast.client = n->next;
				free(cli);
			}
			else {
				while (n->next) {
					if (cli==n->next) {
						n->next = n->next->next;
						free(cli);
						break;
					}
					n = n->next;
				}
			}
		}
		//pthread_mutex_unlock(&prg.lockrdgdcli);
	}
}


void *rdgd_connect_cli_thread(void *param)
{
	int clientsock;
	struct sockaddr_in clientaddr;
	socklen_t socklen = sizeof(struct sockaddr);

	while (1) {
		pthread_mutex_lock(&prg.lockrdgdsrv);

		struct pollfd pfd[MAX_CSPORTS];
		int pfdcount = 0;

		struct cardserver_data *cs = cfg.cardserver;
		while(cs) {
			if (cs->radegast.handle>0) {
				cs->radegast.ipoll = pfdcount;
				pfd[pfdcount].fd = cs->radegast.handle;
				pfd[pfdcount++].events = POLLIN | POLLPRI;
			} else cs->radegast.ipoll = -1;
			cs = cs->next;
		}

		int retval = poll(pfd, pfdcount, 3013);

		if (retval>0) {
			struct cardserver_data *cs = cfg.cardserver;
			while(cs) {
				if ( (cs->radegast.handle>0) && (cs->radegast.ipoll>=0) && (cs->radegast.handle==pfd[cs->radegast.ipoll].fd) ) {
					if ( pfd[cs->radegast.ipoll].revents & (POLLIN|POLLPRI) ) {
						clientsock = accept(cs->radegast.handle, (struct sockaddr*)&clientaddr, &socklen );
						if (clientsock<0) {
							if (errno == EAGAIN || errno == EINTR) continue;
							else {
								mlogf(LOGERROR,0, " Radegast: Accept failed (errno=%d)\n",errno);
								usleep(1000);
							}
						}
						else {
							SetSocketKeepalive(clientsock);
							SetSocketNoDelay(clientsock);
							SetSoketNonBlocking(clientsock);
							// ADD TO DB
							struct rdgd_client_data *cli = malloc( sizeof(struct rdgd_client_data) );
							memset( cli, 0, sizeof(struct rdgd_client_data) );
							cli->chkrecvtime = 0;
							cli->handle = clientsock; 
							cli->ip = clientaddr.sin_addr.s_addr;
							pthread_mutex_lock(&prg.lockrdgdcli);
							cli->next = cs->radegast.client;
							cs->radegast.client = cli;
							mlogf(LOGERROR,0, " radegast: client (%s) connected\n", ip2string(cli->ip));
							pthread_mutex_unlock(&prg.lockrdgdcli);
							pipe_wakeup( prg.pipe.ecm[1] );
						}
					}
				}
				cs = cs->next;
			}
		}
		pthread_mutex_unlock(&prg.lockrdgdsrv);
		usleep(3000);
	}
	END_PROCESS = 1;
}



void rdgd_store_ecmclient(struct cardserver_data *cs, ECM_DATA *ecm, struct rdgd_client_data *cli)
{
	cli->ecm.recvtime = GetTickCount();
	cli->ecm.request = ecm;
    cli->ecm.status = STAT_ECM_SENT;
	ecm_addip(ecm, cli->ip);
}

int accept_ecm (struct cardserver_data *cs, uint16_t caid, uint32_t provid, uint16_t sid)
{
	// Check for caid, accept caid=0
	if ( !accept_caid(cs,caid) ) return 0;

	// Check for provid, accept provid==0
	if ( !accept_prov(cs,provid) ) return 0;

	// Check for Accepted sids
	if ( !accept_sid(cs,sid) ) return 0;

	return 1;
}


void rdgd_cli_recvmsg(struct rdgd_client_data *cli, struct cardserver_data *cs)
{
	int len;
	unsigned char buf[300];
	int i;

	if (cli->handle>0) {
		len = rdgd_check_message(cli->handle);
		if (len==0) {
			mlogf(LOGERROR,0, " radegast: client (%s) read failed %d\n", ip2string(cli->ip),len);
			rdgd_disconnect_cli(cs,cli);
		}
		else if (len==-1) {
			if (!cli->chkrecvtime) cli->chkrecvtime = GetTickCount();
			else if ( (cli->chkrecvtime+300)<GetTickCount() ) {
				mlogf(LOGERROR,0, " radegast: client (%s) read failed %d\n", ip2string(cli->ip),len);
				rdgd_disconnect_cli(cs,cli);
			}
		}
		else if (len>0) {
			cli->chkrecvtime = 0;
			len = rdgd_message_receive(cli->handle, buf, 0);
			if (len==0) {
				mlogf(LOGERROR,0, " radegast: client (%s) read failed %d\n", ip2string(cli->ip),len);
				rdgd_disconnect_cli(cs,cli);
			}
			else if (len<0) {
				mlogf(LOGERROR,0, " radegast: client '%s' read failed %d(%d)\n", ip2string(cli->ip),len,errno);
				rdgd_disconnect_cli(cs,cli);
			}
			else if (len>0) switch ( buf[0] ) {
				case 0x01: // ECM
					cli->lastecmtime = GetTickCount();
					cli->ecmnb++;
					cli->ecm.id = -1; // ECM DENIED
					if (cli->ecm.busy) {
						cli->ecmdenied++;
						rdgd_senddcw_cli(cli);
						break;
					}
					uint16_t caid = 0;
					uint32_t provid = 0;
					unsigned char ecmdata[300];
					memset(ecmdata, 0, sizeof(ecmdata));
					int ecmlen=0;
					int index = 2;
					while (index<len) {
						//entry = buf[index];	
						//len = buf[index+1];
					    switch (buf[index]) {
							case  2: // CAID (upper byte only, oldstyle)
								caid = buf[index+2]<<8;
								break;
							case 10: // CAID
								caid = (buf[index+2]<<8) | buf[index+3];
								break;
							case  3: // ECM DATA
								ecmlen = buf[index+1];
								memcpy( ecmdata, &buf[index+2], ecmlen);
								break;
							case  6: // PROVID (ASCII)
								for (i=0; i<buf[index+1]; i++) provid = (provid<<4) | hexvalue(buf[index+2+i]);
								//provid = hex2int(char *src); // 6
								break;
							case  7: // KEYNR (ASCII), not needed
								break;
							case  8: // ECM PROCESS PID ?? don't know, not needed
								break;
						}
						index += buf[index+1]+2;
					}

					if (!accept_ecm(cs,caid,provid,0)) {
						rdgd_senddcw_cli(cli);
						break;
					}

					// ACCEPTED
					pthread_mutex_lock(&prg.lockecm); //###

					// Search for ECM
					int ecmid = search_ecmdata_dcw( ecmdata,  ecmlen, 0); // dont get failed ecm request from cache
					if ( ecmid!=-1 ) {
						ECM_DATA *ecm=getecmbyid(ecmid);
						ecm->lastrecvtime = GetTickCount();
						//TODO: Add another card for sending ecm
						rdgd_store_ecmclient(cs, ecmid, cli);
						mlogf(LOGINFO,0, " <- ecm from client (%s) ch %04x:%06x:%04x*\n", ip2string(cli->ip), caid, provid, 0);
						cli->ecm.busy=1;
						cli->ecm.hash = ecm->hash;
					}
					else {
						cs->ecmaccepted++;
						// Setup ECM Request for Server(s)
						ecmid = store_ecmdata(cs, ecmdata, ecmlen, 0, caid, provid);
						ECM_DATA *ecm=getecmbyid(ecmid);
						rdgd_store_ecmclient(cs, ecmid, cli);
						mlogf(LOGINFO,0, " <- ecm from client (%s) ch %04x:%06x:%04x\n", ip2string(cli->ip), caid, provid, 0);
						cli->ecm.busy=1;
						cli->ecm.hash = ecm->hash;
						if (cs->option.fallowcache && cfg.cache.peer) {
							ecm->waitcache = 1;
							ecm->dcwstatus = STAT_DCW_WAITCACHE;
							ecm->checktime = ecm->recvtime + cs->option.cachetimeout;
							pipe_cache_find(ecm, cs);
						} else ecm->dcwstatus = STAT_DCW_WAIT;
					}
					pthread_mutex_unlock(&prg.lockecm); //###
					wakeup_sendecm();
					break;

				default:
					buf[0] = 0x81;
					buf[1] = 0;
					rdgd_message_send(cli->handle,buf,2);
					//radegast_send(answer);
					//cs_log("unknown request %02X, len=%d", buf[0], buf[1]);
			}
		}
	}
}


// Check sending cw to clients
uint rdgd_check_sendcw()
{
	struct cardserver_data *cs = cfg.cardserver;
	uint restime = GetTickCount() + 10000;
	uint clitime = 0;

	while (cs) {
		if (cs->radegast.handle>0) {
			struct rdgd_client_data *cli = cs->radegast.client;
			uint32_t ticks = GetTickCount();
			while (cli) {
				if ( (cli->handle>0)&&(cli->ecm.busy) ) {
					clitime = ticks+11000;
					// Check for DCW ANSWER
					ECM_DATA *ecm = getecmbyid(cli->ecm.id);
					if (ecm) {
						// Check for FAILED
						if (ecm->dcwstatus==STAT_DCW_FAILED) rdgd_senddcw_cli( cli );
						// Check for SUCCESS
						else if (ecm->dcwstatus==STAT_DCW_SUCCESS) rdgd_senddcw_cli( cli );
						// check for timeout
						else if ( (cli->ecm.recvtime+cs->option.dcw.timeout) < ticks ) rdgd_senddcw_cli( cli ); else clitime = cli->ecm.recvtime+cs->option.dcw.timeout;
					}
					else rdgd_senddcw_cli( cli ); // failed
					if (restime>clitime) restime = clitime;
				}
				cli = cli->next;
			}
		}
		cs = cs->next;
	}
	return (restime+1);
}

