void rdg_getsrvmsg();

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

int rdgd_connect_srv(struct server_data *srv, int fd)
{
	static char msg[]= "Connected";
	uint8_t buf[10];
	if ( recv_nonb(fd, buf, 10,0)==0 ) {
		static char msg[]= "Server not connected";
		srv->statmsg = msg;
		return -1;
	}
	mlogf(LOGINFO,getdbgflag(DBG_SERVER,0,srv->id)," radegast: connect to server (%s:%d)\n", srv->host->name, srv->port);
	srv->statmsg = msg;
	srv->connection.status = 1;
	srv->connection.time = GetTickCount();
	srv->keepalive.time = GetTickCount();
	srv->keepalive.status = 0;
	srv->busy = 0;
	srv->lastecmoktime = 0;
	srv->lastecmtime = 0;
	srv->lastdcwtime = 0;
	srv->chkrecvtime = 0;
	srv->handle = fd;
#ifdef EPOLL_ECM
	pipe_pointer( prg.pipe.ecm[1], PIPE_SRV_CONNECTED, srv );
#else
	pipe_cmd( prg.pipe.ecm[1], PIPE_SRV_CONNECTED );
#endif
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
//01 3E 020101 06083030303030303330 070430303036 080102 0A020100 0322 80 001F D4 AB B2 CD C6 9B B4 54 11 0E 82 74 41 21 3D DC 87 70 E9 3E A1 41 E1 FC 67 3E 01 7E 97 EA DC 
int rdgd_sendecm_srv(struct server_data *srv, ECM_DATA *ecm)
{
	unsigned char buf[CWS_NETMSGSIZE];
	buf[0] = 0x01;
	//buf[1] = len;
	int index = 2;
	//Caid Byte Entry
	buf[index]=2; buf[index+1]=1;
	buf[index+2] = ecm->caid>>8;
	index+=3;
	//ProvID Entry
	buf[index]=6; buf[index+1]=8;
	hex32(ecm->provid, (char*)&buf[index+2]);
	index+=10;
	//KeyNo Entry
	buf[index]=7; buf[index+1]=4;
	buf[index+2]=0x30; buf[index+3]=0x30; buf[index+4]=0x30; buf[index+5]=0x36;
	index+=6;
	//Ecm process pid entry
	buf[index]=8; buf[index+1]=1;
	buf[index+2] = 2;
	index+=3;
	//Caid entry
	buf[index]=0x0A; buf[index+1]=2;
	buf[index+2] = ecm->caid>>8; buf[index+3] = ecm->caid & 0xff;
	index+=4;
	//Ecm entry
	buf[index]=3; buf[index+1]=ecm->ecmlen;
	memcpy(&buf[index+2],ecm->ecm, ecm->ecmlen);
	index += 2+ecm->ecmlen;
	buf[1] = index-2;
	return rdgd_message_send(srv->handle, buf, index);
}	


///////////////////////////////////////////////////////////////////////////////

void rdgd_srv_recvmsg(struct server_data *srv)
{
	int len;
	ECM_DATA *ecm;
	unsigned char buf[CWS_NETMSGSIZE];

	if (srv->handle>0)
	if (srv->type==TYPE_RADEGAST) {
		len = rdgd_check_message(srv->handle);
		if (len==0) {
			mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," radegast: server (%s:%d) read failed %d\n", srv->host->name, srv->port, len);
			disconnect_srv(srv);
		}
		else if (len==-1) {
			if (!srv->chkrecvtime) srv->chkrecvtime = GetTickCount();
			else if ( (srv->chkrecvtime+300)<GetTickCount() ) {
				mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," radegast: server (%s:%d) read failed %d\n", srv->host->name, srv->port, len);
				disconnect_srv(srv);
			}
		}
		else if (len>0) {
			srv->chkrecvtime = 0;
			len = rdgd_message_receive(srv->handle, buf, 3);
			if (len==0) {
				mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," radegast: server (%s:%d) read failed %d\n", srv->host->name, srv->port, len);
				disconnect_srv(srv);
			}
			else if (len<0) {
				mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," radegast: server (%s:%d) read failed %d(%d)\n", srv->host->name, srv->port, len, errno);
				disconnect_srv(srv);
			}
			else if (len>0) {
				switch ( buf[0] ) {
				case 0x02: // DCW
					srv->lastdcwtime = GetTickCount();
					if (!srv->busy) {
						mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," [!] dcw error from server (%s:%d), unknown ecm request\n",srv->host->name,srv->port);
						break;
					}
					srv->busy = 0;
					pipe_cmd( prg.pipe.ecm[1], PIPE_SRV_AVAILABLE );

					pthread_mutex_lock(&prg.lockecm); //###

					ecm = srv->ecm.request;
					if (!ecm) {
						mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," [!] dcw error from server (%s:%d), ecm not found!!!\n",srv->host->name,srv->port);
						pthread_mutex_unlock(&prg.lockecm); //###
						break;
					}
					// check for ECM???
					if (ecm->hash!=srv->ecm.hash) {
						mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," [!] dcw error from server (%s:%d), ecm deleted!!!\n",srv->host->name,srv->port);
						pthread_mutex_unlock(&prg.lockecm); //###
						break;
					}

					if ( (buf[1]==0x12)&&(buf[2]==0x05)&&(buf[3]==0x10) ) {
						// Check for DCW
						struct cardserver_data *cs=ecm->cs;
						int isnanoe0=ecm_isnanoe0(ecm->ecm,ecm->caid);
						if ( isnanoe0 )
							mlogf(LOGDEBUG,getdbgflag(DBG_SERVER,0,srv->id)," [!] viaccess nano e0 detected ch %04x:%06x:%04x\n",ecm->caid, ecm->provid, ecm->sid);

						if (!acceptDCW(&buf[4], isnanoe0)) {
							mlogf(LOGINFO,getdbgflag(DBG_SERVER,0,srv->id)," [!] dcw error from radegast server (%s:%d), bad dcw!!! ch %04x:%06x:%04x nanoe0=%d\n",srv->host->name,srv->port,ecm->caid, ecm->provid, ecm->sid, isnanoe0);
							srv->ecmerrdcw ++;
							pthread_mutex_unlock(&prg.lockecm); //###
							break;
						}
						srv->ecmok++;
						srv->ecmoktime += GetTickCount()-srv->lastecmtime;
						srv->lastecmoktime = GetTickCount()-srv->lastecmtime;

						ecm_setsrvflagdcw(srv->ecm.request, srv->id, ECM_SRV_REPLY_GOOD, &buf[4]);
						mlogf(LOGINFO,getdbgflag(DBG_SERVER,0,srv->id)," <= cw from server (%s:%d) ch %04x:%06x:%04x (%dms)\n", srv->host->name,srv->port, ecm->caid,ecm->provid,ecm->sid, GetTickCount()-srv->lastecmtime);

						if (ecm->dcwstatus!=STAT_DCW_SUCCESS) {
							static char msg[] = "Good dcw from Radegast server";
							ecm->statusmsg = msg;
							// Store ECM Answer
							ecm_setdcw( ecm, &buf[4], DCW_SOURCE_SERVER, srv->id );
						}
						else {	//TODO: check same dcw between cards
							srv->ecmerrdcw ++;
							if ( memcmp(&ecm->cw, &buf[3],16) ) mlogf(LOGWARNING,getdbgflag(DBG_SERVER,0,srv->id)," !!! different dcw from server (%s:%d)\n",srv->host->name,srv->port);
						}
#ifdef SID_FILTER
						// ADD IN SID LIST
						//struct cardserver_data *cs=ecm->cs;
						if (cs) {
							cardsids_update( srv->busycard, ecm->provid, ecm->sid, 1);
							srv_cstatadd( srv, cs->id, 1 , srv->lastecmoktime);
						}
#endif
						pthread_mutex_unlock(&prg.lockecm); //###
					}
					else {
						struct cardserver_data *cs=ecm->cs;
						if ( cs && (ecm->dcwstatus!=STAT_DCW_SUCCESS) && (srv->retry<cs->option.retry.radegast) ) {
							if ( (GetTickCount()-ecm->recvtime) < (cs->option.server.timeout*ecm->period) )
							if (rdgd_sendecm_srv(srv, ecm)>0) {
								srv->retry++;
								ecm->lastsendtime = GetTickCount();
								mlogf(LOGINFO,getdbgflag(DBG_SERVER,0,srv->id)," (RE) -> ecm to server (%s:%d) ch %04x:%06x:%04x\n",srv->host->name,srv->port,ecm->caid,ecm->provid,ecm->sid);
								srv->lastecmtime = GetTickCount();
								srv->ecmnb++;
								srv->busy=1;
								//srv->busyecm = ecm;
								pthread_mutex_unlock(&prg.lockecm); //###
								break;
							}
						}
						ecm_setsrvflag(srv->ecm.request, srv->id, ECM_SRV_REPLY_FAIL);
						mlogf(LOGINFO,getdbgflag(DBG_SERVER,0,srv->id)," <| decode failed from server (%s:%d) ch %04x:%06x:%04x (%dms)\n", srv->host->name,srv->port, ecm->caid,ecm->provid,ecm->sid, GetTickCount()-srv->lastecmtime);
#ifdef SID_FILTER
						// ADD IN SID LIST
						if (cs) {
							cardsids_update( srv->busycard, ecm->provid, ecm->sid, -1);
							srv_cstatadd( srv, cs->id, 0 , 0);
						}
#endif
						pthread_mutex_unlock(&prg.lockecm); //###
						wakeup_sendecm();
					}
					break;

				default:
					buf[0] = 0x81;
					buf[1] = 0;
					rdgd_message_send(srv->handle,buf,2);
				}
			}

		}
	}
}

