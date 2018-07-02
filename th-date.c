void* thread_enddate(void *param)
{
#ifndef PUBLIC
	prg.pid_date = syscall(SYS_gettid);
	prctl(PR_SET_NAME,"Expire Date Thread",0,0,0);
#endif
	while (!prg.restart) {
		pthread_mutex_lock(&prg.lockthreaddate);
		time_t nowtime = time(NULL);
		struct tm *nowtm = localtime(&nowtime);
		//strftime(buf, sizeof(buf), "%d %b %Y %H:%M", nowtm); printf(" Local Time = %s %d\n", buf, nowtm->tm_yday);

		int j = (nowtm->tm_mon<<16) | (nowtm->tm_mday<<8) | nowtm->tm_hour;
		// CCcam Clients
		struct cccam_server_data *cccam = cfg.cccam.server;
		while (cccam) {
			struct cc_client_data *cli = cccam->client;
			while (cli) {
				if (!(cli->flags&FLAG_DELETE)) {
					if (cli->enddate.tm_year) {
						int i = (cli->enddate.tm_mon<<16) | (cli->enddate.tm_mday<<8) | cli->enddate.tm_hour;
						//strftime(buf, sizeof(buf), "%d %b %Y %H:%M", &cli->enddate); printf(" Client End date = %s\n", buf);
						if (cli->flags&FLAG_EXPIRED) {
							if (cli->enddate.tm_year > nowtm->tm_year) {
								cli->flags &= ~FLAG_EXPIRED;
								mlogf(LOGINFO,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," CCcam%d: Client '%s' Enabled\n", cccam->id, cli->user);
							}
							else if (cli->enddate.tm_year==nowtm->tm_year) {
								if (i>j) {
									cli->flags &= ~FLAG_EXPIRED;
									mlogf(LOGINFO,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," CCcam%d: Client '%s' Enabled\n", cccam->id, cli->user);
								}
							}
						}
						else {
							if (cli->enddate.tm_year < nowtm->tm_year) {
								cli->flags |= FLAG_EXPIRED;
								if (cli->connection.status>0) cc_disconnect_cli( cli );
								mlogf(LOGINFO,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," CCcam%d: Client '%s' Expired\n", cccam->id, cli->user);
							}
							else if (cli->enddate.tm_year==nowtm->tm_year) {
								if (j>=i) {
									cli->flags |= FLAG_EXPIRED; // printf(" Client Disabled %s\n", cli->user);
									if (cli->connection.status>0) cc_disconnect_cli( cli );
									mlogf(LOGINFO,getdbgflag(DBG_CCCAM,cli->parent->id,cli->id)," CCcam%d: Client '%s' Expired\n", cccam->id, cli->user);
								}
							}
						}
					}
				}
				cli = cli->next;
			}
			cccam = cccam->next;
		}

		// MGcamd Clients
		// CCcam Clients
		struct mgcamdserver_data *mgcamd = cfg.mgcamd.server;
		while (mgcamd) {
			struct mg_client_data *cli = mgcamd->client;
			while (cli) {
				if (!(cli->flags&FLAG_DELETE)) {
					if (cli->enddate.tm_year) {
						//strftime(buf, sizeof(buf), "%d %b %Y %H:%M", &cli->enddate); printf(" Client End date = %s\n", buf);
						int i = (cli->enddate.tm_mon<<16) | (cli->enddate.tm_mday<<8) | cli->enddate.tm_hour;
						if (cli->flags&FLAG_EXPIRED) {
							if (cli->enddate.tm_year > nowtm->tm_year) {
								cli->flags &= ~FLAG_EXPIRED; //printf(" Client Enabled %s\n", cli->user);
								mlogf(LOGINFO,getdbgflag(DBG_MGCAMD,0,cli->id)," mgcamd%d: Client '%s' Enabled\n", mgcamd->id, cli->user);
							}
							else if (cli->enddate.tm_year==nowtm->tm_year) {
								if (i>j) {
									cli->flags &= ~FLAG_EXPIRED; //printf(" Client Enabled %s\n", cli->user);
									mlogf(LOGINFO,getdbgflag(DBG_MGCAMD,0,cli->id)," mgcamd%d: Client '%s' Enabled\n", mgcamd->id, cli->user);
								}
							}
						}
						else {
							if (cli->enddate.tm_year < nowtm->tm_year) {
								cli->flags |= FLAG_EXPIRED;
								if (cli->connection.status>0) mg_disconnect_cli(cli);
								mlogf(LOGINFO,getdbgflag(DBG_MGCAMD,0,cli->id)," mgcamd%d: Client '%s' Expired\n", mgcamd->id, cli->user);
							}
							else if (cli->enddate.tm_year==nowtm->tm_year) {
								if (j>=i) {
									cli->flags |= FLAG_EXPIRED;
									if (cli->connection.status>0) mg_disconnect_cli(cli);
									mlogf(LOGINFO,getdbgflag(DBG_MGCAMD,0,cli->id)," mgcamd%d: Client '%s' Expired\n", mgcamd->id, cli->user);
								}
							}
						}
					}
				}
				cli = cli->next;
			}
			mgcamd = mgcamd->next;
		}

		pthread_mutex_unlock(&prg.lockthreaddate);
		sleep(10);

#ifndef PUBLIC
		// TODO: Make loadaverage limit for restart a config file parameter
		//       For now I prefer increasing it to 100
		// check for load average
		FILE *fp = fopen ("/proc/loadavg", "r");
		if (fp) {
			float avg;
			int i = fscanf(fp, "%f", &avg);
			if (avg>100) {
				flag_debugfile = 1;
				mlogf(LOGCRITICAL, 0 , " Restart: Load average too high %01.2f\n", avg);
				prg.restart = 1;
			}
			fclose(fp);
		}
#endif

	}
	return NULL;
}

void start_thread_date()
{
	create_thread(&prg.tid_date, (threadfn)thread_enddate,NULL);
}

