
///////////////////////////////////////////////////////////////////////////////
// THREAD RESOLVE DNS
///////////////////////////////////////////////////////////////////////////////

void *dns_child_thread(struct host_data *host)
{
	unsigned int newip;

	pthread_mutex_lock(&prg.lockdns);
	newip = hostname2ip(host->name);
	pthread_mutex_unlock(&prg.lockdns);
	usleep(10000);
	if (!newip) {
		//mlogf(LOGDEBUG,0," dns: failed to get address for %s\n",host->name);
		host->checkiptime = getseconds() + 60;
		host->ip = newip;
	}
	else if (newip!=host->ip) {
		host->checkiptime = getseconds() + 300;
		host->ip = newip;
		//mlogf(LOGDEBUG,0," dns: %s --> %s\n", host->name, ip2string(host->ip));
	}
	else {
		host->checkiptime = getseconds() + 600;
		//mlogf(LOGDEBUG,0," dns: %s == %s\n", host->name, ip2string(host->ip));
	}
	return NULL;
}

void *dns_thread(void *param)
{
#ifndef PUBLIC
	prg.pid_dns = syscall(SYS_gettid);
	//prg.tid_dns = pthread_self();
	prctl(PR_SET_NAME,"Lookup",0,0,0);
#endif
	do {
		pthread_mutex_lock(&prg.lockdnsth);

		struct host_data *host = cfg.host;
		while (host) {
			if (host->checkiptime<=getseconds()) {
				//pthread_t new_tid;
				//create_thread(&new_tid, (threadfn)dns_child_thread,host);
				dns_child_thread( host );
			}
			host = host->next;
		}

		pthread_mutex_unlock(&prg.lockdnsth);
		sleep(10);
	} while (1);
	return NULL;
}


int start_thread_dns()
{
	create_thread(&prg.tid_dns, (threadfn)dns_thread,NULL);
	return 0;
}

