
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
int twin_init()
{
	// Set up Serial Port
	if (serial_init(cfg.twin.serial.device,B115200 | CS8 | CLOCAL | CSTOPB | CREAD,&cfg.twin.serial.handle)==-1) {
		mlogf(LOGERROR,0, " Error initializing serial device '%s'\n", cfg.twin.serial.device);
		return -1;
	} else serial_purge(cfg.twin.serial.handle);
	mlogf(LOGINFO,0, " serial device '%s' opened.\n",cfg.twin.serial.device);
	return 0;
}

int twin_done()
{	
  serial_done(cfg.twin.serial.handle);
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

int twin_send(int chn, uint8_t* cw)
{
	uint8_t wbuf[32]; // write
	uint8_t rbuf[32]; // read
	int rlen;

	memset( cw, 0, 16);

	wbuf[0] = 7;
	wbuf[1] = 6;
	wbuf[2] = cfg.twin.chninfo.data[chn].deg>>8;
	wbuf[3] = cfg.twin.chninfo.data[chn].deg&0xff;
	wbuf[4] = cfg.twin.chninfo.data[chn].freq>>8;
	wbuf[5] = cfg.twin.chninfo.data[chn].freq&0xfc;
	wbuf[6] = cfg.twin.chninfo.data[chn].sid>>8;
	wbuf[7] = cfg.twin.chninfo.data[chn].sid&0xff;
	wbuf[8] = wbuf[0]^wbuf[1]^wbuf[2]^wbuf[3]^wbuf[4]^wbuf[5]^wbuf[6]^wbuf[7];

	serial_purge(cfg.twin.serial.handle);
	usleep(20000);

	serial_write(cfg.twin.serial.handle, wbuf, 9);
	usleep(20000);

	memset(rbuf,0,19);
	rlen = serial_readt(cfg.twin.serial.handle, 300, 1000, 19, rbuf);
	if ( (rlen!=19)||(rbuf[0]!=0xF7)||(rbuf[1]!=0x00)||(rbuf[2]!=0x16) )
	{
		char str[512];
		array2hex( rbuf, str, rlen);
		mlogf(LOGWARNING,0, " ch %04x:%06x:%04x, Invalid packet from dongle (%s)\n", cfg.twin.chninfo.data[chn].caid, cfg.twin.chninfo.data[chn].prov, cfg.twin.chninfo.data[chn].sid, str );
		return 0;
	}
	rbuf[6] = rbuf[3]+rbuf[4]+rbuf[5];
	rbuf[10] = rbuf[7]+rbuf[8]+rbuf[9];
	rbuf[14] = rbuf[11]+rbuf[12]+rbuf[13];
	rbuf[18] = rbuf[15]+rbuf[16]+rbuf[17];
	memcpy(cw, rbuf+3, 16);
	return 16;
}
/*
struct channel_info_data *twin_getchannel(uint16_t caid, uint32_t prov, uint16_t sid)
{
	int i;
	for(i=0; i<cfg.twin.chninfo.count; i++)
		if ( (cfg.twin.chninfo.data[i].caid==caid)&&(cfg.twin.chninfo.data[i].prov==prov)&&(cfg.twin.chninfo.data[i].sid==sid) ) return &(cfg.twin.chninfo.data[i]);
	}
	return NULL;
}
*/
void *thread_twin()
{
	int chn;
	uint8_t cw[16];
	uint8_t nullcw[16] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

	if ( twin_init()==-1 ) return NULL;

	while (1) {
		for(chn=0; chn<cfg.twin.chninfo.count; chn++) {
			uint32_t ticks = GetTickCount();
			if ( !cfg.twin.chninfo.data[chn].ecm.rtime ) continue;
			if ( (cfg.twin.chninfo.data[chn].ecm.rtime+2500) > ticks ) continue;
			if ( (cfg.twin.chninfo.data[chn].ecm.rtime+8000) < ticks ) continue;

			if ( !twin_send(chn,cw) ) {
 				if ( !twin_send(chn,cw) ) continue;
			}

			if ( !acceptcw(cw) ) {
				//cfg.twin.chninfo.data[chn].ecm.error++;
				//mlogf(LOGDEBUG,0, " ? chn %04x:%06x:%04x:%s invalid channel '%s'\n", cfg.twin.chninfo.data[chn].caid, cfg.twin.chninfo.data[chn].prov, cfg.twin.chninfo.data[chn].sid, cfg.twin.chninfo.data[chn].name);
				continue;
			}

			char str[512];
			array2hex( cw, str, 16);
			//mlogf(LOGDEBUG,0, "  chn %04x:%06x:%04x:%s\n", cfg.twin.chninfo.data[chn].caid, cfg.twin.chninfo.data[chn].prov, cfg.twin.chninfo.data[chn].sid, str);

//			pthread_mutex_lock(&cfg.lockchn);

			if (cfg.twin.chninfo.data[chn].ecm.rtime) { // maybe changed !!!
				if (cfg.twin.chninfo.data[chn].ecm.cwcycle==0x80) {
					if ( memcmp( cfg.twin.chninfo.data[chn].ecm.prevcw, cw, 8) && !memcmp( cfg.twin.chninfo.data[chn].ecm.prevcw+8, cw+8, 8) ) {
						mlogf(LOGINFO,0, " -> CW0 Cycle chn '%s' %04x:%06x:%04x:%s\n", cfg.twin.chninfo.data[chn].name, cfg.twin.chninfo.data[chn].caid, cfg.twin.chninfo.data[chn].prov, cfg.twin.chninfo.data[chn].sid, str);
						cfg.twin.chninfo.data[chn].ecm.rtime = 0;
						//cacheex_push( &cfg.twin.chninfo.data[chn], cw);
						memcpy( cfg.twin.chninfo.data[chn].ecm.cw, cw, 16);
					}
				}
				else if (cfg.twin.chninfo.data[chn].ecm.cwcycle==0x81) {
					if ( !memcmp( cfg.twin.chninfo.data[chn].ecm.prevcw, cw, 8) && memcmp( cfg.twin.chninfo.data[chn].ecm.prevcw+8, cw+8, 8) ) {
						mlogf(LOGINFO,0, " -> CW1 Cycle chn '%s' %04x:%06x:%04x:%s\n", cfg.twin.chninfo.data[chn].name, cfg.twin.chninfo.data[chn].caid, cfg.twin.chninfo.data[chn].prov, cfg.twin.chninfo.data[chn].sid, str);
						cfg.twin.chninfo.data[chn].ecm.rtime = 0;
						//cacheex_push( &cfg.twin.chninfo.data[chn], cw);
						memcpy( cfg.twin.chninfo.data[chn].ecm.cw, cw, 16);
					}
				}
			}

//			pthread_mutex_unlock(&cfg.lockchn);
		}
	}

	twin_done();

	return NULL;
}


