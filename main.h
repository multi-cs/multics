
void cs_disconnect_cli(struct cs_client_data *cli);
void cs_senddcw_cli(struct cs_client_data *cli); // msgid is stored into ecm
void cs_getclimsg();


void disconnect_srv(struct server_data *srv);

// srv-cccam
#ifdef CCCAM_SRV
struct cccam_server_data *getcccamserverbyid(uint32_t id);
struct cc_client_data *getcccamclientbyid(uint32_t id);
struct cc_client_data *getcccamclientbyname(struct cccam_server_data *cccam, char *name);
void cc_disconnect_cli(struct cc_client_data *cli);
#endif

#ifdef MGCAMD_SRV
struct mgcamdserver_data *getmgcamdserverbyid(uint32_t id);
struct mg_client_data *getmgcamdclientbyid(uint32_t id);
struct mg_client_data *getmgcamdclientbyname(struct mgcamdserver_data *mgcamd, char *name);

void mg_disconnect_cli(struct mg_client_data *cli);
#endif

/*
void srv_cstatadd( struct server_data *srv, int csid, int ok); //, int ecmoktime)
void sidata_add(struct server_data *srv, uint8_t *nodeid, uint16_t caid, uint32_t prov, uint16_t sid,int val);
int sidata_update(struct server_data *srv, struct cardserver_data *cs, uint16_t caid, uint32_t prov, uint16_t sid,int val);
struct cs_card_data *srv_check_card( struct server_data *srv, uint16_t caid, uint32_t prov );
*/

struct cardserver_data *getcsbycaidprov( uint16_t caid, uint32_t prov);
struct cardserver_data *getcsbyid(uint32_t id);
struct cardserver_data *getcsbyport(int port);



void wakeup_sendecm();

char *src2string(int srctype, int srcid, char *ret);




////////////////////////////////////////////////////////////////////////////////
// ECM
////////////////////////////////////////////////////////////////////////////////

struct ecm_request *store_ecmdata(struct cardserver_data *cs,uint8_t *ecm,int ecmlen, unsigned short sid, unsigned short caid, unsigned int provid);

