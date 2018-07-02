extern struct config_data cfg;
extern struct program_data prg;

extern int END_PROCESS;

char *getchname(uint16_t caid, uint32_t prov, uint16_t sid );

void *http_thread(void *param);

int start_thread_http();

int isblockedip(uint32_t ip);

int total_mgcamd_servers();
void total_mgcamd_clients( int *total, int *connected, int *active );
void mgcamd_clients( struct mgcamdserver_data *mgcamd, int *total, int *connected, int *active );

void cccam_clients( struct cccam_server_data *cccam, int *total, int *connected, int *active );
void total_cccam_clients( struct config_data *cfg, int *total, int *connected, int *active );
int total_cccam_servers();

