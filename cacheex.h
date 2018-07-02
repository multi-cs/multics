
int pipe_send_cacheex_reply(ECM_DATA *ecm);
struct cache_data *cacheex_new( struct cache_data *newdata );
struct cache_data *cacheex_fetch( struct cache_data *thereq );
inline int cacheex_acceptshare( struct sharelimit_data sharelimits[100], uint16_t caid, uint32_t provid);
void cc_cachex_prevdcw(ECM_DATA *ecm, struct server_data *srv );
int start_thread_cacheex();
inline int cacheex_check( struct cache_data *req );
int pipe_send_cacheex_push_out(ECM_DATA *ecm);

