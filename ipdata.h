
#ifdef IPLIST

struct ip_hacker_data {
	struct ip_hacker_data *next;
	uint32_t ip;
	char user[256]; // connected with user???
	uint32_t lastseen;
	int nblogin; // total number of successful failed connections
	int dropped; // in iptables
};


struct ip_hacker_data *iplist_find( struct ip_hacker_data *iplist, uint32_t ip );

struct ip_hacker_data *iplist_add( uint32_t ip );

void iplist_newlogin( struct ip_hacker_data *iplist );

void iplist_goodlogin( struct ip_hacker_data *iplist );

int iplist_accept( struct ip_hacker_data *iplist );

#endif
