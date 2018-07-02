
#ifndef WIN32

extern struct timeval startime;

uint64_t GetTickCount();
unsigned int GetuTickCount();
unsigned int GetTicks(struct timeval *tv);
unsigned int getseconds();

#endif


struct table_average {
	uint32_t tab[100];
	int itab;
};

void tabavg_init(struct table_average *t);
void tabavg_add(struct table_average *t, uint32_t value);
uint32_t tabavg_get(struct table_average *t);

int epoll_add( int epfd, int fd, void *ptr);

