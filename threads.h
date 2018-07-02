
typedef void*(*threadfn)(void*);

int create_thread( pthread_t *tid, threadfn func, void *arg);

