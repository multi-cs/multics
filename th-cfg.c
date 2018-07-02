
///////////////////////////////////////////////////////////////////////////////
// THREAD REREAD CONFIG
///////////////////////////////////////////////////////////////////////////////

#ifdef INOTIFY
#include "inotify/inotify.h"
#include "inotify/inotify-syscalls.h"
#else
#include <sys/inotify.h>
#endif
/*
static void displayInotifyEvent(struct inotify_event *i)
{
    printf("    wd =%2d; ", i->wd);
    if (i->cookie > 0)
        printf("cookie =%4d; ", i->cookie);

    printf("mask = ");
    if (i->mask & IN_ACCESS)        printf("IN_ACCESS ");
    if (i->mask & IN_ATTRIB)        printf("IN_ATTRIB ");
    if (i->mask & IN_CLOSE_NOWRITE) printf("IN_CLOSE_NOWRITE ");
    if (i->mask & IN_CLOSE_WRITE)   printf("IN_CLOSE_WRITE ");
    if (i->mask & IN_CREATE)        printf("IN_CREATE ");
    if (i->mask & IN_DELETE)        printf("IN_DELETE ");
    if (i->mask & IN_DELETE_SELF)   printf("IN_DELETE_SELF ");
    if (i->mask & IN_IGNORED)       printf("IN_IGNORED ");
    if (i->mask & IN_ISDIR)         printf("IN_ISDIR ");
    if (i->mask & IN_MODIFY)        printf("IN_MODIFY ");
    if (i->mask & IN_MOVE_SELF)     printf("IN_MOVE_SELF ");
    if (i->mask & IN_MOVED_FROM)    printf("IN_MOVED_FROM ");
    if (i->mask & IN_MOVED_TO)      printf("IN_MOVED_TO ");
    if (i->mask & IN_OPEN)          printf("IN_OPEN ");
    if (i->mask & IN_Q_OVERFLOW)    printf("IN_Q_OVERFLOW ");
    if (i->mask & IN_UNMOUNT)       printf("IN_UNMOUNT ");
    printf("\n");

    if (i->len > 0)
        printf("        name = %s\n", i->name);
}
*/

void *reread_config_thread(void *param)
{
#ifndef PUBLIC
	prg.pid_cfg = syscall(SYS_gettid);
	//prg.tid_cfg = pthread_self();
	prctl(PR_SET_NAME,"Config Thread",0,0,0);
#endif
	init_config(&cfg);
	read_config(&cfg);
	usleep(100000);
	check_config(&cfg);
	cfg_set_id_counters(&cfg);

	int fd = inotify_init(); //1(IN_NONBLOCK);
	while (1) {

		struct filename_data *fs = cfg.files;
		while (fs) {
			if (!fs->nowatch) fs->wd = inotify_add_watch(fd,fs->name, IN_CLOSE_WRITE|IN_IGNORED);
			fs = fs->next;
		}

		struct inotify_event *event;
		char buf[1024];
		int changed = 0;

		do {
			int len = read(fd,buf,1024);
			int i = 0;
			while (i<len) {
				event = (struct inotify_event *) &buf[i];
				struct filename_data *fs = cfg.files;
				while (fs) {
					if (!fs->nowatch)
					if (event->wd==fs->wd) {
						if (event->mask & IN_CLOSE_WRITE) changed = 1;
			            if (event->mask & IN_IGNORED) {
							inotify_rm_watch(fd, fs->wd);
							fs->wd = inotify_add_watch(fd,fs->name, IN_CLOSE_WRITE|IN_IGNORED);
						}
						break;
					}
					fs = fs->next;
				}				
				i += sizeof(struct inotify_event) + event->len;
			}
			usleep(30000);
	    } while (!changed);

		if (changed) {
			mlogf(LOGWARNING,getdbgflag(DBG_CONFIG,0,0)," Config file Changed...\n");
			struct filename_data *fs = cfg.files;
			while (fs) {
				if (!fs->nowatch) inotify_rm_watch(fd, fs->wd);
				fs = fs->next;
			}
			free_filenames( &cfg );
			reread_config(&cfg);
			sleep(1);
			check_config(&cfg);
			cfg_set_id_counters(&cfg);
		}
	}
	return NULL;
}


int start_thread_config()
{
	create_thread(&prg.tid_cfg, (threadfn)reread_config_thread,NULL);
	return 0;
}

