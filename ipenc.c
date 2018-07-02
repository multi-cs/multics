#include "common.h"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdint.h>


#ifdef WIN32

#include <windows.h>
#include <sys/types.h>

#else

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <errno.h>

#endif

#include "iplock.c"


#define IMAGE_VIRT_OFS    0x00000000004020e0
#define IMAGE_FILE_OFS    0x000020e0

#define DATA_VIRT_OFS     0x452ff0
#define DATA_SIZE         9760

int main()
{

	uint8_t pass[4] = { 1, 2, 3, 4 };

	FILE *fhandle;
	fhandle=fopen("x/multics", "r+");
	if (fhandle==0) return 0;


	
	uint8_t *buf = malloc(DATA_SIZE);

	fseek ( fhandle , (DATA_VIRT_OFS-IMAGE_VIRT_OFS) + IMAGE_FILE_OFS , SEEK_SET );
	fread ( buf, 1, DATA_SIZE, fhandle );

	message_encrypt( buf, DATA_SIZE, pass );

	fseek ( fhandle , (DATA_VIRT_OFS-IMAGE_VIRT_OFS) + IMAGE_FILE_OFS , SEEK_SET );
	fwrite ( buf, 1, DATA_SIZE, fhandle );

	fclose(fhandle);
}

