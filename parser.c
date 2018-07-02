#include "common.h"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdint.h>


#ifdef WIN32

#include <windows.h>

#else

#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <errno.h>

#endif

#include "parser.h"


char *uppercase(char *str)
{
	int i;
	for(i=0;;i++) {
		switch(str[i]) {
			case 'a'...'z':
				str[i] = str[i] - ('a'-'A');
				break;
			case 0:
				return str;
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
// PARSER FUNCTIONS
///////////////////////////////////////////////////////////////////////////////

char *iparser; // Current Parser Index

//Skip Spaces
void parse_spaces()
{
	while ( (*iparser==' ')||(*iparser=='\t') ) iparser++;
}


int charpos( char c, char *str )
{
	int i;
	int l = strlen(str);
	for(i=0; i<l; i++) if (c==str[i]) return i+1;
	return 0;
}

int parse_value(char *str, char *delimiters)
{
	int len;
	char *end;
	parse_spaces();
	end=iparser;
	while ( !charpos(*end,delimiters) && (*end!=0) ) end++;
	if ( (len=end-iparser)>0 ) {
		if (len>=255) len=255; // check for length
		memcpy(str, iparser, len);
		iparser = end;
	}
	str[len] = 0;
	return len;
}

int parse_str(char *str)
{
	int len;
	char *end;
	parse_spaces();
	end=iparser;
	while ( (*end!=0)&&(*end!=' ')&&(*end!='\t')&&(*end!=13)&&(*end!=10) ) end++;
	if ( (len=end-iparser)>0 ) {
		if (len>=255) len=255; // check for length
		memcpy(str, iparser, len);
		iparser = end;
	}
	str[len] = 0;
	return len;
}

int parse_name(char *str)
{
	int len;
	char *end;
	parse_spaces();
	end=iparser;
	while ( (*end!=0)&&(*end!=' ')&&(*end!='\t')&&(*end!=13)&&(*end!=10)&&(*end!=']')&&(*end!=':') ) end++;
	if ( (len=end-iparser)>0 ) {
		if (len>=255) len=255; // check for length
		memcpy(str, iparser, len);
		iparser = end;
	}
	str[len] = 0;
	return len;
}

int parse_boolean()
{
	char str[255];
	parse_value(str,"\r\n\t;,:]= ");
	if (!strcmp(str,"1")) return 1;
	else if (!strcmp(str,"0")) return 0;
	else {
		uppercase(str);
		if (!strcmp(str,"NO")) return 0;
		else if (!strcmp(str,"YES")) return 1;
		else if (!strcmp(str,"OFF")) return 0;
		else if (!strcmp(str,"ON")) return 1;
	}
	return 0; // Error
}

int parse_int(char *str)
{
	int len;
	char *end;
	parse_spaces();
	end=iparser;
	while ( (*end>='0')&&(*end<='9') ) end++;
	if ( (len=end-iparser)>0 ) {
		if (len>=255) len=255; // check for length
		memcpy(str, iparser, len);
		iparser = end;
	}
	str[len] = 0;
	return len;
}

int parse_hex(char *str)
{
	int len;
	char *end;
	parse_spaces();
	end=iparser;
	while ( ((*end>='0')&&(*end<='9'))||((*end>='A')&&(*end<='F'))||((*end>='a')&&(*end<='f')) ) end++;
	if ( (len=end-iparser)>0 ) {
		if (len>=255) len=255; // check for length
		memcpy(str, iparser, len);
		iparser = end;
	}
	str[len] = 0;
	return len;
}

int parse_bin(char *str)
{
	int len;
	char *end;
	parse_spaces();
	end=iparser;
	while ( (*end=='0')||(*end=='1') ) end++;
	if ( (len=end-iparser)>0 ) {
		if (len>=255) len=255; // check for length
		memcpy(str, iparser, len);
		iparser = end;
	}
	str[len] = 0;
	return len;
}

int parse_expect( char c )
{
	parse_spaces();
	if (*iparser==c) {
		iparser++;
		return 1;
	}
	else return 0;
}

int parse_quotes( char quote, char *str )
{
	str[0] = 0;
	parse_spaces();
	if (*iparser==quote) {
		iparser++;
		char *start = iparser;
		while ( (*iparser!=quote)&&(*iparser!='\n')&&(*iparser!='\r')&&(*iparser!=0) ) iparser++;
		if (*iparser==quote) {
			if (iparser-start) {
				*iparser = 0;
				strcpy( str, start );
				*iparser = quote;
				iparser++;
			}
			return 1;
		}
	}
	return 0;
}

