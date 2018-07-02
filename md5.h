#define MD5_DIGEST_LENGTH 16

unsigned char *MD5(const unsigned char *input, unsigned long len, unsigned char *output_hash);

char * __md5_crypt( const char *pw, const char *salt, char *passwd );
