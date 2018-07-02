//Don't pack structs on ARM processors like RPI. It causes unaligned access exceptions
#ifdef NOPACK
#define PACK
#else
#define PACK __attribute__ ((__packed__))
#endif

// CCcam Cryptage Functions

struct cc_crypt_block
{
	uint8_t keytable[256];
	uint8_t state;
	uint8_t counter;
	uint8_t sum;
} PACK;



void cc_crypt_swap(unsigned char *p1, unsigned char *p2);
void cc_crypt_init( struct cc_crypt_block *block, uint8_t *key, int len);
void cc_crypt_xor(uint8_t *buf);
void cc_decrypt(struct cc_crypt_block *block, uint8_t *data, int len);
void cc_encrypt(struct cc_crypt_block *block, uint8_t *data, int len);
void cc_crypt_cw(uint8_t *nodeid, uint32_t card_id, uint8_t *cws);


// CCcam Connection Functions

#define CC_MAXMSGSIZE	2048

typedef enum
{
  CC_MSG_CLI_INFO,			// client -> server
  CC_MSG_ECM_REQUEST,		// client -> server
  CC_MSG_EMM_REQUEST,		// client -> server
  CC_MSG_CARD_DEL = 4,		// server -> client
  CC_MSG_BAD_ECM,
  CC_MSG_KEEPALIVE,		// client -> server
  CC_MSG_CARD_ADD,			// server -> client
  CC_MSG_SRV_INFO,			// server -> client
  CC_MSG_CMD_0B = 0x0b,	// server -> client ???????
#ifdef CACHEEX
  CC_MSG_CACHE_PUSH = 0x81, //CacheEx Cache-Push In/Out
#ifdef CACHEEX_CWCYCLE
  CC_MSG_CACHE_PRCW = 0x88,
#endif
#endif
  CC_MSG_ECM_NOK1 = 0xfe,	// server -> client ecm queue full, card not found
  CC_MSG_ECM_NOK2 = 0xff,	// server -> client
  CC_MSG_NO_HEADER = 0xffff
} cc_msg_cmd;

int cc_msg_recv(int handle,struct cc_crypt_block *recvblock, uint8_t *buf, int timeout);
int cc_msg_recv_nohead(int handle, struct cc_crypt_block *recvblock, uint8_t *buf, int len);
int cc_msg_send(int handle,struct cc_crypt_block *sendblock, cc_msg_cmd cmd, int len, uint8_t *buf);
int cc_msg_chkrecv(int handle,struct cc_crypt_block *recvblock);

int cc_msg_peek(int handle,struct cc_crypt_block *recvblock, struct message_data *msg, uint8_t *buf);

