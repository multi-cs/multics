
#define UNKCYCLE 0
#define CW0CYCLE 'A'
#define CW1CYCLE 'B'

struct twin_channel_info_data {
		uint16_t caid;
		uint32_t prov;
		uint16_t sid;
		uint16_t deg;
		uint16_t freq;
		uint8_t cw1cycle;
		char name[64];
		// CURRENT ECM
		struct {
			uint32_t rtime; // receive time
			uint8_t tag;
			uint32_t hash;
			uint32_t cycletime;
			uint8_t cwcycle; // CW0 / CW1
			uint8_t ecmd5[16];
			uint8_t prevcw[16];
			uint8_t cw[16];
			int error;
		} ecm;
};

struct  twin_data {
	int handle;
	char device[64];
	struct {
		char fname[512];
		struct twin_channel_info_data data[1024];
		int count;
	} chninfo;
};

