#ifndef __TUN_H
#define __TUN_H

#define CONNECTION_STATE_IDLE			0
#define CONNECTION_STATE_CONNECTING		1
#define CONNECTION_STATE_CONNECTED		2
#define CONNECTION_STATE_CLOSING		3

#define CONNECTION_CMD_CLOSE			0
#define CONNECTION_CMD_OPEN				1
#define CONNECTION_CMD_READ				2
#define CONNECTION_CMD_WRITE			3


#define MAX_DNS_TRANSMIT_LENGTH			240
#define MAX_TRANSMIT_DATA_LENGTH		120
#define MAX_DOT_DISTANCE				59

#define CLIENT_WRITE_CHUNK_SIZE			64
#define CLIENT_READ_CHUNK_SIZE			64

#define MAX_IPS_PER_RESPONSE			16

#define LENGTH_WOBBLE					5

#define MAX_SOCKET_COUNT				200


typedef struct fifo_t{
	uint8_t * fifo_data;
	size_t fifo_len;
}fifo_t;


#define PRIORITY_DEBUG_NORMAL			0
#define PRIORITY_DEBUG_HIGH				1
#define PRIORITY_DEBUG_ALL				2
#define PRIORITY_DEBUG_EXTREME				3



#define  DEFAULT_PORT_NUMBER			2093

char *LOG_LEVEL_STRS[] = {"NORMAL","HIGH","ALL","EXTREME"};


typedef struct tunobj_t{
	int active;
	int connection_state;
	
	uint32_t seq_no;
	char * tun_fqdn;
	
	uint16_t tun_remote_port;
	
	fifo_t  *to_serv_fifo;
	fifo_t  *to_client_fifo;
	
	int to_client_sock;
	
	uint32_t more_data_waiting;
	
	time_t last_heard;
	
	struct tunobj_t *pnext;
}tunobj_t;


typedef struct server_t{
	char * server_host;
	unsigned short proxy_port;
	int server_fd;
	int server_running;
	int debug_level;
	char * log_file;
	
	struct tunobj_t *phead;
}server_t;


typedef struct  __attribute__((packed)) xmt_hdr_t{
	uint32_t	seq;
	uint8_t		cmd;
	uint8_t		len;
}xmt_hdr_t;


char * base64_messageize(xmt_hdr_t * header, uint8_t *src, size_t len, size_t *out_len);
void tun_shutdown(tunobj_t * tun);
uint32_t fifo_pop_uint32(fifo_t * fifo);
int tun_new_session(tunobj_t * tun);
fifo_t * fifo_new();
fifo_t * internal_get_host_by_name(tunobj_t * tun,char * hostname);
void fifo_del(fifo_t * fifo);
int tun_close(tunobj_t * tun);
size_t base64_reallen(size_t len);
size_t base64_length(size_t len);
int fifo_has_data(fifo_t * fifo);
int fifo_push(fifo_t * fifo, uint8_t * data, size_t datalen);
size_t fifo_pop(fifo_t * fifo, uint8_t * buffer, size_t  * datalen);
int fifo_has_enough_data(fifo_t * fifo, size_t size);
int bind_service(char * tunnel_host, int bind_host, int bind_port);
int tun_connect(tunobj_t * tun);
tunobj_t * tun_new(server_t * server,int socket);
int do_proxy(tunobj_t * tun);
void usage(char * execname);
char * base64_encode(uint8_t *src, size_t len, char *dst, size_t *out_len);
int pump_data(tunobj_t * tun);
void debuglog(int priority, const char *format, ...);
uint32_t lfsr_inc(uint32_t *lfsr);

#endif

