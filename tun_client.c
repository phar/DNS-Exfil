#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <netdb.h>
#include <poll.h>
#include <time.h>
#include <stdarg.h>
#include "tun_client.h"



static const unsigned char base64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";


uint8_t lfsr_taps4[] = {0xF, (1 << 3), (1 << 2), 0};
uint8_t lfsr_taps8[] = {0xFF, (1 << 7), (1 << 5), (1 << 4), (1 << 3), 0};
uint16_t lfsr_taps12[] = {0xFFF, (1 << 11), (1 << 5), (1 << 3), (1 << 0), 0};
uint16_t lfsr_taps16[] = {0xFFFF, (1 << 15), (1 << 14), (1 << 12), (1 << 3), 0};
uint32_t lfsr_taps20[] = {0xFFFFF, (1 << 19), (1 << 16), 0};
uint32_t lfsr_taps24[] = {0xFFFFFF, (1 << 23), (1 << 22), (1 << 21), (1 << 16), 0};
uint32_t lfsr_taps28[] = {0xFFFFFFF, (1 << 27), (1 << 24), 0};
uint32_t lfsr_taps32[] = {0xFFFFFFFF, (1 << 31), (1 << 21), (1 << 1), (1 << 0), 0};


server_t Server;


int main (int argc, char *argv[]) {
int err,i, s,ret,readlen;
struct sockaddr_in client;
char c;
int has_host = 0;
int has_port = 0;
char * tunnel_server;
struct pollfd fds[MAX_SOCKET_COUNT];
tunobj_t * t;
int fdc;
uint8_t inbuff[CLIENT_READ_CHUNK_SIZE];
uint8_t outbuff[CLIENT_WRITE_CHUNK_SIZE];

	srand(time(NULL));
	
	memset(&Server,0,sizeof(server_t));
	Server.server_running = 1;
	Server.proxy_port = DEFAULT_PORT_NUMBER;
	
	while ((c = getopt (argc, argv, "s:p:l:d:")) != -1){
		switch (c){
			case 's': //server
				has_host = 1;
				Server.server_host = strdup(optarg);
				debuglog(PRIORITY_DEBUG_NORMAL,"Setting tunel host %s", Server.server_host);
				break;
				
			case 'p': //port
				has_port = 1;
				Server.proxy_port = atoi(optarg);
				break;

				
			case 'd': //debug level
				has_port = 1;
				Server.debug_level = atoi(optarg);
				break;

			case 'l': //logfile
				Server.log_file = strdup(optarg);
				break;

			case '?':
			default:
				usage(argv[0]);
		}
	}
	
	if (has_host == 0){
		usage(argv[0]);
		exit(-1);
	}
	
	Server.server_fd =  bind_service(tunnel_server, INADDR_ANY,Server.proxy_port);
	debuglog(PRIORITY_DEBUG_NORMAL,"Server is listening on %d", Server.proxy_port);
	
	while (Server.server_running) {
		
		socklen_t client_len = sizeof(client);
		size_t outbufflen = CLIENT_WRITE_CHUNK_SIZE;
	
		fds[0].fd = Server.server_fd;
		fds[0].events = POLLIN;
		
		for(t = Server.phead,fdc=1;(t != NULL) && (fdc < MAX_SOCKET_COUNT);t=t->pnext,fdc+=1){
			fds[fdc].fd = t->to_client_sock;
			fds[fdc].events = POLLIN  | POLLERR  |POLLHUP;
			if((t->more_data_waiting== 1) | fifo_has_data(&t->to_serv_fifo) | fifo_has_data(&t->to_client_fifo) | (t->last_heard < (time(NULL) - 1))){
				t->more_data_waiting= 0;
				pump_data(t);
			}
			
			if(fifo_has_data(&t->to_client_fifo)){
				fifo_pop(&t->to_client_fifo,outbuff,&outbufflen);
				send(t->to_client_sock, outbuff, outbufflen, 0);
			}
		}
		
		ret = poll(fds, fdc, 50);

		if (fds[0].revents & POLLIN){
			tunobj_t * tun;

			if(fdc < MAX_SOCKET_COUNT){
				if ((s = accept(Server.server_fd, (struct sockaddr *) &client, &client_len))){
					tun = tun_new(&Server,s);
					debuglog(PRIORITY_DEBUG_NORMAL,"tunnel client connect on socket %d", s);
					tun_connect(tun);
				}else{
					debuglog(PRIORITY_DEBUG_NORMAL,"tunnel client connect failed!", s);
				}
			}else{
				debuglog(PRIORITY_DEBUG_NORMAL,"refusing to answer connect request with %d open connections", fdc);
			}
		}

		for(t = Server.phead;t;t=t->pnext){
			if(ret){
				for(i = 1;i<fdc;i++){
					if(fds[i].fd == t->to_client_sock){
						if (fds[i].revents & (POLLERR | POLLHUP)) {
							debuglog(PRIORITY_DEBUG_NORMAL,"socket error");
							tun_close(t);
							break;
						}else{
							if (fds[i].revents & POLLIN) {
								if((readlen = recv(fds[i].fd, inbuff, CLIENT_READ_CHUNK_SIZE, 0)) == -1){
									tun_close(t);
									break;
								}else{
									fifo_push(&t->to_serv_fifo, inbuff, readlen);
								}
							}
//							if (fds[i].revents & POLLOUT){
//								fifo_pop(&t->to_client_fifo,outbuff,&outbufflen);
//								send(fds[i].fd, outbuff, outbufflen, 0);
//							}
						}
					}
				}
			}
		}
	
	}
	return 0;
}



int bind_service(char * tunnel_host, int bind_host, int bind_port){
int opt_val = 1;
struct sockaddr_in thisserver;
int server_fd;
int err;
	
	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	
	thisserver.sin_family = AF_INET;
	thisserver.sin_port = htons(bind_port);
	thisserver.sin_addr.s_addr = htonl(bind_host);
	
	setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof opt_val);
	
	if((err = bind(server_fd, (struct sockaddr *) &thisserver, sizeof(thisserver))) < 0){
		debuglog(PRIORITY_DEBUG_NORMAL,"error binding socket.. fatal with error %d", err);
		return -1;
	}
	
	if((err = listen(server_fd, 128)) < 0){
		debuglog(PRIORITY_DEBUG_NORMAL,"error listening on socket.. fatal with error %d", err);
		return -1;
	}
	
	return server_fd;
}


tunobj_t * tun_new(server_t * server,int socket){
tunobj_t * newtun;
tunobj_t * t;
	
	newtun = calloc(1,sizeof(tunobj_t));
	newtun->tun_fqdn = strdup(server->server_host);
	newtun->to_client_sock = socket;
	
	if (server->phead){
		for(t = server->phead;t->pnext;t=t->pnext);
		t->pnext = newtun;
	}else{
		server->phead = newtun;
	}
	return newtun;
}

int tun_close(tunobj_t * tun){
tunobj_t *t,*prev;
	
	if(Server.phead){
		for(t = Server.phead,prev= Server.phead;t;t=t->pnext){
			if(t == tun){
				debuglog(PRIORITY_DEBUG_HIGH, "removing connection on socket %d", t->to_client_sock);
				if(prev == Server.phead){
					Server.phead = t->pnext;
				}else{
					prev->pnext = t->pnext;
				}
				fifo_del(&t->to_client_fifo);
				fifo_del(&t->to_serv_fifo);
				close(t->to_client_sock);
				free(t->tun_fqdn);
				return 0;
			}else{
				prev = t;
			}
		}
	}else{
		return -1;
	}
	return 0;
}



int tun_connect(tunobj_t * tun){
struct sockaddr_in server_address;
struct hostent *he;
char hostbuff[1024];
int trycount = 0;
struct in_addr **addr_list;
	
	do{
		memset(hostbuff,0,sizeof(hostbuff));
		sprintf(hostbuff,"c.%.8x.%s",rand(),tun->tun_fqdn);
		debuglog(PRIORITY_DEBUG_HIGH,hostbuff);
		he = gethostbyname(hostbuff);
		trycount += 1;
		if(trycount > 3){
			break;
		}
	}while(he == NULL);
	
	tun->last_heard = time(NULL);
	addr_list = (struct in_addr **)he->h_addr_list;
	
	if((trycount >= 3) | (he == NULL)){
		debuglog(PRIORITY_DEBUG_NORMAL,"packet transmission aborted due to retry limit being exceeded");
		tun->connection_state = 0;
		return -1;

	}else if (addr_list[0]->s_addr == 0){
		tun->connection_state = 0;
		debuglog(PRIORITY_DEBUG_NORMAL,"connect failed error %08x",addr_list[0]->s_addr );
		return -2;
	}
	tun->connection_state = 1;
	tun->seq_no = ntohl(addr_list[0]->s_addr);
	debuglog(PRIORITY_DEBUG_NORMAL,"proxy connect success");
	return 0;
}


int pump_data(tunobj_t * tun){
int i,e;
struct hostent *he;
struct in_addr **addr_list;
char hostbuff[1024];
char tchunk[1024+2];
char * encoded_buf;
int trycount = 0;
uint8_t encode_buf[MAX_TRANSMIT_DATA_LENGTH+4];

	
	do{
		if(trycount){
			debuglog(PRIORITY_DEBUG_NORMAL,"transmission failed, retrying");
		}
		
		if (fifo_has_data(&tun->to_serv_fifo)){
			size_t outlen;
			size_t encode_bufflen = base64_reallen(MAX_DNS_TRANSMIT_LENGTH);
			
			fifo_pop(&tun->to_serv_fifo,encode_buf,&encode_bufflen);
			encoded_buf = base64_encode(encode_buf, encode_bufflen, &outlen);
			sprintf(hostbuff, "d.%.8x.", tun->seq_no);
			for(i=0,e=0;i<(outlen/MAX_DOT_DISTANCE);i++){
				strncpy(tchunk,encoded_buf+(i*MAX_DOT_DISTANCE),MAX_DOT_DISTANCE);
				tchunk[MAX_DOT_DISTANCE] = 0;
				strcat(hostbuff,tchunk);
				strcat(hostbuff,".");
				e += MAX_DOT_DISTANCE;
			}
			if(e < outlen){
				strcat(hostbuff,encoded_buf + (i * MAX_DOT_DISTANCE));
				strcat(hostbuff,".");
			}
			strcat(hostbuff,tun->tun_fqdn);
			free(encoded_buf);
			
		}else{
			sprintf(hostbuff, "p.%.8x.%s", tun->seq_no,tun->tun_fqdn);
		}
		debuglog(PRIORITY_DEBUG_HIGH,"Q: %s" , hostbuff);
		he = gethostbyname(hostbuff);
		trycount += 1;
		if(trycount > 3){
			break;
		}
	}while(he == NULL);
	if(he != NULL){
		tun->last_heard = time(NULL);

		size_t assemblylen = 0;
		uint8_t assemblybuff[3 * MAX_IPS_PER_RESPONSE];
		
		addr_list = (struct in_addr **)he->h_addr_list;
		
		memset(assemblybuff,0,sizeof(assemblybuff));
		
		lfsr_inc_32(lfsr_taps32, &tun->seq_no);
		
		for(i = 0; addr_list[i] != NULL; i++) {
			int tmpval = ntohl(addr_list[i]->s_addr);
			
			if ((ntohl(addr_list[i]->s_addr) &    0x40000000) >> 30)
				tun->more_data_waiting = 1;
			
 			assemblylen += (ntohl(addr_list[i]->s_addr) & 0x30000000) >> 28;
			
			for(e=0;e<(tmpval & 0x30000000) >> 28;e++){
				int mask = (0xff0000 >> (e * 8));
				assemblybuff[(((tmpval & 0x0f000000) >> 24) * 3) + e] = (tmpval & mask) >> (16 - (e * 8));
			}
		}
		fifo_push(&tun->to_client_fifo, assemblybuff, assemblylen);
	}else{
		return -2;
	}
	return 0;
}


void usage(char * execname){
	printf("\nDNS pipe client usage!\n");
	printf("%s\n", execname);
	printf("\t-s <dns tunnel server hostname>\n");
	printf("\t-p [<dns tunnel bind port>]\n");
	printf("\t-d [<debug level>]\n");
	printf("\t-l [<output log file name>]\n");

}


void debuglog(int priority, const char *format, ...){
time_t curr_time;
char * timestring;
	
	va_list args;
	va_start(args, format);
	
	if(Server.debug_level){
		curr_time = time(NULL);
		timestring = ctime(&curr_time);
		timestring[strlen(timestring)-1] = 0;
		printf("[%s] - %s - ",timestring,LOG_LEVEL_STRS[priority]);
		vprintf(format, args);
		printf("\n");
	}
	va_end(args);
}

size_t base64_reallen(size_t len){
	return ((len / 4) * 3);
}

size_t base64_length(size_t len){
	return (((len / 3) + ((len % 3) > 0)) * 4);
}

char * base64_encode(uint8_t *src, size_t len, size_t *out_len){
char  *out, *pos;
uint8_t *end, *in;
size_t olen;

	olen = base64_length(len) + 1;
	olen++; /* nul termination */
	if (olen < len)
		return NULL; /* integer overflow */
	
	out = malloc(olen);
	if (out == NULL)
		return NULL;
	
	end = src + len;
	in = src;
	pos = out;
	
	while ((end - in) >= 3) {
		*pos++ = base64_table[in[0] >> 2];
		*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
		*pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*pos++ = base64_table[in[2] & 0x3f];
		in += 3;
	}
	
	if (end - in) {
		*pos++ = base64_table[in[0] >> 2];
		if (end - in == 1) {
			*pos++ = base64_table[(in[0] & 0x03) << 4];
		} else {
			*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
			*pos++ = base64_table[(in[1] & 0x0f) << 2];
		}
	}
	
	*pos = '\0';
	*out_len = pos - out;
	return out;
}


int fifo_has_data(fifo_t * fifo){
	return (fifo->fifo_len > 0);
}

int fifo_has_enough_data(fifo_t * fifo, size_t size){
	return (fifo->fifo_len > size);
}

void fifo_del(fifo_t * fifo){
	
	if(fifo->fifo_len){
		free(fifo->fifo_data);
	}
}

int fifo_push(fifo_t * fifo, uint8_t * data, size_t datalen){
	if(datalen){
		if(fifo->fifo_len){
			fifo->fifo_data = realloc(fifo->fifo_data,fifo->fifo_len + datalen);
			memmove(fifo->fifo_data+fifo->fifo_len,data,datalen);
			fifo->fifo_len+=datalen;
			
		}else{
			fifo->fifo_data = malloc(datalen);
			memmove(fifo->fifo_data,data,datalen);
			fifo->fifo_len=datalen;
		}
	}
	return 0;
}

size_t fifo_pop(fifo_t * fifo, uint8_t * buffer, size_t  * datalen){
	
	if(*datalen){
		if(fifo->fifo_len >= *datalen){
			fifo->fifo_len -= *datalen;
			memcpy(buffer,fifo->fifo_data,*datalen);
			memmove(fifo->fifo_data, fifo->fifo_data+*datalen, fifo->fifo_len);
			if(fifo->fifo_len){
				fifo->fifo_data = realloc(fifo->fifo_data,fifo->fifo_len);
			}else{
				fifo->fifo_len = 0;
				free(fifo->fifo_data);
				fifo->fifo_data = 0;
			}
		}else{
			if(fifo->fifo_len){
				*datalen = fifo->fifo_len;
				memcpy(buffer,fifo->fifo_data,*datalen);
				free(fifo->fifo_data);
				fifo->fifo_len = 0;
				fifo->fifo_data = 0;
			}else{
				*datalen = 0;
			}
		}
	}
	return *datalen;
}




uint32_t lfsr_inc_32(uint32_t *taps, uint32_t *lfsr){
	uint32_t tap = 0;
	int i = 1;
	
	while(taps[i]){
		tap ^= (taps[i] & *lfsr) > 0;
		i+=1;
	}
	*lfsr <<= 1;
	*lfsr |= tap;
	*lfsr &= taps[0];
	
	return *lfsr;
}
