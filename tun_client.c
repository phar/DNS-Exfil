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



static const unsigned char BASE64_ALPHABET[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
char SIMPLE_ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";


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
		
		for(t = Server.phead,fdc=1;(t != NULL) && (fdc < MAX_SOCKET_COUNT);t=t->pnext){
			if (t->active){
				fds[fdc].fd = t->to_client_sock;
				fds[fdc].events = POLLIN  | POLLERR  |POLLHUP;
				if((t->more_data_waiting== 1) | fifo_has_data(t->to_serv_fifo) | fifo_has_data(t->to_client_fifo) | (t->last_heard < (time(NULL) - 1))){
					t->more_data_waiting= 0;
					if(pump_data(t) < 0){ //error condition
						tun_shutdown(t);
					}
				}
				
				if(fifo_has_data(t->to_client_fifo)){
					if((fifo_pop(t->to_client_fifo,outbuff,&outbufflen)) != -1){
						send(t->to_client_sock, outbuff, outbufflen, 0);
					}else{
						tun_shutdown(t);
					}
				}
				fdc+=1;
			}
		}
		
		ret = poll(fds, fdc, 50);

		if (fds[0].revents & POLLIN){
			tunobj_t * tun;

			if(fdc < MAX_SOCKET_COUNT){
				if ((s = accept(Server.server_fd, (struct sockaddr *) &client, &client_len))){
					if((tun = tun_new(&Server,s))){
						tun_new_session(tun); //fixme error handling
						tun_connect(tun);
						debuglog(PRIORITY_DEBUG_NORMAL,"tunnel client connect on socket %d", s);
					}else{
						debuglog(PRIORITY_DEBUG_NORMAL,"tunnel client connect failed due to memory issue");
					}
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
							tun_shutdown(t);
						}else{
							if (fds[i].revents & POLLIN) {
								if((readlen = recv(fds[i].fd, inbuff, CLIENT_READ_CHUNK_SIZE, 0)) == -1){
									debuglog(PRIORITY_DEBUG_NORMAL,"tunnel client connect failed due to memory issue");
									tun_shutdown(t);
								}else{
									if((fifo_push(t->to_serv_fifo, inbuff, readlen)) == -1){
										debuglog(PRIORITY_DEBUG_NORMAL,"tunnel close due to low memory condition");
										tun_shutdown(t);
									}
								}
							}
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



int pump_data(tunobj_t * tun){
char hostbuff[1024];
char * encoded_buf;
uint8_t encode_buf[MAX_TRANSMIT_DATA_LENGTH+4];
xmt_hdr_t header ;
size_t encode_bufflen;
fifo_t * getdata;

	header.seq = tun->seq_no;


	if (fifo_has_data(tun->to_serv_fifo)){
		header.cmd = 'd';
		encode_bufflen =  base64_reallen(MAX_TRANSMIT_DATA_LENGTH - ((MAX_TRANSMIT_DATA_LENGTH/MAX_DOT_DISTANCE)+1) - (strlen(tun->tun_fqdn) + 1));

		if((fifo_pop(tun->to_serv_fifo,encode_buf,&encode_bufflen)) == -1){
			debuglog(PRIORITY_DEBUG_NORMAL,"tunnel client connect failed due to memory issue");
			return -1;
		}
		encoded_buf = base64_messageize(&header, encode_buf, encode_bufflen, &encode_bufflen);
	}else{
		header.cmd = 'p';
		encode_bufflen = sizeof(header);
		encoded_buf = base64_messageize(&header, NULL, 0, &encode_bufflen);
	}
	sprintf(hostbuff,"%c%s.%s",SIMPLE_ALPHABET[rand() % (sizeof(SIMPLE_ALPHABET) - 1)],encoded_buf,tun->tun_fqdn);

	free(encoded_buf);

	getdata =  internal_get_host_by_name(tun,hostbuff);
	if (getdata){
		if((fifo_push(tun->to_client_fifo, getdata->fifo_data, getdata->fifo_len)) == -1){
			return -1;
		}
		fifo_del(getdata);
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


/*
  base64 encodeing and messageizing api
*/
size_t base64_reallen(size_t len){
	return ((len / 4) * 3);
}

size_t base64_length(size_t len){
	return (((len / 3) + ((len % 3) > 0)) * 4);
}



char * base64_messageize(xmt_hdr_t * header, uint8_t *src, size_t len, size_t *out_len){
uint8_t *inbuff;
char * outbuff;
size_t tmplen;
	
	tmplen = len + sizeof(xmt_hdr_t);
	
	if((inbuff = malloc(tmplen)) == NULL){
		return NULL;
	}
	
	header->len = len;
	header->seq = htonl(header->seq);
	memcpy(inbuff,header,sizeof(xmt_hdr_t));
	memcpy(inbuff+sizeof(xmt_hdr_t),src,len);
	
	tmplen = base64_length(sizeof(xmt_hdr_t)+len);
	
	if((outbuff = malloc(tmplen))==NULL){
		return NULL;
	}
	base64_encode(inbuff, sizeof(xmt_hdr_t)+len, outbuff, &tmplen);
	free(inbuff);
	return outbuff;
	
}

char * base64_encode(uint8_t *src, size_t len, char *dst, size_t *out_len){
char  *pos;
uint8_t *end, *in;
size_t dotlen;

	end = src + len;
	in = src;
	pos = dst;
	dotlen = 0;
	
	while (end - in >= 3) {
		*pos++ = BASE64_ALPHABET[in[0] >> 2];
		*pos++ = BASE64_ALPHABET[((in[0] & 0x03) << 4) | (in[1] >> 4)];
		*pos++ = BASE64_ALPHABET[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*pos++ = BASE64_ALPHABET[in[2] & 0x3f];
		in += 3;
		dotlen += 4;
		if (dotlen > MAX_DOT_DISTANCE) {
			*pos++ = '.';
			dotlen = 0;
		}
	}
	
	if (end - in) {
		*pos++ = BASE64_ALPHABET[in[0] >> 2];
		if (end - in == 1) {
			*pos++ = BASE64_ALPHABET[(in[0] & 0x03) << 4];
		} else {
			*pos++ = BASE64_ALPHABET[((in[0] & 0x03) << 4) |
								  (in[1] >> 4)];
			*pos++ = BASE64_ALPHABET[(in[1] & 0x0f) << 2];
		}
		dotlen += 4;
	}
	
	*pos = '\0';
	if (out_len)
		*out_len = pos - dst;
	return dst;
}

/*
 basic tunnel api
*/

tunobj_t * tun_new(server_t * server,int socket){
tunobj_t * newtun;
tunobj_t * t;
	
	if((newtun = calloc(1,sizeof(tunobj_t))) == NULL)
		return 0;
	
	newtun->tun_fqdn = strdup(server->server_host);
	newtun->to_client_sock = socket;
	newtun->to_serv_fifo = fifo_new();
	newtun->to_client_fifo = fifo_new();
	newtun->active = 1;
	
	if (server->phead){
		for(t = server->phead;t->pnext;t=t->pnext);
		t->pnext = newtun;
	}else{
		server->phead = newtun;
	}
	return newtun;
}


void tun_shutdown(tunobj_t * tun){
tunobj_t *t,*prev;
char hostbuff[1024];
char encodebuff[512];
fifo_t * getdata;
xmt_hdr_t header;
char * newhostbuff;
size_t encodebufflen = sizeof(encodebuff);

	if(Server.phead){
		for(t = Server.phead,prev= Server.phead;t;t=t->pnext){
			if(t == tun){
				t->active = 0;
				header.cmd = 'x';
				header.seq = tun->seq_no;
				
				debuglog(PRIORITY_DEBUG_HIGH,"close()");
				
				newhostbuff = base64_messageize(&header, NULL, 0, &encodebufflen);
				sprintf(hostbuff,"%c%s.%s",SIMPLE_ALPHABET[rand() % (sizeof(SIMPLE_ALPHABET) - 1)],newhostbuff,tun->tun_fqdn);
				free(newhostbuff);
				if((getdata =  internal_get_host_by_name(tun,hostbuff)) != NULL){
					debuglog(PRIORITY_DEBUG_NORMAL,"There server acknowledged the connection close request");
					fifo_del(getdata);
				}else{
					debuglog(PRIORITY_DEBUG_NORMAL,"The server did not acknowledge the connection close request");
				}
			}
		}
	}
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
				fifo_del(t->to_client_fifo);
				fifo_del(t->to_serv_fifo);
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


int tun_new_session(tunobj_t * tun){
char hostbuff[1024];
char encodebuff[512];
xmt_hdr_t header;
char * newhostbuff;
size_t encodebufflen = sizeof(encodebuff);
fifo_t * getdata;


	tun->seq_no = rand();
	
	header.cmd = 's';
	header.seq = tun->seq_no;
	
	debuglog(PRIORITY_DEBUG_HIGH,"tun_new_session()");

	newhostbuff = base64_messageize(&header, NULL, 0, &encodebufflen);
	sprintf(hostbuff,"%c%s.%s",SIMPLE_ALPHABET[rand() % (sizeof(SIMPLE_ALPHABET) - 1)],newhostbuff,tun->tun_fqdn);

	if((getdata =  internal_get_host_by_name(tun,hostbuff)) != NULL){
		debuglog(PRIORITY_DEBUG_NORMAL,"proxy session create success");
		fifo_del(getdata);
		return 0;
	}else{
		debuglog(PRIORITY_DEBUG_NORMAL,"proxy session could not be created.. server did not respond");
		return -1;
	}
}

int tun_connect(tunobj_t * tun){
char hostbuff[1024];
char encodebuff[512];
xmt_hdr_t header;
char * newhostbuff;
size_t encodebufflen = sizeof(encodebuff);
fifo_t * getdata;
uint32_t res;
	
	header.cmd = 'c';
	header.seq = tun->seq_no;
	debuglog(PRIORITY_DEBUG_HIGH,"tun_connect()");
	
	newhostbuff = base64_messageize(&header, NULL, 0, &encodebufflen);
	sprintf(hostbuff,"%c%s.%s",SIMPLE_ALPHABET[rand() % (sizeof(SIMPLE_ALPHABET) - 1)],newhostbuff,tun->tun_fqdn);

	if((getdata =  internal_get_host_by_name(tun,hostbuff)) != NULL){
		tun->connection_state = 1;
		res = fifo_pop_uint32(getdata);
		if(res > 0){
			debuglog(PRIORITY_DEBUG_NORMAL,"connect success");
		}else{
			debuglog(PRIORITY_DEBUG_NORMAL,"connect failure, server reports error %d", res);
		}
		fifo_del(getdata);
	}else{
		debuglog(PRIORITY_DEBUG_NORMAL,"proxy connection could not be created.. server did not respond");
		return -1;
	}
	return 0;
}


/*
 	gethostbyname transport wrapper
*/


fifo_t * internal_get_host_by_name(tunobj_t * tun,char * hostname){
size_t assemblylen = 0;
uint8_t assemblybuff[3 * MAX_IPS_PER_RESPONSE];
int trycount,i,e;
fifo_t * fifo = NULL;
struct hostent *he;
struct in_addr **addr_list;
	
	do{
		debuglog(PRIORITY_DEBUG_HIGH,"Q: %s" , hostname);
		he = gethostbyname(hostname);
		trycount += 1;
		if(trycount > 3){
			break;
		}
	}while(he == NULL);

	if(he != NULL){
		uint32_t t;

		tun->last_heard = time(NULL);

		addr_list = (struct in_addr **)he->h_addr_list;
		
		assemblylen = 0;
		memset(assemblybuff,0,sizeof(assemblybuff));
		t =  tun->seq_no;
		lfsr_inc(&tun->seq_no);
		debuglog(PRIORITY_DEBUG_EXTREME, "sequence number change from %u to %u", t, tun->seq_no);

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
		
		if(assemblylen){
			fifo = fifo_new();
			fifo_push(fifo, assemblybuff, assemblylen);
		}
	}else{
		debuglog(PRIORITY_DEBUG_HIGH,"Q: query failed to reach tunnel server!");
	}
	return fifo;
}



/*
 FIFO utils
*/

fifo_t * fifo_new(){
	return calloc(1,sizeof(fifo_t));
}


int fifo_has_data(fifo_t * fifo){
	return (fifo->fifo_len > 0);
}

int fifo_has_enough_data(fifo_t * fifo, size_t size){
	return (fifo->fifo_len > size);
}

void fifo_del(fifo_t * fifo){
	debuglog(PRIORITY_DEBUG_EXTREME,"fifo_del, len is %d",fifo->fifo_len);
	if(fifo){
		if(fifo->fifo_len){
			free(fifo->fifo_data);
		}
		free(fifo);
	}else{
		debuglog(PRIORITY_DEBUG_HIGH, "null pointer passed to fifo_del, should never be the case");
	}
}

int fifo_push(fifo_t * fifo, uint8_t * data, size_t datalen){
	debuglog(PRIORITY_DEBUG_EXTREME,"fifo_push, len is %d before push with new datalen %d",fifo->fifo_len, datalen);
	if(datalen){
		if(fifo->fifo_len){
			if((fifo->fifo_data = realloc(fifo->fifo_data,fifo->fifo_len + datalen)))
				return -1;
			memmove(fifo->fifo_data+fifo->fifo_len,data,datalen);
			fifo->fifo_len+=datalen;
			
		}else{
			if((fifo->fifo_data = malloc(datalen)) == NULL)
				return -1;
			memmove(fifo->fifo_data,data,datalen);
			fifo->fifo_len=datalen;
		}
	}
	debuglog(PRIORITY_DEBUG_EXTREME,"fifo_push, len is %d after push",fifo->fifo_len, datalen);
	return 0;
}


uint32_t fifo_pop_uint32(fifo_t * fifo){
uint32_t popval;
size_t datalen  = sizeof(uint32_t);

	if((fifo_pop(fifo, (uint8_t *)&popval, &datalen)) != sizeof(uint32_t)){
		debuglog(PRIORITY_DEBUG_HIGH,"fifo did not have enough data for uint32 request, but api is bad");
		return 0;
	}
	return ntohl(popval);
}

			
size_t fifo_pop(fifo_t * fifo, uint8_t * buffer, size_t  * datalen){
	
	debuglog(PRIORITY_DEBUG_EXTREME,"fifo_pop, len is %d before pop",fifo->fifo_len, datalen);
	if(*datalen){
		if(fifo->fifo_len >= *datalen){
			fifo->fifo_len -= *datalen;
			memcpy(buffer,fifo->fifo_data,*datalen);
			memmove(fifo->fifo_data, fifo->fifo_data+*datalen, fifo->fifo_len);
			if(fifo->fifo_len){
				if((fifo->fifo_data = realloc(fifo->fifo_data,fifo->fifo_len)))
					return -1;
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
	debuglog(PRIORITY_DEBUG_EXTREME,"fifo_pop, len is %d after pop",fifo->fifo_len, datalen);
	return *datalen;
}


/*
 LFSR implementation for session tracking
*/

uint32_t lfsr_inc(uint32_t *lfsr){
	uint32_t taps[] = {0xFFFFFFFF, (1 << 31), (1 << 21), (1 << 1), (1 << 0), 0};

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
