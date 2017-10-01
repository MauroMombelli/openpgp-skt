#include "../util_qr/qr_code.h"
#include "tsl_server.h"

#include <stdlib.h>

#include <unistd.h>
#include <stdint.h>

#define PORT 5556               /* listen to 5556 port */

int main(void) {
	/*
	if (gnutls_check_version("3.1.4") == NULL) {
		fprintf(stderr, "GnuTLS 3.1.4 or later is required\n");
		exit(1);
	}
	*/
	
	char urlbuf[1024];
	const char schema[] = "OPGPSKT";
	urlbuf[sizeof(urlbuf)-1] = 0;
	char addrp[] = "192.168.178.51";
	char pskhex[PSK_BYTES*2 + 1];
	char eesid[] = "6561737962656C6C2044534C2D324446383444";
	
	
	server_create(pskhex);
	
	snprintf(urlbuf, sizeof(urlbuf)-1, "%s:%s/%d/%s%s%s", schema, addrp, PORT, pskhex, "/SSID:", eesid);
	create_and_print_qr(urlbuf, stdout);
	
	server_bind(PORT);
	int client_id;
	while ( (client_id = server_accept() ) == -1 ){ //while waiting for client
		//wait for connection, ugly but hey, is a test
		sleep(1);
	}
	
	printf("out of accept\n");
	
	#define size 1000
	uint8_t buffer[size];
	int readed;
	while ( (readed = client_read(client_id, buffer, size)) >= 0){
		if (readed == 0){
			printf("read nothing");
		}else{
			printf("readed: %d byte", readed);
		}
		sleep(1);
	}
	
	printf("out of read\n");
	
	client_close(client_id);
	printf("client closed\n");
	
	//while ( 1 ){ //while waiting for client
		//wait for connection, ugly but hey, is a test
		
	//}
	
	
	server_close();
	printf("server closed\n");
	/*
	 * 
	 * int err, listen_sd;
	 * int sd, ret;
	 * struct sockaddr_in sa_serv;
	 * struct sockaddr_in sa_cli;
	 * socklen_t client_len;
	 * char topbuf[512];
	 * gnutls_session_t session;
	 * gnutls_anon_server_credentials_t anoncred;
	 * char buffer[MAX_BUF + 1];
	 * int optval = 1;
	 */
	
	return 0;
	
}
