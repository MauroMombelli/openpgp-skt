#include "util_qr/qr_code.h"
#include "util_tsl_server/tsl_server.h"
#include "util_network_info/network_info.h"

#include <stdlib.h>

#include <unistd.h>
#include <stdint.h>

#include <string.h>

#define PORT 5556               /* listen to 5556 port */

int server_fd;

void open_server() {
	char urlbuf[1024];
	const char schema[] = "OPGPSKT";
	urlbuf[sizeof(urlbuf)-1] = 0;
	char pskhex[PSK_BYTES*2 + 1];
	
	struct network_info info;
	
	server_create(pskhex, sizeof(pskhex));
	
	get_info(&info);
	printf("%s - %s %ld %d %ld\n", info.ssid, info.ip, strlen(pskhex), PSK_BYTES, sizeof(pskhex));
	
	snprintf(urlbuf, sizeof(urlbuf)-1, "%s:%s/%d/%s%s%s", schema, info.ip, PORT, pskhex, "/SSID:", info.ssid);
	create_and_print_qr(urlbuf, stdout);
	
	free(info.ssid);
	free(info.ip);
	
	server_fd = server_bind(PORT);
}

void loop() {
	fd_set rfds;
	struct timeval tv;
	int retval;
	
	int client_fd = -1;
	
	int is_running = 1;
	
	while (is_running) {
		printf("-------------\nLOOP\n");
		/* Wait up to five seconds. */
		tv.tv_sec = 5;
		tv.tv_usec = 0;
	
		/* Watch server to see when it has input. */
		FD_ZERO(&rfds);
		if (server_fd == -1) {
			printf("Impossible to bind the server port\n");
			exit(-1);
		}
		FD_SET(server_fd, &rfds);
		
		/* Watch stdin (fd 0) to see when it has input. */
		FD_SET(STDIN_FILENO, &rfds);
		
		/* Watch client to see when it has input. */
		if (client_fd != -1) {
			printf("client listening\n");
			//set back
			FD_SET(client_fd, &rfds);
		}
		
		retval = select(FD_SETSIZE, &rfds, NULL, NULL, &tv);
		/* Don't rely on the value of tv now! */
		
		if (retval == -1){
			perror("select()");
			is_running = 0;
		}else if (retval){
			printf("Data is available now. ");
			
			//listen for user input
			if (FD_ISSET(STDIN_FILENO, &rfds)) {
				printf("From STDIN ");
				static char line[256];
				
				if(fgets(line, sizeof line, stdin) != NULL) {
					printf("%s", line);
				}
			}
			
			//listen for new connection
			if (FD_ISSET(server_fd, &rfds)) {
				//only one connection at time
				if (client_fd != -1){
					client_close(client_fd);
					client_fd = -1;
				}
				
				client_fd = server_accept();
				printf("New socket connected with FD %d! ", client_fd);
				FD_SET(client_fd, &rfds);
				
			}
			
			//if client connected, check for input
			if (client_fd != -1 && FD_ISSET(client_fd, &rfds)){
				printf("client %d! ", client_fd);
				uint8_t buff[100];
				int ris;
				do{
					ris = client_update( client_fd, buff, sizeof(buff) );
					if (ris == -1) {
						printf("client closed %d", client_fd);
						client_close(client_fd);
						client_fd = -1;
					}else{
						printf("client sent data %d byte: ", ris);
						for (size_t i = 0; i < ris; i++)
						{
							printf("%02X", buff[i]);
						}
					}
				}while(ris > 0);
			}
			
			
			printf("\n");
		}else{
			//printf("No data within five seconds.\n");
		}
	}
}

int main(void) {
	
	
	
	open_server();
	
	loop();
	
	printf("server closing\n");
	server_close();
	
	return 0;
	
}

