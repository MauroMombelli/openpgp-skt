#include "util_qr/qr_code.h"
#include "util_tsl_server/tsl_server.h"

#include <stdlib.h>

#include <unistd.h>
#include <stdint.h>

#define PORT 5556               /* listen to 5556 port */

int server_fd;

void open_server() {
	char urlbuf[1024];
	const char schema[] = "OPGPSKT";
	urlbuf[sizeof(urlbuf)-1] = 0;
	char addrp[] = "192.168.0.27";
	char pskhex[PSK_BYTES*2 + 1];
	char eesid[] = "6561737962656C6C2044534C2D324446383444";
	
	server_create(pskhex);
	
	snprintf(urlbuf, sizeof(urlbuf)-1, "%s:%s/%d/%s%s%s", schema, addrp, PORT, pskhex, "/SSID:", eesid);
	create_and_print_qr(urlbuf, stdout);
	
	server_fd = server_bind(PORT);
}

void loop() {
	fd_set rfds;
	struct timeval tv;
	int retval;
	
	int client_fd = -1;
	
	int is_running = 1;
	
	while (is_running) {
		printf("main loop\n");
		/* Wait up to five seconds. */
		tv.tv_sec = 5;
		tv.tv_usec = 0;
	
		/* Watch stdin (fd 0) to see when it has input. */
		FD_ZERO(&rfds);
		if (server_fd == -1) {
			printf("Impossible to bind the server port\n");
			exit(-1);
		}
		FD_SET(server_fd, &rfds);
		FD_SET(STDIN_FILENO, &rfds);
		if (client_fd != -1) {
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
					FD_CLR(client_fd, &rfds);
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
				int ris = client_update( client_fd, buff, sizeof(buff) );
				if (ris == -1) {
					FD_CLR(client_fd, &rfds);
					client_fd = -1;
				}
			}
			
			//listen for handshake
			
			
			printf("\n");
		}else{
			printf("No data within five seconds.\n");
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

