#include "util_qr/qr_code.h"
#include "util_tls_server/tls_server.h"
#include "util_network_info/network_info.h"
#include "util_gpg/gpg_session.h"

#include <stdlib.h>

#include <unistd.h>
#include <stdint.h>

#include <string.h>

#include <inttypes.h>

#include <errno.h>


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

gpgme_key_t *list_of_keys = NULL;
size_t number_of_keys;

void update_and_print_keys(gpgme_ctx_t *ctx) {
	
	if (list_of_keys != NULL) {
		gpgsession_free_secret_keys(&list_of_keys, number_of_keys);
	}
	
	gpgsession_gather_secret_keys(ctx, &list_of_keys, &number_of_keys);
	
	printf("Select a key to share:\n");
	for (size_t c = 0; c < number_of_keys; c++) {
		printf("[%ld] key %s\n", c,  list_of_keys[c]->fpr);
	}
	
}

int send_key(gpgme_ctx_t * const ctx, gpgme_key_t key, const int fd) {
	int rc = 0;
	gpgme_error_t gerr = 0;
	gpgme_export_mode_t mode = GPGME_EXPORT_MODE_MINIMAL | GPGME_EXPORT_MODE_SECRET;
	char *pattern = NULL;
	gpgme_data_t data = NULL;
	
	rc = asprintf(&pattern, "0x%s", key->fpr);
	if (rc == -1) {
		fprintf(stderr, "failed to malloc appropriately!\n");
		return -1;
	}
	
	/* create buffer for data exchange with gpgme*/
	gerr = gpgme_data_new(&data);
	if(gerr) {
		fprintf(stderr, "failed to init data buffer: (%d) %s\n", gerr, gpgme_strerror(gerr));
		return -1;
	}
	
	ssize_t read_bytes;
	
	/* FIXME: blocking! */
	gerr = gpgme_op_export(*ctx, pattern, mode, data);
	free(pattern);
	
	read_bytes = gpgme_data_seek (data, 0, SEEK_END);
	if(read_bytes == -1) {
		printf("data-seek-err: %s\n", gpgme_strerror(errno));
	}
	read_bytes = gpgme_data_seek (data, 0, SEEK_SET);
	
	if (gerr) {
		gpgme_data_release(data);
		fprintf(stderr, "failed to export key: (%d) %s\n", gerr, gpgme_strerror(gerr));
		return -1;
	}
	
	/* write keys to stderr */
	char buf[1000];
	while ((read_bytes = gpgme_data_read (data, buf, sizeof(buf))) > 0) {
		ssize_t written = client_write(fd, buf, read_bytes); /* FIXME: blocking */
		if (written != read_bytes) {
			fprintf(stderr, "failed to wite key\n");
			gpgme_data_release(data);
			return -1;
		}
	}
	
	if (read_bytes < 0) {
		fprintf(stderr, "failed to read key: (%d) %s\n", gerr, gpgme_strerror(gerr));
	}
	
	gpgme_data_release(data);
	return 0;
}

void loop() {
	fd_set rfds;
	struct timeval tv;
	int retval;
	
	int client_fd = -1;
	
	int is_running = 1;
	
	gpgme_ctx_t ctx;
	if (gpgsession_new(&ctx, false) != 0) {
		fprintf(stderr, "failed to generate gpg session\n");
		return;
	}
	
	while (is_running) {
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
			//set back
			FD_SET(client_fd, &rfds);
		}
		
		retval = select(FD_SETSIZE, &rfds, NULL, NULL, &tv);
		/* Don't rely on the value of tv now! */
		
		if (retval == -1){
			perror("select()");
			is_running = 0;
		}else if (retval){
			
			//listen for user input
			if (FD_ISSET(STDIN_FILENO, &rfds)) {
				static char line[256];
				
				if(fgets(line, sizeof line, stdin) != NULL) {
					char *end;
					uintmax_t num = strtoumax(line, &end, 10);
					
					if (errno == ERANGE || *end != '\n'){
						printf("Invalid command\n");
					}else if (num >= number_of_keys) {
						printf("Invalid selection\n");
					}else if(client_fd != -1) {
						printf("Sending key %s\n", list_of_keys[num]->fpr);
						int err = send_key(&ctx, list_of_keys[num], client_fd);
						if (!err) {
							printf("Sent\n");
						}else{
							printf("Error\n");
						}
					}
				}
			}
			
			//listen for new connection
			if (FD_ISSET(server_fd, &rfds)) {
				//only one connection at time
				if (client_fd != -1){
					printf(" - forcing client disconnect for a new client\n");
					client_close(client_fd);
					client_fd = -1;
				}
				
				client_fd = server_accept();
				printf(" - client connected\n");
				update_and_print_keys(&ctx);
			}
			
			//if client connected, check for input
			if (client_fd != -1 && FD_ISSET(client_fd, &rfds)){
				uint8_t buff[100];
				int ris;
				do{
					ris = client_update( client_fd, buff, sizeof(buff) );
					if (ris == -1) {
						client_fd = -1;
						printf(" - client disconnected\n");
					}else{
						if ( gpgsession_add_data(&ctx, (const char * const)buff, ris ) ) { // we imported a new key
							printf(" - client sent a key\n");
							update_and_print_keys(&ctx);
						}
					}
				}while(ris > 0);
			}
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

