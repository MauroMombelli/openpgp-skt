#include "tsl_server.h"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <gnutls/gnutls.h>


#include <ctype.h> //for toupper, test
/* 
 * This is absed form TLS 1.0 sample echo server, http://gnutls.org/manual/html_node/Echo-server-with-anonymous-authentication.html#Echo-server-with-anonymous-authentication
 */


#define SOCKET_ERR(err,s) if(err==-1) {perror(s);return(1);}
#define MAX_BUF 1024

#define MAX_CLIENTS 1

const char psk_id_hint[] = "openpgp-skt";

enum connection_status{
	CLOSED = 0,  //force enum CLOSED to be 0, so we can initialize the struct to 0 and will be closed
	HANDSHAKE, 
	OPEN
};

struct session_tsl{
	gnutls_session_t session;
	gnutls_priority_t priority_cache;
	enum connection_status status;
	int socket_id;
};

gnutls_psk_server_credentials_t creds = NULL;
struct session_tsl clients[MAX_CLIENTS] = {0};

int listen_sd;

gnutls_datum_t psk;

int get_psk_creds(gnutls_session_t session, const char* username, gnutls_datum_t* key) {
	//skt = gnutls_session_get_ptr(session);
	
	//if (skt->log_level > 2)
	for (int i = 0; i < sizeof(psk_id_hint); i++) {
		if (username[i] != psk_id_hint[i]){
			fprintf(stderr, "sent username is invalid: %s\n", username /* dangerous: random bytes from the network! */); 
			return -1;
		}
	}
	
	key->size = psk.size;
	key->data = gnutls_malloc(psk.size);
	if (!key->data)
		return -1;
	memcpy(key->data, psk.data, psk.size);
	return 0;
}

int server_create(char * const pskhex) {
	int rc;
	
	/* choose random number */  
	rc = gnutls_key_generate(&psk, PSK_BYTES);
	if (rc) {
		fprintf(stderr, "failed to get randomness: (%d) %s\n", rc, gnutls_strerror(rc));
	}
	
	size_t pskhexsz;
	if ((rc = gnutls_hex_encode(&psk, pskhex, &pskhexsz))) {
		fprintf(stderr, "failed to encode PSK as a hex string: (%d) %s\n", rc, gnutls_strerror(rc));
		return -1;
	}

	for (int ix = 0; ix < pskhexsz; ix++)
		pskhex[ix] = toupper(pskhex[ix]);
	
	
	//TODO: gnutls_session_set_ptr(skt->session, skt);
	//gnutls_transport_set_pull_function(skt->session, skt_session_gnutls_pull_func);
	//gnutls_transport_set_push_function(skt->session, skt_session_gnutls_push_func);
	//TODO: gnutls_transport_set_ptr(skt->session, skt);
	
	rc = gnutls_psk_allocate_server_credentials(&creds);
	if (rc) {
		fprintf(stderr, "failed to allocate PSK credentials: (%d) %s\n", rc, gnutls_strerror(rc));
		return -1;
	}
	
	rc = gnutls_psk_set_server_credentials_hint(creds, psk_id_hint);
	if (rc) {
		fprintf(stderr, "failed to set server credentials hint to '%s', ignoring…\n", psk_id_hint);
	}
	rc = gnutls_psk_set_server_known_dh_params(creds, GNUTLS_SEC_PARAM_HIGH);
	if (rc) {
		fprintf(stderr, "failed to set server credentials known DH params: (%d) %s\n", rc, gnutls_strerror(rc));
		return -1;
	}
	
	return 0;
}

int server_close() {
	
	close(listen_sd);
	
	gnutls_global_deinit();
	
	return 0;
}

int server_bind(const int port) {
	/*
	 * Socket operations
	 */
	listen_sd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	SOCKET_ERR(listen_sd, "socket");
	
	struct sockaddr_in sa_serv;
	memset(&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons(port); /* Server Port number */
	
	int optval = 1;
	setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, (void *) &optval, sizeof(int));
	int err;
	err = bind(listen_sd, (struct sockaddr *) &sa_serv, sizeof(sa_serv));
	SOCKET_ERR(err, "bind");
	err = listen(listen_sd, 1024);
	SOCKET_ERR(err, "listen");
	
	printf("Server ready. Listening to port '%d'.\n\n", port);

	return 0;
}

int client_close(const int i) {
	gnutls_bye(clients[i].session, GNUTLS_SHUT_RDWR);
	
	close(clients[i].socket_id);
	gnutls_deinit(clients[i].session);
	
	clients[i].status = CLOSED;
	
	return 0;
}

int client_read(const int i, void * const buffer, const size_t size){
	int ret = gnutls_record_recv(clients[i].session, buffer, size);
	
	if (ret == 0) {
		printf ("\n- Peer has closed the GnuTLS connection\n");
		client_close(i);
		return -1;
	} else if (ret < 0 && gnutls_error_is_fatal(ret) == 0) { 
		fprintf(stderr, "*** Warning: %s\n", gnutls_strerror(ret));
	} else if (ret < 0) {
		fprintf(stderr, "\n*** Received corrupted data(%d). Closing the connection.\n\n", ret);
		return -1;
	} else if (ret > 0) {
		/* echo data back to the client */
		gnutls_record_send(clients[i].session, buffer, ret);
	}
	
	return 0;
}

int server_handshake() {
	for(unsigned int i = 0; i < MAX_CLIENTS; i++) {
		if (clients[i].status != HANDSHAKE){
			continue;
		}
		
		
		int ret = gnutls_handshake(clients[i].session);
		
		if (ret < 0 && gnutls_error_is_fatal(ret) != 0) {
			close( clients[i].socket_id );
			gnutls_deinit(clients[i].session);
			fprintf(stderr, "*** Handshake has failed (%s)\n\n", gnutls_strerror(ret));
			clients[i].status = CLOSED;
			continue;
		}
		if (ret){
			printf("- Handshake was completed\n");
			clients[i].status = OPEN;
			return i;
		}		
	}
	
	return -1;
}

int server_accept() {
	
	struct sockaddr_storage sa_cli;
	socklen_t client_len;
	
	int sd = accept(listen_sd, (struct sockaddr *) &sa_cli, &client_len); /*SOCK_NONBLOCK*/
	
	if (sd < 1) {
		//fprintf(stderr, "failed accept any client %d\n", sd);
		return 1;
	}
	
	printf("client connected\n");
	
	int client_index = -1;
	
	for(unsigned int i = 0; i < MAX_CLIENTS; i++) {
		if (clients[i].status == CLOSED){
			client_index = i;
		}
	}
	
	if (client_index == -1) {
		fprintf(stderr, "too many client connected\n");
		return -1;
	}
	
	clients[client_index].socket_id = sd;
	
	/* open tls server connection */
	int rc;
	rc = gnutls_init(&(clients[client_index].session), GNUTLS_SERVER | GNUTLS_NONBLOCK);
	if (rc) {
		fprintf(stderr, "failed to init session: (%d) %s\n", rc, gnutls_strerror(rc));
		return -1;
	}
	gnutls_psk_set_server_credentials_function(creds, get_psk_creds);
	rc = gnutls_credentials_set(clients[client_index].session, GNUTLS_CRD_PSK, creds);
	if (rc) {
		fprintf(stderr, "failed to assign PSK credentials to GnuTLS server: (%d) %s\n", rc, gnutls_strerror(rc));
		return -1;
	}
	
	const char priority[] = "NORMAL:-CTYPE-ALL"
	":%SERVER_PRECEDENCE:%NO_TICKETS"
	":-VERS-TLS1.0:-VERS-TLS1.1:-VERS-DTLS1.0:-VERS-DTLS1.2"
	":-CURVE-SECP224R1:-CURVE-SECP192R1"
	":-SIGN-ALL"
	":-KX-ALL:+ECDHE-PSK:+DHE-PSK"
	":-3DES-CBC:-CAMELLIA-128-CBC:-CAMELLIA-256-CBC";
	
	rc = gnutls_priority_init(&(clients[client_index].priority_cache), priority, NULL);
	if (rc) {
		fprintf(stderr, "failed to set up GnuTLS priority: (%d) %s\n", rc, gnutls_strerror(rc));
		return -1;
	}
	rc = gnutls_priority_set(clients[client_index].session, clients[client_index].priority_cache);
	if (rc) {
		fprintf(stderr, "failed to assign gnutls priority: (%d) %s\n", rc, gnutls_strerror(rc));
		return -1;
	}
	
	gnutls_transport_set_int(clients[client_index].session, sd);
	
	clients[client_index].status = HANDSHAKE;
	
	return 0;
}
