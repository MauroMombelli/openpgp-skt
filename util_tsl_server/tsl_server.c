#include "tsl_server.h"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
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


#define SOCKET_ERR(err,s) if(err==-1) {perror(s);return(-1);}
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
};

gnutls_psk_server_credentials_t creds = NULL;
struct session_tsl * clients[FD_SETSIZE] = {0};

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
	SOCKET_ERR(listen_sd, "socket_server_creation");
	
	struct sockaddr_in sa_serv;
	memset(&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons(port); /* Server Port number */
	
	int optval = 1;
	setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, (void *) &optval, sizeof(int));
	int err;
	err = bind(listen_sd, (struct sockaddr *) &sa_serv, sizeof(sa_serv));
	SOCKET_ERR(err, "socket_server_bind");
	err = listen(listen_sd, 5);
	SOCKET_ERR(err, "socket_server_listen");
	
	printf("Server ready. Listening to port '%d'.\n\n", port);

	return listen_sd;
}

int client_handshake(int fd) {
	printf("client hadshake happening: %d\n", fd);
	int ret = gnutls_handshake(clients[fd]->session);
	
	switch(ret) {
		case GNUTLS_E_WARNING_ALERT_RECEIVED:
			;
			gnutls_alert_description_t alert;
			alert = gnutls_alert_get(clients[fd]->session);
			fprintf(stderr, "Got GnuTLS alert (%d) %s\n", alert, gnutls_alert_get_name(alert));
			return 0; //fail, but not fatal
		case GNUTLS_E_INTERRUPTED:
		case GNUTLS_E_AGAIN:
			fprintf(stderr, "gnutls_handshake() got (%d) %s\n", ret, gnutls_strerror(ret));
			return 0; //fail, but not fatal
		case GNUTLS_E_SUCCESS:
			clients[fd]->status = OPEN;
			return 0; // success!
		default:
			close( fd );
			gnutls_deinit(clients[fd]->session);
			fprintf(stderr, "*** Handshake has failed (%s)\n\n", gnutls_strerror(ret));
			clients[fd]->status = CLOSED;
			return -1; //fail, fatal
	}
	fprintf(stderr, "No handshake completed\n");
}

int client_read(const int fd, void * const buffer, const size_t size) {
	printf ("\n- Start read\n");
	int ret = gnutls_record_recv(clients[fd]->session, buffer, size);
	printf ("\n- END read\n");
	if (ret == GNUTLS_E_AGAIN){
		printf ("\n- Peer did not sent data\n");
		return 0;
	}else if (ret == 0) {
		printf ("\n- Peer has closed the GnuTLS connection\n");
		client_close(fd);
		return -1;
	} else if (ret < 0 && gnutls_error_is_fatal(ret) == 0) { 
		fprintf(stderr, "*** Warning: %s\n", gnutls_strerror(ret));
	} else if (ret < 0) {
		fprintf(stderr, "\n*** Received corrupted data(%d). Closing the connection.\n\n", ret);
		return -1;
	} else if (ret > 0) {
		/* echo data back to the client */
		//gnutls_record_send(clients[i].session, buffer, ret);
	}
	
	return ret;
}


int client_update(const int fd, void * const buffer, const size_t size) {
	
	switch (clients[fd]->status) {
		case HANDSHAKE:
			return client_handshake(fd);
		case OPEN:
			return client_read(fd, buffer, size);
		default:
			client_close(fd);
			return -1;
	}
	
}

int server_accept() {
	
	struct sockaddr sa_cli;
	socklen_t client_len = sizeof(sa_cli);
	
	int client_fd = accept4(listen_sd, (struct sockaddr *) &sa_cli, &client_len, SOCK_NONBLOCK); /*SOCK_NONBLOCK*/
	
	if (client_fd < 1) {
		fprintf(stderr, "failed accept any client %d\n", client_fd);
		perror("err");
		return -1;
	}
	
	if (clients[client_fd] == NULL) {
		clients[client_fd] = malloc( sizeof(struct session_tsl) );
		if (clients[client_fd] == 0){
			perror("failed to accept client, out of RAM?");
			return -1;
		}
	}
	printf("client connected\n");
	
	/* open tls server connection */
	int rc;
	rc = gnutls_init(&(clients[client_fd]->session), GNUTLS_SERVER | GNUTLS_NONBLOCK);
	if (rc) {
		fprintf(stderr, "failed to init session: (%d) %s\n", rc, gnutls_strerror(rc));
		return -1;
	}
	gnutls_psk_set_server_credentials_function(creds, get_psk_creds);
	rc = gnutls_credentials_set(clients[client_fd]->session, GNUTLS_CRD_PSK, creds);
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
	
	rc = gnutls_priority_init(&(clients[client_fd]->priority_cache), priority, NULL);
	if (rc) {
		fprintf(stderr, "failed to set up GnuTLS priority: (%d) %s\n", rc, gnutls_strerror(rc));
		return -1;
	}
	rc = gnutls_priority_set(clients[client_fd]->session, clients[client_fd]->priority_cache);
	if (rc) {
		fprintf(stderr, "failed to assign gnutls priority: (%d) %s\n", rc, gnutls_strerror(rc));
		return -1;
	}
	
	gnutls_transport_set_int(clients[client_fd]->session, client_fd);
	
	clients[client_fd]->status = HANDSHAKE;
	
	return client_fd;
}

int client_close(const int fd) {
	
	gnutls_bye(clients[fd]->session, GNUTLS_SHUT_RDWR);
	
	close(fd);
	gnutls_deinit(clients[fd]->session);
	
	clients[fd]->status = CLOSED;
	
	return 0;
}
