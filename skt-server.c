#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <qrencode.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

const char * psk_id_hint = "openpgp-skt";
const char schema[] = "OPENPGP+SKT";
const char priority[] = "NORMAL:-CTYPE-ALL"
  ":%SERVER_PRECEDENCE:%NO_TICKETS"
  ":-VERS-TLS1.0:-VERS-TLS1.1:-VERS-DTLS1.0:-VERS-DTLS1.2"
  ":-CURVE-SECP224R1:-CURVE-SECP192R1"
  ":-SIGN-ALL"
  ":-KX-ALL:+ECDHE-PSK:+DHE-PSK"
  ":-3DES-CBC:-CAMELLIA-128-CBC:-CAMELLIA-256-CBC";

#define PSK_BYTES 16
#define LOG_LEVEL 9

struct session_status {
  gnutls_datum_t psk;
  char pskhex[PSK_BYTES*2 + 1];
};  

int get_psk_creds(gnutls_session_t session, const char* username, gnutls_datum_t* key) {
  struct session_status *status;
  status = gnutls_session_get_ptr(session);
  fprintf(stderr, "sent username: %s, PSK: %s\n", username, status->pskhex); /* FIXME: dangerous random network bytes! */
  key->size = status->psk.size;
  key->data = gnutls_malloc(status->psk.size);
  if (!key->data)
    return GNUTLS_E_MEMORY_ERROR;
  memcpy(key->data, status->psk.data, status->psk.size);
  for (int ix = 0; ix < key->size; ix++)
    fprintf(stderr, "%02x", status->psk.data[ix]);
  fprintf(stderr, "\n");
  return GNUTLS_E_SUCCESS;
}

void skt_log(int level, const char* data) {
  fprintf(stderr, "S:|<%d>| %s%s", level, data, data[strlen(data)-1] == '\n' ? "" : "\n");
}


int print_qrcode(FILE* f, const QRcode* qrcode) {
  const struct { char *data; size_t size; }  out[] = {
    { .data = "\xe2\x96\x88", .size = 3 }, /* U+2588 FULL BLOCK */
    { .data = "\xe2\x96\x80", .size = 3 }, /* U+2580 UPPER HALF BLOCK */
    { .data = "\xe2\x96\x84", .size = 3 }, /* U+2584 LOWER HALF BLOCK */
    { .data = " ", .size = 1 }, /* U+0020 SPACE */
  };
  const int margin = 2;
  int mx, my;

  if (1 != fwrite("\n", 1, 1, f)) {
    fprintf(stderr, "failed to write start of qrcode\n");
    return -1;
  }
  for (my = 0; my < margin; my++) {
    for (mx = 0; mx < qrcode->width + margin*4; mx++)
      if (1 != fwrite(out[0].data, out[0].size, 1, f)) {
        fprintf(stderr, "failed at upper margin of qrcode\n");
        return -1;
      }
    if (1 != fwrite("\n", 1, 1, f)) {
      fprintf(stderr, "failed writing newline into QR code in upper margin\n");
      return -1;
    }
  }
  
  for (int iy = 0; iy < qrcode->width; iy+= 2) {
    for (mx = 0; mx < margin*2; mx++)
      if (1 != fwrite(out[0].data, out[0].size, 1, f)) {
        fprintf(stderr, "failed at left margin of qrcode in row %d\n", iy);
        return -1;
      }
    for (int ix = 0; ix < qrcode->width; ix++) {
      int n = (qrcode->data[iy*qrcode->width + ix] & 0x01) << 1;
      if (iy+1 < qrcode->width)
        n += (qrcode->data[(iy+1)*qrcode->width + ix] & 0x01);
      if (1 != fwrite(out[n].data, out[n].size, 1, f)) {
        fprintf(stderr, "failed writing QR code at (%d,%d)\n", ix, iy);
        return -1;
      }
    }
    for (mx = 0; mx < margin*2; mx++)
      if (1 != fwrite(out[0].data, out[0].size, 1, f)) {
        fprintf(stderr, "failed at right margin of qrcode in row %d\n", iy);
        return -1;
      }
    if (1 != fwrite("\n", 1, 1, f)) {
      fprintf(stderr, "failed writing newline into QR code after line %d\n", iy);
      return -1;
    }
  }
  
  for (my = 0; my < margin; my++) {
    for (mx = 0; mx < qrcode->width + margin*4; mx++)
      if (1 != fwrite(out[0].data, out[0].size, 1, f)) {
        fprintf(stderr, "failed at lower margin of qrcode\n");
        return -1;
      }
    if (1 != fwrite("\n", 1, 1, f)) {
      fprintf(stderr, "failed writing newline into QR code in lower margin\n");
      return -1;
    }
  }

  return 0;
}

int main(int argc, const char *argv[]) {
  struct session_status status = { .psk = { .data = NULL, .size = 0 } };
  int rc;
  gnutls_session_t session = NULL;
  gnutls_psk_server_credentials_t creds = NULL;
  gnutls_priority_t priority_cache;
  int sd, sdconn;
  struct sockaddr_in6 sa_serv, *sa_serv_full;
  struct sockaddr_storage sa_serv_storage, sa_cli_storage;
  socklen_t sa_serv_storage_sz = sizeof (sa_serv_storage);
  socklen_t sa_cli_storage_sz = sizeof (sa_cli_storage);
  int optval = 1;
  char addrp[INET6_ADDRSTRLEN];
  int port;
  size_t pskhexsz = sizeof(status.pskhex);
  char urlbuf[INET6_ADDRSTRLEN + 25 + 32];
  int urllen;
  QRcode *qrcode = NULL;  

  gnutls_global_set_log_level(LOG_LEVEL);
  gnutls_global_set_log_function(skt_log);
  
  /* choose random number */  
  if ((rc = gnutls_key_generate(&status.psk, PSK_BYTES))) {
    fprintf(stderr, "failed to get randomness: (%d) %s\n", rc, gnutls_strerror(rc));
    return -1;
  }
  if ((rc = gnutls_hex_encode(&status.psk, status.pskhex, &pskhexsz))) {
    fprintf(stderr, "failed to encode PSK as a hex string: (%d) %s\n", rc, gnutls_strerror(rc));
    return -1;
  }
  if (pskhexsz != sizeof(status.pskhex)) {
    fprintf(stderr, "bad calculation for psk size\n");
    return -1;
  }
  for (int ix = 0; ix < sizeof(status.pskhex)-1; ix++)
    status.pskhex[ix] = toupper(status.pskhex[ix]);
  
  /* FIXME: pick an IP address with getifaddrs instead of using in6addr_any */
  
  /* open listening socket */
  sd = socket(AF_INET6, SOCK_STREAM, 0);
  if (sd == -1) {
    fprintf(stderr, "failed to allocate a socket: (%d) %s\n", errno, strerror(errno));
    return -1;
  }
  memset(&sa_serv, 0, sizeof(sa_serv));
  sa_serv.sin6_family = AF_INET6;
  sa_serv.sin6_addr = in6addr_any;
  sa_serv.sin6_port = htons(0);
  if ((rc = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (void *) &optval, sizeof(int)))) {
    fprintf(stderr, "failed to set SO_REUSEADDR: (%d) %s\n", errno, strerror(errno));
    return -1;
  }
  if ((rc = bind(sd, (struct sockaddr *) &sa_serv, sizeof(sa_serv)))) {
    fprintf(stderr, "failed to bind: (%d) %s\n", errno, strerror(errno));
    return -1;
  }    
  if ((rc = getsockname(sd, (struct sockaddr *) &sa_serv_storage, &sa_serv_storage_sz))) {
    fprintf(stderr, "failed to getsockname: (%d) %s\n", errno, strerror(errno));
    return -1;
  }
  if (sa_serv_storage_sz > sizeof(sa_serv_storage)) {
    fprintf(stderr, "needed more space (%d) than expected (%zd) for getsockname\n", sa_serv_storage_sz, sizeof(sa_serv_storage));
    return -1;
  }
  if (sa_serv_storage.ss_family != AF_INET6) {
    fprintf(stderr, "was expecting IPv6 address family (%d) after binding, got %d\n", AF_INET6, sa_serv_storage.ss_family);
    return -1;
  }
  sa_serv_full = (struct sockaddr_in6 *)&sa_serv_storage;
  if (NULL == inet_ntop(sa_serv_storage.ss_family, &(sa_serv_full->sin6_addr), addrp, sizeof(addrp))) {
    fprintf(stderr, "inet_ntop failed (%d) %s\n", errno, strerror(errno));
    return -1;
  }
  port = ntohs(sa_serv_full->sin6_port);
  if ((rc = listen(sd, 1024))) {
    fprintf(stderr, "failed to listen: (%d) %s\n", errno, strerror(errno));
    return -1;
  }    

  
  /* open tls server connection */
  if ((rc = gnutls_init(&session, GNUTLS_SERVER))) {
    fprintf(stderr, "failed to init session: (%d) %s\n", rc, gnutls_strerror(rc));
    return -1;
  }
  gnutls_session_set_ptr(session, &status);
  if ((rc = gnutls_psk_allocate_server_credentials(&creds))) {
    fprintf(stderr, "failed to allocate PSK credentials: (%d) %s\n", rc, gnutls_strerror(rc));
    return -1;
  }
  if ((rc = gnutls_psk_set_server_credentials_hint(creds, psk_id_hint))) {
    fprintf(stderr, "failed to set server credentials hint to '%s', ignoring…\n", psk_id_hint);
  }
  if ((rc = gnutls_psk_set_server_known_dh_params(creds, GNUTLS_SEC_PARAM_HIGH))) {
    fprintf(stderr, "failed to set server credentials known DH params: (%d) %s\n", rc, gnutls_strerror(rc));
    return -1;
  }
  gnutls_psk_set_server_credentials_function(creds, get_psk_creds);
  if ((rc = gnutls_credentials_set(session, GNUTLS_CRD_PSK, creds))) {
    fprintf(stderr, "failed to assign PSK credentials to GnuTLS server: (%d) %s\n", rc, gnutls_strerror(rc));
    return -1;
  }
  if ((rc = gnutls_priority_init(&priority_cache, priority, NULL))) {
    fprintf(stderr, "failed to set up GnuTLS priority: (%d) %s\n", rc, gnutls_strerror(rc));
    return -1;
  }
  if ((rc = gnutls_priority_set(session, priority_cache))) {
    fprintf(stderr, "failed to assign gnutls priority: (%d) %s\n", rc, gnutls_strerror(rc));
    return -1;
  }

  /* construct string */
  urlbuf[sizeof(urlbuf)-1] = 0;
  urllen = snprintf(urlbuf, sizeof(urlbuf)-1, "%s://%s@[%s]:%d", schema, status.pskhex, addrp, port);
  if (urllen >= (sizeof(urlbuf)-1)) {
    fprintf(stderr, "buffer was somehow truncated.\n");
    return -1;
  }
  if (urllen < 5) {
    fprintf(stderr, "printed URL was somehow way too small (%d).\n", urllen);
    return -1;
  }
  fprintf(stdout, "%s\n", urlbuf);
      
  /* generate qrcode (can't use QR_MODE_AN because of punctuation in URL) */
  qrcode = QRcode_encodeString(urlbuf, 0, QR_ECLEVEL_L, QR_MODE_8, 0);
  if (qrcode == NULL) {
    fprintf(stderr, "failed to encode string as QRcode: (%d) %s\n", errno, strerror(errno));
    return -1;
  }
  
  /* display qrcode */
  if ((rc = print_qrcode(stdout, qrcode))) {
    fprintf(stderr, "failed to print qr code\n");
    return -1;
  }

  /* for test purposes... */
  fprintf(stdout, "gnutls-cli --debug %d --priority %s --port %d --pskusername %s --pskkey %s localhost\n",
          LOG_LEVEL, priority, port, psk_id_hint, status.pskhex);
  
  /* wait for connection to come in */
  sdconn = accept(sd, (struct sockaddr *) &sa_cli_storage, &sa_cli_storage_sz);

  gnutls_transport_set_int(session, sdconn);

  do rc = gnutls_handshake(session);
  while (rc < 0 && gnutls_error_is_fatal(rc) == 0);

  if (rc < 0) {
    fprintf(stderr, "TLS Handshake failed (%d) %s\n", rc, gnutls_strerror(rc));
    return -1;
  }

  
  /* if handshake succeeds, prompt user for key */
  /* send key */
  /* store incoming key */
  /* write incoming key */

  /* cleanup */
                
  gnutls_deinit(session);
  gnutls_priority_deinit(priority_cache);
  gnutls_psk_free_server_credentials(creds);
  QRcode_free(qrcode);
  return 0;
}

  
