#include <assert.h>
#include <stdarg.h>
#include <ctype.h>
#include <stdlib.h>
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
#include <ifaddrs.h>
#include <net/if.h>
#include <stdbool.h>
#include <unistd.h>
#include <gpgme.h>
#include <uv.h>
#include <iwlib.h>

const char * psk_id_hint = "openpgp-skt";
const char schema[] = "OPGPSKT";
const char priority[] = "NORMAL:-CTYPE-ALL"
  ":%SERVER_PRECEDENCE:%NO_TICKETS"
  ":-VERS-TLS1.0:-VERS-TLS1.1:-VERS-DTLS1.0:-VERS-DTLS1.2"
  ":-CURVE-SECP224R1:-CURVE-SECP192R1"
  ":-SIGN-ALL"
  ":-KX-ALL:+ECDHE-PSK:+DHE-PSK"
  ":-3DES-CBC:-CAMELLIA-128-CBC:-CAMELLIA-256-CBC";
const char pgp_begin[] = "-----BEGIN PGP PRIVATE KEY BLOCK-----";
const char pgp_end[] = "\n-----END PGP PRIVATE KEY BLOCK-----";

#define ANSI_ESC "\x1b["
#define PSK_BYTES 16
#define KEYS_PER_PAGE 8

typedef struct skt_session skt_st;

struct gpgkey {
  char *fpr;
  gpgme_key_t key;
  bool refresh;
};

int print_qrcode(FILE* f, const QRcode* qrcode);
int print_address_name(struct sockaddr_storage *addr, char *paddr, size_t paddrsz, int *port);
void its_all_over(skt_st *skt, const char *fmt, ...);
void skt_session_connect(uv_stream_t* server, int status);
int skt_session_gather_secret_keys(skt_st *skt);
int skt_session_close_tls(skt_st *skt);
void skt_session_cleanup_listener(uv_handle_t* handle);
int skt_session_import_incoming_key(skt_st *skt, gpgme_key_t k);
int recursive_unlink(const char *pathname, int log_level);
void clearscreen(FILE *f);


struct gpgsession {
  gpgme_ctx_t ctx;
  char *homedir; /* NULL if the default */
  struct gpgkey *keys;
  size_t num_keys;
  size_t keylist_offset;
  char base_key;
  const char *name;

  void (*instructions)(struct gpgsession *session, FILE *f);
};

void gpgsession_free(struct gpgsession *session, int log_level);
struct gpgsession * gpgsession_new(bool ephemeral, char base_key, const char *name, void (*instructions)(struct gpgsession *session, FILE *f));
void gpgsession_display(struct gpgsession *session, FILE *f);
void gpgsession_instructions_base(struct gpgsession *session, FILE *f);
void gpgsession_instructions_incoming(struct gpgsession *session, FILE *f);

struct skt_session {
  uv_loop_t *loop;
  uv_tcp_t listen_socket;
  uv_tcp_t accepted_socket;
  gnutls_datum_t psk;
  char addrp[INET6_ADDRSTRLEN];
  int port;
  char caddrp[INET6_ADDRSTRLEN];
  int cport;
  char pskhex[PSK_BYTES*2 + 1];
  struct sockaddr_storage sa_serv_storage;
  struct sockaddr_storage sa_cli_storage;
  int sa_serv_storage_sz;
  int sa_cli_storage_sz;
  gnutls_session_t session;
  
  gnutls_datum_t incomingkey;
  size_t incomingkeylen;

  struct gpgsession *base;
  struct gpgsession *incoming;
  struct gpgsession *fromfile;
  
  struct ifaddrs *ifap;
  char *essid;
  int iwcfgfd;
  
  char tlsreadbuf[65536];
  size_t start;
  size_t end;
  bool handshake_done;
  bool active;
  uv_tty_t input;
  int log_level;
};


void skt_session_free(skt_st *skt) {
  if (skt) {
    if (skt->base)
      gpgsession_free(skt->base, skt->log_level);
    if (skt->incoming)
      gpgsession_free(skt->incoming, skt->log_level);
    if (skt->incomingkey.data) {
      free(skt->incomingkey.data);
    }
    if (skt->session) {
      skt_session_close_tls(skt);
    }
    if (skt->ifap)
      freeifaddrs(skt->ifap);
    if (skt->essid)
      free(skt->essid);
    if (skt->iwcfgfd >= 0)
      iw_sockets_close(skt->iwcfgfd);
    free(skt);
  }
}


void gpgsession_free(struct gpgsession *session, int log_level) {
  if (!session)
    return;
  if (session->keys) {
    for (int ix = 0; ix < session->num_keys; ix++)
      gpgme_key_unref(session->keys[ix].key);
    free(session->keys);
  }
  if (session->ctx)
    gpgme_release(session->ctx);
  if (session->homedir) {
    /* Really tear down the ephemeral homedir -- yikes! */
    if (recursive_unlink(session->homedir, log_level))
      fprintf(stderr, "failed to recursively remove ('%s'): (%d) %s\n", session->homedir, errno, strerror(errno));
    
    /* FIXME: should we also try to kill all running daemons?*/
    free(session->homedir);
  }
  free(session);
}

bool gpgsession_can_handle_keypress(struct gpgsession *session, char key) {
  if (key == 'n' && session->num_keys > KEYS_PER_PAGE)
    return true;
  /* only accept if we're on a page with sufficient keys */
  if (key >= session->base_key && key < session->base_key + KEYS_PER_PAGE)
    return (session->keylist_offset + (key - session->base_key)) < session->num_keys;
  return false;
}

struct gpgkey * gpgsession_fetch_key(struct gpgsession *session, char key) {
  if (key == 'n')  {
    if (session->num_keys <= KEYS_PER_PAGE)
      fprintf(stderr, "No more keys to display\n");
    else {
      session->keylist_offset += 8;
      if (session->keylist_offset >= session->num_keys)
        session->keylist_offset = 0;
      gpgsession_display(session, stdout);
    }
    return NULL;
  }
  if (key >= session->base_key && key < session->base_key + KEYS_PER_PAGE) {
    int kx = (session->keylist_offset + (key - session->base_key));
    if (kx >= session->num_keys) {
      fprintf(stderr, "not enough keys available for %s (wanted #%d, have %zd)!", session->name, kx, session->num_keys);
    } else {
      return session->keys + kx;
    }      
  }
  return NULL;
}




int gpgsession_add_key(struct gpgsession *session, gpgme_key_t key) {
  session->num_keys++;
  struct gpgkey * update = realloc(session->keys, sizeof(session->keys[0]) * session->num_keys);
  if (!update) {
    fprintf(stderr, "out of memory allocating new gpgme_key_t\n");
    return -1;
  }
  
  session->keys = update;
  session->keys[session->num_keys-1].key = key;
  session->keys[session->num_keys-1].fpr = strdup(key->fpr);
  session->keys[session->num_keys-1].refresh = false;
  gpgme_key_ref(key);
  return 0;
}

int gpgsession_add_fpr(struct gpgsession *session, const char *fpr) {
  /* check if we already have it */
  for (int ix = 0; ix < session->num_keys; ix++) {
    if (!strcmp(session->keys[ix].fpr, fpr)) {
      session->keys[ix].refresh = true;
      return 0;
    }
  }

  session->num_keys++;
  struct gpgkey * update = realloc(session->keys, sizeof(session->keys[0]) * session->num_keys);
  if (!update) {
    fprintf(stderr, "out of memory allocating new gpgme_key_t\n");
    return -1;
  }
  
  session->keys = update;
  session->keys[session->num_keys-1].key = NULL;
  session->keys[session->num_keys-1].fpr = strdup(fpr);
  session->keys[session->num_keys-1].refresh = true;
  return 0;
}

struct gpgsession * gpgsession_new(bool ephemeral, char base_key, const char *name, void (*instructions)(struct gpgsession *session, FILE *f)) {
  struct gpgsession *ret;
  gpgme_error_t gerr;
  int rc;
  char *xdg = NULL;
  bool xdgf = false;
  ret = calloc(1, sizeof(struct gpgsession));
  if (!ret)
    return NULL;

  if (ephemeral) {
    xdg = getenv("XDG_RUNTIME_DIR");
    if (xdg == NULL) {
      rc = asprintf(&xdg, "/run/user/%d", getuid());
      if (rc == -1) {
        fprintf(stderr, "failed to guess user ID during ephemeral GnuPG setup.\r\n");
        goto fail;
      }
      xdgf = true;
    }

    if (F_OK != access(xdg, W_OK)) {
      fprintf(stderr, "We don't have write access to '%s' for GnuPG ephemeral dir, falling back...\n", xdg);
      free(xdg);
      xdgf = false;
      xdg = getenv("TMPDIR");
      if (xdg == NULL || (F_OK != access(xdg, W_OK))) {
        if (xdg != NULL)
          fprintf(stderr, "We don't have write access to $TMPDIR ('%s') for GnuPG ephemeral dir, falling back to /tmp\n", xdg);
        xdg = "/tmp";
      }
    }
    
    rc = asprintf(&ret->homedir, "%s/skt-server.XXXXXX", xdg);
    if (rc == -1) {
      fprintf(stderr, "Failed to allocate ephemeral GnuPG directory name in %s\n", xdg);
      goto fail;
    }
    if (NULL == mkdtemp(ret->homedir)) {
      fprintf(stderr, "failed to generate an ephemeral GnuPG homedir from template '%s'\n", ret->homedir);
      goto fail;
    }
  }
    
  if ((gerr = gpgme_new(&ret->ctx))) {
    fprintf(stderr, "gpgme_new failed when setting up ephemeral incoming directory: (%d), %s\n",
            gerr, gpgme_strerror(gerr));
    goto fail;
  }
  if ((gerr = gpgme_ctx_set_engine_info(ret->ctx, GPGME_PROTOCOL_OpenPGP, NULL, ret->homedir))) {
    fprintf(stderr, "gpgme_ctx_set_engine_info failed%s%s%s: (%d), %s\n",
            ephemeral?" ephemeral (":"",
            ephemeral?ret->homedir:"",
            ephemeral?")":"",
            gerr, gpgme_strerror(gerr));
    goto fail;
  }
  gpgme_set_armor(ret->ctx, 1);

  ret->base_key = base_key;
  ret->name = name;
  ret->instructions = instructions;
  return ret;
 fail:
  if (xdgf)
    free(xdg);
  if (ret) {
    if (ret->homedir) {
      if (rmdir(ret->homedir))
        fprintf(stderr, "failed to rmdir('%s'): (%d) %s\n", ret->homedir, errno, strerror(errno));
      free(ret->homedir);
    }
    free(ret);
  }
  return NULL;
}

int recursive_unlink(const char *path, int log_level) {
  int rc;
  errno = 0;
  DIR *d = opendir(path);
  if (d == NULL)
    return errno;
  struct dirent *de = NULL;
  while ((de = readdir(d))) {
    /* ignore . and .. */
    if (de->d_name[0] == '.' &&
        (de->d_name[1] == '\0' ||
         (de->d_name[1] == '.' && de->d_name[2] == '\0')))
      continue;
    if (log_level > 2)
      fprintf(stderr, "unlinking %s/%s\n", path, de->d_name);
    if (de->d_type == DT_DIR) {
      char *child = NULL;
      rc = asprintf(&child, "%s/%s", path, de->d_name);
      if (rc == -1)
        return ENOMEM;
      rc = recursive_unlink(child, log_level);
      free(child);
      if (rc)
        return rc;
    } else {
      rc = unlinkat(dirfd(d), de->d_name, 0);
      if (rc) {
        fprintf(stderr, "unlinkat(\"%s\", \"%s\", 0) failed: (%d) %s\n",
                path, de->d_name, rc, strerror(rc));
        return rc;
      }
    }
  }
  return rmdir(path);
}

void input_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
  /*  skt_st *skt = handle->data; */
  buf->base = malloc(1);
  buf->len = buf->base ? 1 : 0;
}

ssize_t skt_session_gpgme_write(void *h, const void *buf, size_t sz) {
  skt_st *skt = h;
  if (skt->log_level > 3)
    fprintf(stderr, "got %zd octets of data from gpgme (%p)\n", sz, (void*)skt);
  int rc = gnutls_record_send(skt->session, buf, sz); /* FIXME: blocking */
  if (rc < 0) {
    switch (rc) {
    case GNUTLS_E_AGAIN:
      errno = EAGAIN;
      return -1;
    case GNUTLS_E_INTERRUPTED:
      errno = EINTR;
      return -1;
    default:
      fprintf(stderr, "gnutls_record_send() failed: (%d) %s\n", rc, gnutls_strerror(rc));
      /* FIXME: is this a reasonable value for errno when we don't know the error? */
      errno = EINVAL;
      return -1;
    }
  }
  return sz;
}

void clearscreen(FILE* f) {
  fprintf(f, "%s", ANSI_ESC "2J" ANSI_ESC "0;0H");
  fflush(f);
}

int skt_session_import_incoming_key(skt_st *skt, gpgme_key_t k) {
  gpgme_error_t gerr;
  gpgme_data_t d[2];
  char *pattern = NULL;
  int rc;
  int fds[2];
  gpgme_export_mode_t mode = GPGME_EXPORT_MODE_SECRET;

  if (skt->log_level > 0)
    fprintf(stderr, "Importing key %s\n", k->fpr);

  if (pipe2(fds, O_CLOEXEC)) {
    fprintf(stderr, "Failed to create pipe: (%d) %s\n", errno, strerror(errno));
    return -1;
  }
  /* FIXME: these uses of GnuPG are serialized, but they should be
     parallelized at least -- there's no reason to wait for the export
     to complete to launch the import.  Even better would be to make
     them entirely non-blocking, of course */
  for (int ix = 0; ix < 2; ix++) {
    if ((gerr = gpgme_data_new_from_fd(&d[ix], fds[ix]))) {
      fprintf(stderr, "failed to initialize new gpgme data[%d]. (%d) %s\n",
              ix, gerr, gpgme_strerror(gerr));
      return ENOMEM;
    }
  }
  
  rc = asprintf(&pattern, "0x%s", k->fpr);
  if (rc == -1) {
    for (int ix = 0; ix < 2; ix++) {
      gpgme_data_release(d[ix]);
      close(fds[ix]);
    }
    return rc;
  }

  gerr = gpgme_op_export(skt->incoming->ctx, pattern, mode, d[1]);
  gpgme_data_release(d[1]);
  close(fds[1]);
  free(pattern);
  if (gerr) {
    gpgme_data_release(d[0]);
    close(fds[0]);
    fprintf(stderr, "gpgme_op_export_start() failed with this error: (%d) %s\n", gerr, gpgme_strerror(gerr));
    return EIO;
  }

  gerr = gpgme_op_import(skt->base->ctx, d[0]);
  gpgme_data_release(d[0]);
  close(fds[0]);
  if (gerr) {
    fprintf(stderr, "gpgme_op_import() failed with this error: (%d) %s\n",
            gerr, gpgme_strerror(gerr));
    return EIO;
  }
  gpgme_import_result_t result = gpgme_op_import_result(skt->base->ctx);
  if (!result) {
    fprintf(stderr, "failure to get gpgme_op_import_result().\n");
    return EIO;
  }
  bool found = false;
  for (gpgme_import_status_t s = result->imports; s; s = s->next) {
    if (!strcmp(s->fpr, k->fpr)) {
      found = true;
    } else {
      fprintf(stderr, "found surprising other fingerprint (%s) during attempt to import %s\n",
              s->fpr, k->fpr);
    }
  }
  if (!found) {
    fprintf(stderr, "Did not see expected fingerprint %s during import\n", k->fpr);
    return EIO;
  }
    
  return 0;
}


/* FIXME: should be const, but gpgme is cranky */
struct gpgme_data_cbs gpg_callbacks = { .write = skt_session_gpgme_write };

int skt_session_send_key(skt_st *skt, gpgme_key_t key) {
  int rc = 0;
  gpgme_error_t gerr = 0;
  gpgme_export_mode_t mode = GPGME_EXPORT_MODE_MINIMAL | GPGME_EXPORT_MODE_SECRET;
  char *pattern = NULL;
  gpgme_data_t data = NULL;

  skt->active = true;
  rc = asprintf(&pattern, "0x%s", key->fpr);
  if (rc == -1) {
    fprintf(stderr, "failed to malloc appropriately!\n");
    return -1;
  }
  if ((gerr = gpgme_data_new_from_cbs(&data, &gpg_callbacks, skt))) {
    free(pattern);
    fprintf(stderr, "failed to make new gpgme_data_t object: (%d) %s\n", gerr, gpgme_strerror(gerr));
    return -1;
  }
  /* FIXME: blocking! */
  if ((gerr = gpgme_op_export(skt->base->ctx, pattern, mode, data))) {
    free(pattern);
    fprintf(stderr, "failed to export key: (%d) %s\n", gerr, gpgme_strerror(gerr));
    return -1;
  }
  free(pattern);

  gpgme_data_release(data);
  return 0;
}

void ctrl_c(skt_st *skt) {
  its_all_over(skt, "got ctrl-c\n");
}

void ctrl_d(skt_st *skt) {
  its_all_over(skt, "got ctrl-d\n");
}


void ctrl_l(skt_st *skt) {
  /* FIXME: refresh the screen */
}

void quit(skt_st *skt) {
  its_all_over(skt, "quitting…\n");
}

void input_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
  skt_st *skt = stream->data;
  if (nread > 0) {
    int c = buf->base[0];
    if (c == 3) {
      ctrl_c(skt);
    } else if (c == 4) {
      ctrl_d(skt);
    } else if (c == 12) {
      ctrl_l(skt);
    } else if (tolower(c) == 'q' || c == 0x1B /* ESC */) {
      quit(skt);
    } else if (skt->incoming) {
      if (gpgsession_can_handle_keypress(skt->incoming, c)) {
        struct gpgkey *k = gpgsession_fetch_key(skt->incoming, c);
        if (k) {
          if (skt_session_import_incoming_key(skt, k->key)) {
            fprintf(stderr, "Failed to import key with fingeprint %s!\n", k->fpr);
          }
        }
      }
    } else if (skt->handshake_done && gpgsession_can_handle_keypress(skt->base, c)) {
      struct gpgkey *k = gpgsession_fetch_key(skt->base, c);
      if (k)
        skt_session_send_key(skt, k->key);
    } else if (c == '0') {
      fprintf(stderr, "FIXME: sending a file from active mode is not yet implemented!\n");
    } else {
      if (skt->log_level > 2)
        fprintf(stderr, "Got %d (0x%02x) '%.1s'\n", buf->base[0], buf->base[0], isprint(buf->base[0])? buf->base : "_");
    }
  } else if (nread < 0) {
    its_all_over(skt, "Got error during input_read_cb: (%d) %s\n", nread, uv_strerror(nread));
  }
  if (buf && buf->base)
    free(buf->base);
}

/* FIXME: tried to use this callback to do
   uv_tty_set_mode(&skt->input, UV_TTY_MODE_NORMAL), but it kept
   giving errors. */
void input_close_cb(uv_handle_t *handle) {
  skt_st *skt = handle->data;

  if (skt->log_level > 5) {
    fprintf(stderr, "input_close_cb()\n");
  }
}

skt_st * skt_session_new(uv_loop_t *loop, int log_level) {
  skt_st *skt = calloc(1, sizeof(skt_st));
  size_t pskhexsz = sizeof(skt->pskhex);
  int rc;
  
  if (skt) {
    skt->loop = loop;
    skt->log_level = log_level;
    skt->sa_serv_storage_sz = sizeof (skt->sa_serv_storage);
    skt->sa_cli_storage_sz = sizeof (skt->sa_cli_storage);
    skt->iwcfgfd = iw_sockets_open();
    if (skt->iwcfgfd < 0) /* non-fatal error */
      fprintf(stderr, "Warning: unable to learn about wireless configuration\n"); 

    skt->base = gpgsession_new(false, '1', "base", gpgsession_instructions_base);
    if (!skt->base) {
      fprintf(stderr, "failed to prepare base GnuPG session\n");
      goto fail;
    }

    /* choose random number */  
    if ((rc = gnutls_key_generate(&skt->psk, PSK_BYTES))) {
      fprintf(stderr, "failed to get randomness: (%d) %s\n", rc, gnutls_strerror(rc));
      goto fail;
    }
    if ((rc = gnutls_hex_encode(&skt->psk, skt->pskhex, &pskhexsz))) {
      fprintf(stderr, "failed to encode PSK as a hex string: (%d) %s\n", rc, gnutls_strerror(rc));
      goto fail;
    }
    if (pskhexsz != sizeof(skt->pskhex)) {
      fprintf(stderr, "bad calculation for psk size\n");
      goto fail;
    }
    for (int ix = 0; ix < sizeof(skt->pskhex)-1; ix++)
      skt->pskhex[ix] = toupper(skt->pskhex[ix]);
  }
 return skt;
 fail:
  skt_session_free(skt);
  return NULL;
}

int skt_session_choose_address(skt_st* skt) {
  struct ifaddrs *ifa;
  struct wireless_config x; /* just for size info */
  struct {
    int myfamily;
    struct sockaddr *myaddr;
    bool has_essid;
    size_t essid_len;
    bool is_wifi;
    char essid[sizeof(x.essid)];
  } selected = { .myfamily = 0 };
  int rc;
  /*  int optval = 1; */
  
  /* pick an IP address with getifaddrs instead of using in6addr_any */
  if (getifaddrs(&skt->ifap)) {
    fprintf(stderr, "getifaddrs failed: (%d) %s\n", errno, strerror(errno));
    return -1;
  }
    
  for (ifa = skt->ifap; ifa; ifa = ifa->ifa_next) {
    char addrstring[INET6_ADDRSTRLEN];
    bool skip = false;
    int family = 0;
    bool is_wifi = false;
    struct wireless_config cfg;
    
    if (ifa->ifa_addr) {
      family = ((struct sockaddr_storage*)(ifa->ifa_addr))->ss_family;
      void * ptr = NULL;
      if (family == AF_INET6)
        ptr = &((struct sockaddr_in6*)(ifa->ifa_addr))->sin6_addr;
      else if (family == AF_INET)
        ptr = &((struct sockaddr_in*)(ifa->ifa_addr))->sin_addr;
      else if (family == AF_PACKET) 
        skip = true; /* struct rtnl_link_stats *stats = ifa->ifa_data */
      if (!skip)
        inet_ntop(family, ptr, addrstring, sizeof(addrstring));
      else
        strcpy(addrstring, "<unknown family>");
    } else {
      strcpy(addrstring, "<no address>");
    }
    if (ifa->ifa_flags & IFF_LOOPBACK) {
      if (skt->log_level > 2)
        fprintf(stderr, "skipping %s because it is loopback\n", ifa->ifa_name);
      continue;
    }
    if (!(ifa->ifa_flags & IFF_UP)) {
      if (skt->log_level > 2)
        fprintf(stderr, "skipping %s because it is not up\n", ifa->ifa_name);
      continue;
    }
    if (!skip) {
      if (skt->iwcfgfd >= 0) {
        if (iw_get_basic_config(skt->iwcfgfd, ifa->ifa_name, &cfg)) {
          if (errno == EOPNOTSUPP) {
            if (skt->log_level > 2)
              fprintf(stderr, "interface %s is not Wi-Fi\n", ifa->ifa_name);
          } else {
            fprintf(stderr, "failed to get wireless info: (%d) %s\n", errno, strerror(errno));
          }
        } else {
          is_wifi = true;
          if (cfg.has_essid) {
            if (cfg.essid_len >= sizeof(cfg.essid)) {
              fprintf(stderr, "essid is longer (%d octets) than we can handle (%zd octets)\n",
                      cfg.essid_len, sizeof(cfg.essid)-1);              
            } else {
              if (skt->log_level > 2) {
                bool essid_printable = true;
                /* avoid un-URL-able symbols in the essid */
                for (const char *c = cfg.essid; c < cfg.essid + cfg.essid_len; c++) {
                  if (!(isascii(*c) && isgraph(*c) && (NULL == strchr("%&+", *c)))) {
                    fprintf(stderr, "unprintable octet 0x%02x in essid, we will not log it raw\n", *c);
                    essid_printable = false;
                    break;
                  }
                }
                fprintf(stderr, "%s has ESSID: ", ifa->ifa_name);
                if (essid_printable) 
                  fwrite(cfg.essid, cfg.essid_len, 1, stderr);
                else {
                  fprintf(stderr, "(hex:)");
                  for (const char *c = cfg.essid; c < cfg.essid + cfg.essid_len; c++) 
                    fprintf(stderr, "%02X", *c);
                }
                fprintf(stderr, "\n");
              }
            }
          } else {
            fprintf(stderr, "Interface %s is wifi, but has no ESSID!\n", ifa->ifa_name);
          }
        }
      }
      /* if a wifi NIC is up and has a printable ESSID, we'll take it.
         Otherwise, we will just take the first up, non-loopback address */
      /* FIXME: be cleverer about preferring link-local addresses, and RFC1918 addressses. */
      bool takeit = selected.myaddr == NULL ||
        (is_wifi && (!selected.is_wifi ||
                     (cfg.has_essid && !selected.has_essid)));
      if (skt->log_level > 2)
        fprintf(stdout, "%s %s: %s (flags: 0x%x)\n", takeit?"*":" ", ifa->ifa_name, addrstring, ifa->ifa_flags);
      if (takeit) {
        selected.myfamily = family;
        selected.myaddr = ifa->ifa_addr;
        selected.is_wifi = is_wifi;
        if (cfg.has_essid) {
          selected.has_essid = true;
          memcpy(selected.essid, cfg.essid, sizeof(selected.essid));
          selected.essid_len = cfg.essid_len;
        }
      }
    }
  }

  if (selected.myfamily == 0) {
    fprintf(stderr, "could not find an acceptable address to bind to.\n");
    return -1;
  }
  
  /* open listening socket */
  if ((rc = uv_tcp_init(skt->loop, &skt->listen_socket))) {
    fprintf(stderr, "failed to allocate a socket: (%d) %s\n", rc, uv_strerror(rc));
    return -1;
  }
  /* FIXME: i don't know how to set SO_REUSEADDR for libuv.  maybe we don't need it, though.
  if ((rc = setsockopt(skt->listen_socket, SOL_SOCKET, SO_REUSEADDR, (void *) &optval, sizeof(int)))) {
    fprintf(stderr, "failed to set SO_REUSEADDR: (%d) %s\n", errno, strerror(errno));
    return -1;
  }
  */
  if ((rc = uv_tcp_bind(&skt->listen_socket, selected.myaddr, 0))) {
    fprintf(stderr, "failed to bind: (%d) %s\n", rc, uv_strerror(rc));
    return -1;
  }    
  if ((rc = uv_tcp_getsockname(&skt->listen_socket, (struct sockaddr *) &skt->sa_serv_storage, &skt->sa_serv_storage_sz))) {
    fprintf(stderr, "failed to uv_tcp_getsockname: (%d) %s\n", rc, uv_strerror(rc));
    return -1;
  }
  if (skt->sa_serv_storage_sz > sizeof(skt->sa_serv_storage)) {
    fprintf(stderr, "needed more space (%d) than expected (%zd) for getsockname\n", skt->sa_serv_storage_sz, sizeof(skt->sa_serv_storage));
    return -1;
  }
  if (skt->sa_serv_storage.ss_family != selected.myfamily) {
    fprintf(stderr, "was expecting address family %d after binding, got %d\n", selected.myfamily, skt->sa_serv_storage.ss_family);
    return -1;
  }
  if (print_address_name(&skt->sa_serv_storage, skt->addrp, sizeof(skt->addrp), &skt->port))
    return -1;
  skt->listen_socket.data = skt;
  if ((rc = uv_listen((uv_stream_t*)(&skt->listen_socket), 0, skt_session_connect))) {
    fprintf(stderr, "failed to listen: (%d) %s\n", errno, strerror(errno));
    return -1;
  }
  if (selected.has_essid) {
    skt->essid = malloc(selected.essid_len * 2 + 1);
    if (skt->essid) {
      for (int ix = 0; ix < selected.essid_len; ix++)
        sprintf(skt->essid + (ix * 2), "%02X", selected.essid[ix]);
      skt->essid[selected.essid_len * 2] = '\0';
    }
  }
  return 0;
}


int get_psk_creds(gnutls_session_t session, const char* username, gnutls_datum_t* key) {
  skt_st *skt;
  skt = gnutls_session_get_ptr(session);
  
  if (skt->log_level > 2)
    fprintf(stderr, "sent username: %s, PSK: %s\n",
            username, /* dangerous: random bytes from the network! */
            skt->pskhex); 
  key->size = skt->psk.size;
  key->data = gnutls_malloc(skt->psk.size);
  if (!key->data)
    return GNUTLS_E_MEMORY_ERROR;
  memcpy(key->data, skt->psk.data, skt->psk.size);
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

  if (fflush(f))
    fprintf(stderr, "Warning: failed to flush QR code stream: (%d) %s\n", errno, strerror(errno));

  return 0;
}

int print_address_name(struct sockaddr_storage *addr, char *paddr, size_t paddrsz, int *port) {
  if (addr->ss_family == AF_INET6) {
    struct sockaddr_in6 *sa_serv_full;
    sa_serv_full = (struct sockaddr_in6 *)addr;
    if (NULL == inet_ntop(addr->ss_family, &(sa_serv_full->sin6_addr), paddr, paddrsz)) {
      fprintf(stderr, "inet_ntop failed (%d) %s\n", errno, strerror(errno));
      return -1;
    }
    *port = ntohs(sa_serv_full->sin6_port);
  } else if (addr->ss_family == AF_INET) {
    struct sockaddr_in *sa_serv_full;
    sa_serv_full = (struct sockaddr_in *)addr;
    if (NULL == inet_ntop(addr->ss_family, &(sa_serv_full->sin_addr), paddr, paddrsz)) {
      fprintf(stderr, "inet_ntop failed (%d) %s\n", errno, strerror(errno));
      return -1;
    }
    *port = ntohs(sa_serv_full->sin_port);
  } else {
    fprintf(stderr, "unrecognized address family %d\n", addr->ss_family);
    return -1;
  }
  return 0;
}

int skt_session_close_tls(skt_st *skt) {
  int rc;
  assert(skt->session);
  if (skt->accepted_socket.data == skt) {
    if ((rc = gnutls_bye(skt->session, GNUTLS_SHUT_RDWR))) {
      fprintf(stderr, "gnutls_bye got error (%d) %s\n", rc, gnutls_strerror(rc));
      return -1;
    }
  } else {
    uv_close((uv_handle_t*)(&skt->listen_socket), skt_session_cleanup_listener);
  }
  gnutls_deinit(skt->session);
  skt->session = NULL;
  if ((rc = uv_read_stop((uv_stream_t*)&skt->accepted_socket))) {
    fprintf(stderr, "failed to stop reading the TLS stream (%d) %s\n", rc, uv_strerror(rc));
    return -1;
  }    
  return 0;
}

void its_all_over(skt_st *skt, const char *fmt, ...) {
  va_list ap;
  int rc;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  /* FIXME: how to tear it all down? */
  if (skt->session) {
    skt_session_close_tls(skt);
  }
  if (skt->input.data && !uv_is_closing((uv_handle_t*)(&skt->input))) {
    if ((rc = uv_tty_reset_mode()))
      fprintf(stderr, "failed to uv_tty_reset_mode: (%d) %s\n", rc, uv_strerror(rc));
    uv_close((uv_handle_t*)(&skt->input), input_close_cb);
  }
  uv_stop(skt->loop);
}

/* FIXME: this would only be used in the event of a fully asynchronous
   write.  however, i don't see how to keep track of the memory being
   written correctly in that case.

void skt_session_write_done(uv_write_t* req, int x) {
  if (x) {
    fprintf(stderr, "write failed: (%d) %s\n", x, uv_strerror(x));
    return;
  }
  skt_st *skt = req->handle->data;
  
  free(req);
}
*/

ssize_t skt_session_gnutls_push_func(gnutls_transport_ptr_t ptr, const void* buf, size_t sz) {
  skt_st *skt = ptr;
  int rc;
  /* FIXME: be more asynchronous in writes; here we're just trying to be synchronous */
  
  /* FIXME: i do not like casting away constness here */
  uv_buf_t b[] = {{ .base = (void*) buf, .len = sz }};

  if (skt->accepted_socket.data == skt) {
    rc = uv_try_write((uv_stream_t*)(&skt->accepted_socket), b, sizeof(b)/sizeof(b[0]));
    if (rc >= 0)
      return rc;
    fprintf(stderr, "got error %d (%s) when trying to write %zd octets\n", rc, uv_strerror(rc), sz);
    if (rc == UV_EAGAIN) {
      gnutls_transport_set_errno(skt->session, EAGAIN);
      return -1;
    }
  }
  gnutls_transport_set_errno(skt->session, EIO);
  return -1;
}

ssize_t skt_session_gnutls_pull_func(gnutls_transport_ptr_t ptr, void* buf, size_t sz) {
  skt_st *skt = ptr;
  int available = skt->end - skt->start;
  if (uv_is_closing((uv_handle_t*)(&skt->accepted_socket)))
    return 0;
  if (skt->end == skt->start) {
    gnutls_transport_set_errno(skt->session, EAGAIN);
    return -1;
  }
  /* FIXME: this seems like an extra unnecessary copy.  can we arrange
     it so that the buffer gets passed through to the uv_alloc_cb? */
  if (sz >= skt->end - skt->start) {
    memcpy(buf, skt->tlsreadbuf + skt->start, available);
    skt->start = skt->end = 0;
    return available;
  } else {
    memcpy(buf, skt->tlsreadbuf + skt->start, sz);
    skt->start += sz;
    return sz;
  }
}

void skt_session_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
  skt_st *skt = handle->data;
  assert(handle == (uv_handle_t*)(&skt->accepted_socket));
  buf->base = skt->tlsreadbuf + skt->end;
  buf->len = sizeof(skt->tlsreadbuf) - skt->end;
  /* FIXME: should consider how to read partial buffers, if these don't match a TLS record */
}

void skt_session_handshake_done(skt_st *skt) {
  char *desc;
  desc = gnutls_session_get_desc(skt->session);
  fprintf(stdout, "TLS handshake complete: %s\n", desc);
  gnutls_free(desc);
  skt->handshake_done = true;
  gpgsession_display(skt->base, stdout);
}

int skt_session_gather_secret_keys(skt_st *skt) {
  gpgme_error_t gerr;
  int secret_only = 1;
  const char *pattern = NULL;
  fprintf(stdout, "Gathering a list of available OpenPGP secret keys...\n");
  if ((gerr = gpgme_op_keylist_start(skt->base->ctx, pattern, secret_only))) {
    fprintf(stderr, "Failed to start gathering keys: (%d) %s\n", gerr, gpgme_strerror(gerr));
    return 1;
  }
  while (!gerr) {
    gpgme_key_t key = NULL;
    gerr = gpgme_op_keylist_next(skt->base->ctx, &key);
    if (!gerr) {
      if (gpgsession_add_key(skt->base, key))
        goto fail;
    } else if (gpgme_err_code(gerr) != GPG_ERR_EOF) {
      fprintf(stderr, "Failed to get keys: (%d) %s\n", gerr, gpgme_strerror(gerr));
      goto fail;
    }
  }
  return 0;
 fail:
  if ((gerr = gpgme_op_keylist_end(skt->base->ctx)))
    fprintf(stderr, "failed to gpgme_op_keylist_end(): (%d) %s\n", gerr, gpgme_strerror(gerr));
  return 1;
}

void gpgsession_instructions_base(struct gpgsession *session, FILE *f) {
  if (!session->num_keys)
    fprintf(f, "You have no secret keys that you can send.\n");
  fprintf(f, "To receive a key, ask the other device to send it.\n");
  if (session->num_keys)
    fprintf(f, "To send a key, press its number:\n\n");
}

void gpgsession_instructions_incoming(struct gpgsession *session, FILE *f) {
  if (!session->num_keys)
    fprintf(f, "The other device has started sending keys, but no valid keys have arrived yet.\n");
  else
    fprintf(f, "To import an incoming key, press its letter: \n\n");
}

void gpgsession_display(struct gpgsession *session, FILE *f) {
  int numleft = session->num_keys - session->keylist_offset;
  if (numleft > KEYS_PER_PAGE)
    numleft = KEYS_PER_PAGE;
  clearscreen(f);
  
  session->instructions(session, f);
  
  if (session->num_keys) {
    for (int ix = 0; ix < numleft; ix++) {
      fprintf(f, "[%c] %s\n    %s\n", session->base_key + ix,
              session->keys[session->keylist_offset + ix].key->uids->uid,
              session->keys[session->keylist_offset + ix].fpr);
    }
    if (session->num_keys > KEYS_PER_PAGE)
      fprintf(f, "\n[n] …more available keys (%zd total)…\n", session->num_keys);
  }
/*   fprintf(f, "[0] <choose a file to send>\n");  FIXME: prompt to load local keys from a file! */
  fprintf(f, "[q] to quit\n");

}


/* appends SUFFIX to position POS in BASE, growing BASE if necessary */
int append_data(gnutls_datum_t *base, const gnutls_datum_t *suffix, size_t pos) {
  size_t newlen = pos + suffix->size;
  if (base->size < newlen) {
    unsigned char *newdata = realloc(base->data, newlen);
    if (!newdata)
      return ENOMEM;
    base->data = newdata;
    base->size = newlen;
  }
  memcpy(base->data + pos, suffix->data, suffix->size);
  return 0;
}

int gpgsession_load_keys(struct gpgsession *gpg) {
  gpgme_error_t gerr;
  int secret = 1;
  int ret = 0;
  bool refreshed = false;
  for (struct gpgkey *k = gpg->keys; k < gpg->keys + gpg->num_keys; k++) {
    if (k->key == NULL || k->refresh) {
      if (k->key) {
        gpgme_key_unref(k->key);
        k->key = NULL;
      }
      if ((gerr = gpgme_get_key(gpg->ctx, k->fpr, &k->key, secret))) {
        fprintf(stderr, "Failed to get %s key with fingerprint %s: (%d) %s\n",
                gpg->name, k->fpr, gerr, gpgme_strerror(gerr));
        ret = EIO;
      } else
        refreshed = true;
    }
  }

  if (refreshed)
    gpgsession_display(gpg, stdout);
  return ret;
}

int skt_session_ingest_key(skt_st *skt, unsigned char *ptr, size_t sz) {
  gpgme_data_t d;
  gpgme_error_t gerr;
  int copy = 0;
  gpgme_import_result_t result = NULL;
  gpgme_import_status_t newkey = NULL;
    
  assert(skt->incoming);
  
  if ((gerr = gpgme_data_new_from_mem(&d, (const char *)ptr, sz, copy))) {
    fprintf(stderr, "Failed to allocate new gpgme_data_t: (%d) %s\n", gerr, gpgme_strerror(gerr));
    return ENOMEM;
  }
  gerr = gpgme_op_import(skt->incoming->ctx, d);
  gpgme_data_release(d);
  if (gerr) {
    fprintf(stderr, "Failed to import key: (%d) %s\n", gerr, gpgme_strerror(gerr));
    return ENOMEM;
  }

  result = gpgme_op_import_result(skt->incoming->ctx);
  if (!result) {
    fprintf(stderr, "something went wrong during import to GnuPG\n");
    return EIO;
  }
  if (skt->log_level > 2)
    fprintf(stderr, "Imported %d secret keys\n", result->secret_imported);

  for (newkey = result->imports; newkey; newkey = newkey->next) {
    if ((newkey->result == GPG_ERR_NO_ERROR) &&
        (newkey->status & (GPGME_IMPORT_NEW | GPGME_IMPORT_SECRET))) {
      gpgsession_add_fpr(skt->incoming, newkey->fpr);
    }
  }
  return gpgsession_load_keys(skt->incoming);
}

/* look through the incoming data stream and if it contains a key, try
   to ingest it.  FIXME: it's a bit wasteful to perform this scan of
   the whole buffer every time a TLS record comes in; should really be
   done in true async form, with the state stored in skt someplace. */
int skt_session_try_incoming_keys(skt_st *skt) {
  unsigned char *key = skt->incomingkey.data;
  size_t sz = skt->incomingkeylen;
  size_t consumed = 0;
  unsigned char *end;
  int rc;
  int ret = 0;

  while (sz > 0) {
    if (sz < sizeof(pgp_begin)) {
      if (memcmp(pgp_begin, key, sz))
        return EINVAL; /* even the beginning doesn't match the expected first line */
      break; /* just not big enough yet */
    }
    if (memcmp(pgp_begin, key, sizeof(pgp_begin)-1))
      return EINVAL; /* it's gotta start with the usual header */
    if (!(key[sizeof(pgp_begin)-1] == '\r' || key[sizeof(pgp_begin)-1] == '\n'))
      return EINVAL; /* needs a trailing newline, however that's formed */
    
    /* FIXME: ensure that we just get comments and headers between the
       begin and end lines */
    
    end = memmem(key, sz, pgp_end, sizeof(pgp_end)-1);
    if (end == NULL)
      break; /* haven't reached the end yet */
    size_t pos = end + (sizeof(pgp_end)-1) - key;
    assert(pos <= sz);
    if (pos == sz)
      return 0; /* got everything but the final newline */
    if (key[pos] == '\n') {
      pos += 1;
    } else if (key[pos] == '\r') {
      if (pos+1 == sz)
        return 0; /* got everything but the final newline in a CRLF format */
      if (key[pos+1] == '\n')
        pos += 2;
      else
        return EINVAL;
    } else
      return EINVAL;
    /* at this point, POS points to the end of what we suspect to be an
       OpenPGP transferable private key. */
    if ((rc = skt_session_ingest_key(skt, key, pos))) {
      ret = rc;
    }
    consumed += pos;
    key += pos;
    sz -= pos;
  }
  if (consumed) {
    size_t leftovers = skt->incomingkeylen - consumed;
    if (leftovers)
      memmove(skt->incomingkey.data, skt->incomingkey.data + consumed, leftovers);
    skt->incomingkeylen = leftovers;
  }
  return ret;
}

int skt_session_ingest_packet(skt_st *skt, gnutls_packet_t packet) {
  gnutls_datum_t data;
  int rc;

  assert(packet);
  gnutls_packet_get(packet, &data, NULL);
  if ((rc = append_data(&skt->incomingkey, &data, skt->incomingkeylen))) {
    fprintf(stderr, "Failed to append data: (%d) %s\n", rc, strerror(rc));
    return rc;
  }
  skt->incomingkeylen += data.size;
  return skt_session_try_incoming_keys(skt);
}

void skt_session_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
  skt_st *skt = stream->data;
  int rc;
  assert(stream == (uv_stream_t*)(&skt->accepted_socket));
  assert(buf->base == skt->tlsreadbuf + skt->end);
  skt->end += nread;

  if (!skt->handshake_done) {
    gnutls_alert_description_t alert;
    rc = gnutls_handshake(skt->session);
    switch(rc) {
    case GNUTLS_E_WARNING_ALERT_RECEIVED:
      alert = gnutls_alert_get(skt->session);
      fprintf(stderr, "Got GnuTLS alert (%d) %s\n", alert, gnutls_alert_get_name(alert));
      break;
    case GNUTLS_E_INTERRUPTED:
    case GNUTLS_E_AGAIN:
      if (skt->log_level > 3)
        fprintf(stderr, "gnutls_handshake() got (%d) %s\n", rc, gnutls_strerror(rc));
      break;
    case GNUTLS_E_SUCCESS:
      skt_session_handshake_done(skt);
      break;
    default:
      its_all_over(skt, "gnutls_handshake() got (%d) %s, fatal\n", rc, gnutls_strerror(rc));
    }
  } else while (1) {
    gnutls_packet_t packet = NULL;
    assert(skt->session);
    rc = gnutls_record_recv_packet(skt->session, &packet);
    if (rc == GNUTLS_E_AGAIN)
      return;
    if (rc == 0) {
      /* This is EOF from the remote peer.  We'd like to handle a
         half-closed stream if we're the active peer */
      assert(packet == NULL);
      if (skt->active) {
        if (skt->log_level > 0) 
          fprintf(stderr, "passive peer closed its side of the connection.\n");
      } else {
        if (skt->incoming) {
          /* Now we've loaded as many of the keys as we will get.  We
             should now be in a mode where we ask the user to import
             them.  So we just need to close the TLS session and carry
             on. */
          if (!skt_session_close_tls(skt)) {
            fprintf(stderr, "Failed to close the TLS session!\n");
            return;
          }
        } else {
          its_all_over(skt, "TLS session closed with nothing transmitted from either side!\n");
          return;
        }
      }
    } else if (rc < 0) {
      if (packet)
        gnutls_packet_deinit(packet);
      if (rc == GNUTLS_E_INTERRUPTED) {
        fprintf(stderr, "gnutls_record_recv_packet returned (%d) %s\n", rc, gnutls_strerror(rc));
      } else {
        /* this is an error */
        its_all_over(skt, "Got an error in gnutls_record_recv_packet: (%d) %s\n", rc, gnutls_strerror(rc));
        return;
      }
    } else {
      if (skt->active) {
        gnutls_packet_deinit(packet);
        its_all_over(skt, "We are the active sender, but the other side sent stuff\n");
        return;
      }

      /* we're now in passive mode.  */
      if (!skt->incoming) {
        skt->incoming = gpgsession_new(true, 'a', "incoming", gpgsession_instructions_incoming);
        if (!skt->incoming) {
          its_all_over(skt, "failed to prepare for key input\n");
          return;
        }
        gpgsession_display(skt->incoming, stdout);
      }

      if ((rc = skt_session_ingest_packet(skt, packet))) {
        gnutls_packet_deinit(packet);
        its_all_over(skt, "failed to ingest the packet: (%d) %s\n", rc, strerror(rc));
        return;
      }
      gnutls_packet_deinit(packet);
    }
  }
}

void skt_session_cleanup_listener(uv_handle_t* handle) {
  skt_st *skt = handle->data;
  assert(handle == (uv_handle_t*)(&skt->listen_socket));
  /* FIXME: do we need to clean up anything? */
}


void skt_session_connect(uv_stream_t* server, int x) {
  int rc;
  skt_st *skt = server->data;
  assert(server == (uv_stream_t*)(&skt->listen_socket));
  if (x < 0) 
    its_all_over(skt, "connect callback called with status %d\n", x);
  else if ((rc = uv_tcp_init(skt->loop, &skt->accepted_socket))) 
    its_all_over(skt, "failed to init accepted_socket: (%d) %s\n", rc, uv_strerror(rc));
  else {
    skt->accepted_socket.data = skt;
    if ((rc = uv_accept(server, (uv_stream_t*)(&skt->accepted_socket))))
      its_all_over(skt, "failed to init accepted_socket: (%d) %s\n", rc, uv_strerror(rc));
    else if ((rc = uv_tcp_getpeername(&skt->accepted_socket, (struct sockaddr*)(&skt->sa_cli_storage),
                                      &skt->sa_cli_storage_sz)))
      its_all_over(skt, "failed to getpeername of connected host: (%d) %s\n", rc, uv_strerror(rc));
    else {
      uv_close((uv_handle_t*)(&skt->listen_socket), skt_session_cleanup_listener);
      
      if (print_address_name(&skt->sa_cli_storage, skt->caddrp, sizeof(skt->caddrp), &skt->cport))
        return;
      fprintf(stdout, "A connection was made from %s%s%s:%d!\n",
              skt->sa_cli_storage.ss_family==AF_INET6?"[":"",
              skt->caddrp,
              skt->sa_cli_storage.ss_family==AF_INET6?"]":"",
              skt->cport
              );

      if ((rc = uv_read_start((uv_stream_t*)(&skt->accepted_socket), skt_session_alloc_cb, skt_session_read_cb)))
        its_all_over(skt, "failed to uv_read_start: (%d) %s\n", rc, uv_strerror(rc));
    }
  }
}




int main(int argc, const char *argv[]) {
  skt_st *skt;
  uv_loop_t loop;
  int rc;
  gnutls_psk_server_credentials_t creds = NULL;
  gnutls_priority_t priority_cache;
  char urlbuf[INET6_ADDRSTRLEN + 1024];
  int urllen;
  QRinput *qrinput = NULL;
  QRcode *qrcode = NULL;
  FILE * inkey = NULL;
  const char *ll;
  int log_level;

  ll = getenv("LOG_LEVEL");
  log_level = ll ? atoi(ll) : 0;
  gpgme_check_version (NULL);
  gnutls_global_set_log_level(log_level);
  gnutls_global_set_log_function(skt_log);
  if ((rc = uv_loop_init(&loop))) {
    fprintf(stderr, "failed to init uv_loop: (%d) %s\n", rc, uv_strerror(rc));
    return -1;
  }

  if (argc > 1) {
    if (!strcmp(argv[1], "-")) {
      inkey = stdin;
    } else {
      inkey = fopen(argv[1], "r");
      if (inkey == NULL)
        fprintf(stderr, "could not read key '%s', instead waiting to receive key: (%d) %s\n",
                argv[1], errno, strerror(errno));
    }
  }

  skt = skt_session_new(&loop, log_level);
  if (!skt) {
    fprintf(stderr, "Failed to initialize skt object\n");
    return -1;
  }
  if (skt_session_choose_address(skt))
    return -1;

  if (skt_session_gather_secret_keys(skt))
    return -1;
  
  /* open tls server connection */
  if ((rc = gnutls_init(&skt->session, GNUTLS_SERVER | GNUTLS_NONBLOCK))) {
    fprintf(stderr, "failed to init session: (%d) %s\n", rc, gnutls_strerror(rc));
    return -1;
  }
  gnutls_session_set_ptr(skt->session, skt);
  gnutls_transport_set_pull_function(skt->session, skt_session_gnutls_pull_func);
  gnutls_transport_set_push_function(skt->session, skt_session_gnutls_push_func);
  gnutls_transport_set_ptr(skt->session, skt);
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
  if ((rc = gnutls_credentials_set(skt->session, GNUTLS_CRD_PSK, creds))) {
    fprintf(stderr, "failed to assign PSK credentials to GnuTLS server: (%d) %s\n", rc, gnutls_strerror(rc));
    return -1;
  }
  if ((rc = gnutls_priority_init(&priority_cache, priority, NULL))) {
    fprintf(stderr, "failed to set up GnuTLS priority: (%d) %s\n", rc, gnutls_strerror(rc));
    return -1;
  }
  if ((rc = gnutls_priority_set(skt->session, priority_cache))) {
    fprintf(stderr, "failed to assign gnutls priority: (%d) %s\n", rc, gnutls_strerror(rc));
    return -1;
  }

  clearscreen(stdout);
  
  /* construct string */
  urlbuf[sizeof(urlbuf)-1] = 0;
  urllen = snprintf(urlbuf, sizeof(urlbuf)-1, "%s:%s/%d/%s%s%s",
                    schema,
                    skt->addrp,
                    skt->port,
                    skt->pskhex,
                    skt->essid ? "/SSID:" : "",
                    skt->essid ? skt->essid : "");
  if (urllen >= (sizeof(urlbuf)-1)) {
    fprintf(stderr, "buffer was somehow truncated.\n");
    return -1;
  }
  if (urllen < 5) {
    fprintf(stderr, "printed URL was somehow way too small (%d).\n", urllen);
    return -1;
  }
  fprintf(stdout, "%s\n", urlbuf);
      
  /* generate qrcode (FIXME: can't use QR_MODE_AN, because QRcode_encodeString only likes 8bit or kanji; need to invoke this differently) */
  qrinput = QRinput_new();
  if (!qrinput) {
    fprintf(stderr, "Failed to allocate new QRinput\n");
    return -1;
  }
  if ((rc = QRinput_append(qrinput, QR_MODE_AN, strlen(urlbuf), (unsigned char *)urlbuf))) {
    fprintf(stderr, "failed to QRinput_append: (%d) %s\n", rc == -1 ? errno: rc, strerror(rc == -1 ? errno : rc));
    return -1;
  }
  qrcode = QRcode_encodeInput(qrinput);
  if (qrcode == NULL) {
    fprintf(stderr, "failed to encode string as QRcode: (%d) %s\n", errno, strerror(errno));
    return -1;
  }
  
  /* display qrcode */
  if ((rc = print_qrcode(stdout, qrcode))) {
    fprintf(stderr, "failed to print qr code\n");
    return -1;
  }

  /* FIXME: should flush all input before starting to respond to it? */
  if ((rc = uv_tty_init(skt->loop, &skt->input, 0, 1))) {
    fprintf(stderr, "failed to grab stdin for reading, using passive mode only: (%d) %s\n", rc, uv_strerror(rc));
  } else if ((rc = uv_tty_set_mode(&skt->input, UV_TTY_MODE_RAW))) {
    fprintf(stderr, "failed to switch input to raw mode, using passive mode only: (%d) %s\n", rc, uv_strerror(rc));
    uv_close((uv_handle_t*)(&skt->input), input_close_cb);
  } else if ((rc = uv_read_start((uv_stream_t*)(&skt->input), input_alloc_cb, input_read_cb))) {
    fprintf(stderr, "failed to start reading from stdin, using passive mode only: (%d) %s\n", rc, uv_strerror(rc));
    uv_close((uv_handle_t*)(&skt->input), input_close_cb);
  } else {
    skt->input.data = skt;
  }
  
  /* for test purposes... */
  if (skt->log_level > 0)
    fprintf(stdout, "gnutls-cli --debug %d --priority %s --port %d --pskusername %s --pskkey %s %s\n",
            skt->log_level, priority, skt->port, psk_id_hint, skt->pskhex, skt->addrp);

  if ((rc = uv_run(&loop, UV_RUN_DEFAULT))) {
    while ((rc = uv_run(&loop, UV_RUN_ONCE))) {
      fprintf(stderr, "UV_RUN_ONCE returned %d\n", rc);
    }
  }

  if (inkey) {
    /* FIXME: send key */
    char data[65536];
    if (skt->log_level > 3)
      fprintf(stderr, "trying to write %s to client\n", (stdin == inkey) ? "standard input" : argv[1]);

    /* read from inkey, send to gnutls */
    while (!feof(inkey)) {
      size_t r;
      r = fread(data, 1, sizeof(data), inkey); /* FIXME: blocking */
      if (ferror(inkey)) {
        fprintf(stderr, "Error reading from input\n");
        return -1;
      } else {
        if (skt->log_level > 3)
          fprintf(stderr, "trying to write %zd octets to client\n", r);
        while (r) {
          rc = GNUTLS_E_AGAIN;
          while (rc == GNUTLS_E_AGAIN || rc == GNUTLS_E_INTERRUPTED) {
            rc = gnutls_record_send(skt->session, data, r); /* FIXME: blocking */
            if (rc < 0) {
              if (rc != GNUTLS_E_AGAIN && rc != GNUTLS_E_INTERRUPTED) {
                fprintf(stderr, "gnutls_record_send() failed: (%d) %s\n", rc, gnutls_strerror(rc));
                return -1;
              }
            } else {
              r -= rc;
            }
          }
        }
      }
    }
  }

  /* cleanup */
  skt_session_free(skt);
  gnutls_priority_deinit(priority_cache);
  gnutls_psk_free_server_credentials(creds);
  QRcode_free(qrcode);
  QRinput_free(qrinput);
  if ((rc = uv_loop_close(&loop)))
    fprintf(stderr, "uv_loop_close() returned (%d) %s\n", rc, uv_strerror(rc));
  return 0;
}
