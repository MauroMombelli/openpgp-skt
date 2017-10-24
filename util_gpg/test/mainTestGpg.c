#include "gpg_session.h"

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>


int main(int argc, const char *argv[]){
	gpgme_ctx_t ctx;
	gpgsession_new(&ctx, false);
	
	int inkeysfd = -1;
	if (argc > 1) {
		printf("argv1\n");
		inkeysfd = open(argv[1], 0, O_RDONLY);
		if (inkeysfd == -1)
			fprintf(stderr, "could not read key '%s', falling back to normal GnuPG: (%d) %s\n", argv[1], errno, strerror(errno));
	}
	
	if (inkeysfd != -1) {
		gpgme_error_t err;
		gpgme_data_t d = NULL;
		err = gpgme_data_new_from_fd(&d, inkeysfd);
		if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
			fprintf(stderr, "failed to initialize new gpgme data. (%d) %s\n", err, gpgme_strerror(err));
			return -1;
		}
		printf("ok stream\n");
		/* FIXME: blocking */
		err = gpgme_op_import(ctx, d);
		printf("done import\n");
		gpgme_data_release(d);
		if (gpgme_err_code(err) != GPG_ERR_NO_ERROR){
			fprintf(stderr, "Failed to import key(s) from file '%s', falling back to normal GnuPG: (%d) %s\n", argv[1], err, gpgme_strerror(err));
			//gpgsession_free(skt->fromfile, skt->log_level);
		}/* else if (gpgsession_gather_secret_keys(skt->fromfile)) {
			fprintf(stderr, "Failed to learn the secret key(s) available in %s\n", argv[1]);
			//gpgsession_free(skt->fromfile, skt->log_level);
		}*/
	}
	
	gpgsession_gather_secret_keys(&ctx);
}
