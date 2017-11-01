#include "util_gpg/gpg_session.h"

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

char data[]= "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\
\n\
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\n\
=uFxb\n\
-----END PGP PRIVATE KEY BLOCK-----\n\
\n";

int main(int argc, const char *argv[]){
	
	gpgme_ctx_t ctx;
	if (gpgsession_new(&ctx, false) != 0) {
		fprintf(stderr, "failed to create gpg session\n");
		return -1;
	}
	
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
	
	
	//skt_session_try_incoming_keys to find the begin of the key
	
	//skt_session_ingest_key for actual import in gpgme
	
	printf("Gathering a list of available OpenPGP secret keys...\n");
	gpgme_key_t *list_of_keys = NULL;
	size_t number_of_keys;
	gpgsession_gather_secret_keys(&ctx, &list_of_keys, &number_of_keys);
	
	for (size_t c = 0; c < number_of_keys; c++) {
		printf("key %s\n", list_of_keys[c]->fpr);
	}
	
	gpgsession_free_secret_keys(&list_of_keys, number_of_keys);
	
	printf("importing test private key\n");
	
	gpgsession_add_data(&ctx, data, sizeof(data) );
	
	gpgsession_gather_secret_keys(&ctx, &list_of_keys, &number_of_keys);
	
	if (list_of_keys == NULL){
		fprintf(stderr, "Failed to import expected key\n");
		return -1;
	}
	
	bool found = 0;
	for (size_t c = 0; c < number_of_keys; c++) {
		printf("key %s\n", list_of_keys[c]->fpr);
		found |= strcmp("643DCBB823321CAB1517715EDAD3B3B87F023329", list_of_keys[c]->fpr) == 0;
	}
	
	gpgsession_free_secret_keys(&list_of_keys, number_of_keys);
	
	if (!found) {
		fprintf(stderr, "Iimport key NOT found\n");
		return -1;
	}
	
	return 0;
}
