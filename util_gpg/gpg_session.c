#include "gpg_session.h"

#include <string.h>

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>


void gpgsession_new(gpgme_ctx_t *ctx, bool ephemeral) {
	printf("gpgsession_new\n");
	gpgme_error_t gerr;
	
	int rc;
	char *xdg = NULL;
	bool xdgf = false;
	
	char *ephemeral_path = NULL;
	
	// Initialization, required
	gpgme_check_version(NULL);
	gerr = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
	
	if (gerr) {
		fprintf(stderr, "gpgme_new failed when setting up ephemeral incoming directory: (%d), %s\n", gerr, gpgme_strerror(gerr));
		return;
	}
	
	
	
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
		rc = asprintf(&ephemeral_path, "%s/skt-server.XXXXXX", xdg);
		if (rc == -1) {
			fprintf(stderr, "Failed to allocate ephemeral GnuPG directory name in %s\n", xdg);
			goto fail;
		}
		if (NULL == mkdtemp(ephemeral_path)) {
			fprintf(stderr, "failed to generate an ephemeral GnuPG homedir from template '%s'\n", ephemeral_path);
			goto fail;
		}
	}
	
	if ((gerr = gpgme_new(ctx))) {
		fprintf(stderr, "gpgme_new failed when setting up ephemeral incoming directory: (%d), %s\n",
				gerr, gpgme_strerror(gerr));
		goto fail;
	}
	if ((gerr = gpgme_ctx_set_engine_info(*ctx, GPGME_PROTOCOL_OpenPGP, NULL, ephemeral_path))) {
		fprintf(stderr, "gpgme_ctx_set_engine_info failed%s%s%s: (%d), %s\n",
				ephemeral?" ephemeral (":"",
				ephemeral?ephemeral_path:"",
				ephemeral?")":"",
		  gerr, gpgme_strerror(gerr));
		goto fail;
	}
	gpgme_set_armor(*ctx, 1);

	free(ephemeral_path);
	
	return;
	
	fail:
	if (xdgf)
		free(xdg);
	if (ephemeral_path != NULL) {
		if (rmdir(ephemeral_path)){
			fprintf(stderr, "failed to rmdir('%s'): (%d) %s\n", ephemeral_path, errno, strerror(errno));
		}
		free(ephemeral_path);
	}
}

int gpgsession_gather_secret_keys(gpgme_ctx_t *ctx) {
	printf("gpgsession_gather_secret_keys\n");
	gpgme_error_t gerr;
	int secret_only = 1;
	const char *pattern = NULL;
	fprintf(stdout, "Gathering a list of available OpenPGP secret keys...\n");
	if ((gerr = gpgme_op_keylist_start(*ctx, pattern, secret_only))) {
		fprintf(stderr, "Failed to start gathering keys: (%d) %s\n", gerr, gpgme_strerror(gerr));
		return 1;
	}
	while (!gerr) {
		gpgme_key_t key = NULL;
		gerr = gpgme_op_keylist_next(*ctx, &key);
		if (!gerr) {
			//if (gpgsession_add_key(gpg, key))
			//	goto fail;
			printf("Got keys: %s - %s\n", key->uids->uid, key->fpr);
		} else if (gpgme_err_code(gerr) != GPG_ERR_EOF) {
			fprintf(stderr, "Failed to get keys: (%d) %s\n", gerr, gpgme_strerror(gerr));
			goto fail;
		}
	}
	return 0;
	fail:
	if ((gerr = gpgme_op_keylist_end(*ctx)))
		fprintf(stderr, "failed to gpgme_op_keylist_end(): (%d) %s\n", gerr, gpgme_strerror(gerr));
	return 1;
}
