#include "util_gpg/gpg_session.h"

#include <string.h>

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <stdint.h>


void gpgsession_new(gpgme_ctx_t *ctx, bool ephemeral) {
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
	if ((gerr = gpgme_op_keylist_end(*ctx)))
		fprintf(stderr, "failed to gpgme_op_keylist_end(): (%d) %s\n", gerr, gpgme_strerror(gerr));
	return 0;
	fail:
	if ((gerr = gpgme_op_keylist_end(*ctx)))
		fprintf(stderr, "failed to gpgme_op_keylist_end(): (%d) %s\n", gerr, gpgme_strerror(gerr));
	return 1;
}

int gpgsession_import_key(gpgme_ctx_t * const ctx, const char * const data, const size_t length){
	gpgme_data_t d;
	gpgme_error_t gerr;
	int copy = 0;
	gpgme_import_result_t result = NULL;
	
	gerr = gpgme_data_new_from_mem(&d, data, length, copy);
	if (gerr) {
		fprintf(stderr, "Failed to allocate new gpgme_data_t: (%d) %s\n", gerr, gpgme_strerror(gerr));
		return ENOMEM;
	}
	
	gerr = gpgme_op_import(*ctx, d);
	gpgme_data_release(d);
	if (gerr) {
		fprintf(stderr, "Failed to import key: (%d) %s\n", gerr, gpgme_strerror(gerr));
		return ENOMEM;
	}
	
	result = gpgme_op_import_result(*ctx);
	if (!result) {
		fprintf(stderr, "something went wrong during import to GnuPG\n");
		return EIO;
	}
	printf("Imported %d secret keys\n", result->secret_imported);
	
	return 0;
}

int gpgsession_add_data(gpgme_ctx_t * const ctx, const char * const input, const size_t length) {
	static const char * const beingString = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n";
	static const char * const endString = "-----END PGP PRIVATE KEY BLOCK-----\n";	
	
	static enum {WAIT_BEGIN, WAIT_COMMENT, WAIT_DATA, WAIT_END} status = WAIT_BEGIN;
	
	size_t index = 0;
	
	static char pk[100000] = {"-----BEGIN PGP PRIVATE KEY BLOCK-----\n"};
	static size_t pk_index = sizeof(beingString);
	
	switch(status) {
		case WAIT_BEGIN: //we look for the beingString
			{
				pk_index = sizeof(beingString);
				static size_t match = 0;
				while (index < length && match < sizeof(beingString)){
					if ( beingString[match] != input[index] ) {
						match = 0;
					}else{
						match++;
					}
					index++;
				}
				if (match == sizeof(beingString)) {
					match = 0;
					status = WAIT_COMMENT; //we have a valid start line, move to next state
				}else{
					break; //need more data
				}
			}
		case WAIT_COMMENT:
			{
				static bool emptyLine = true;
				while (index < length && pk_index < sizeof(pk) && !(emptyLine && input[index] == '\n')){
					pk[pk_index] = input[index]; //save current char
					pk_index++;
					
					emptyLine = (input[index] == '\n');
					index++;
				}
				
				if (pk_index + 1 >= sizeof(pk)) { //we need at least one more char to add the \n
					//no more space in buffer, fail!
					fprintf(stderr, "no more space in buffer while loading comment, import failed\n");
					status = WAIT_BEGIN;
					emptyLine = true;
					return gpgsession_add_data(ctx, input+index, length); //check if the buffer contains valid start sequence from here
				}
				
				if (emptyLine && input[index] == '\n'){
					pk[pk_index] = '\n'; //save current char
					pk_index++;
					index++;
					status = WAIT_DATA; //we have read all comments, move to next state
				}else{
					break; //need more data
				}
			}
		case WAIT_DATA:
			//Radix 64 is also often called ASCII armored. valid char are [a-z][A-Z][0-9]+/= a \n will move to next status
			while (index < length && pk_index < sizeof(pk) && input[index] != '-'){
				if (
					(input[index] >= 'a' && input[index] <= 'z') ||
					(input[index] >= 'A' && input[index] <= 'Z') ||
					(input[index] >= '0' && input[index] <= '9') ||
					input[index] == '+' || input[index] == '/' || input[index] == '=' || input[index] == '\n'
				){
					pk[pk_index] = input[index]; //save current char
					pk_index++;
					index++;
				}else{
					//invalid key! ABORT!
					fprintf(stderr, "something went wrong during import to GnuPG, invalid data format\n");
					status = WAIT_BEGIN;
					return gpgsession_add_data(ctx, input+index, length); //check if the buffer contains valid start sequence from here
				}
			}
			
			if (pk_index + 1 >= sizeof(pk)) { //we need at least one more char to add the \n
				//no more space in buffer, fail!
				fprintf(stderr, "no more space in buffer while loading PK, import failed\n");
				status = WAIT_BEGIN;
				return gpgsession_add_data(ctx, input+index, length); //check if the buffer contains valid start sequence from here
			}
			
			if (input[index] == '-'){
				status = WAIT_END; //we have read all comments, move to next state
			}else{
				break; //need more data
			}
		case WAIT_END:
			{
				static size_t match = 0;
				while (index < length && pk_index < sizeof(pk) && match < sizeof(endString) && endString[match] == input[index]){
					pk[pk_index] = input[index]; //save current char
					pk_index++;
					match++;
					index++;
				}
				
				if (endString[match] != input[index]){
					fprintf(stderr, "DIFF %c %c\n", endString[match], input[index]);
				}
				
				pk[pk_index] = '\0';
				if (index < length && match != sizeof(endString)) {
					//invalid key! ABORT!
					fprintf(stderr, "something went wrong during import to GnuPG, invalid end string %d %d %d %s\n", (index < length), (pk_index < sizeof(pk)), (match < sizeof(endString)), pk);
					status = WAIT_BEGIN;
					match = 0;
					return gpgsession_add_data(ctx, input+index, length); //check if the buffer contains valid start sequence from here
				}else if (match == sizeof(endString)) {
					gpgsession_import_key(ctx, pk, pk_index);
					match = 0;
					status = WAIT_BEGIN; //we have a valid start line, move to next state
				}else{
					break; //need more data
				}
			}
			break;
	}
	
	return 0;
}





















