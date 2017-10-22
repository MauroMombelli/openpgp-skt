#include "qr_code.h"

#include <qrencode.h>
#include <errno.h>
#include <string.h> //strerror

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
		for (mx = 0; mx < qrcode->width + margin*4; mx++){
			if (1 != fwrite(out[0].data, out[0].size, 1, f)) {
				fprintf(stderr, "failed at upper margin of qrcode\n");
				return -1;
			}
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

int create_qr(const char * const string, QRcode **qrcode) {
	
	QRinput *qrinput = NULL;
	int rc;
	
	if (*qrcode != NULL) {
		fprintf(stderr, "QRcode expected to be NULL\n");
		return -1;
	}
	
	fprintf(stdout, "%s\n", string);
	
	qrinput = QRinput_new();
	if (!qrinput) {
		fprintf(stderr, "Failed to allocate new QRinput\n");
		goto fail;
	}
	if ((rc = QRinput_append(qrinput, QR_MODE_AN, strlen(string), (unsigned char *)string))) {
		fprintf(stderr, "failed to QRinput_append: (%d) %s\n", rc == -1 ? errno: rc, strerror(rc == -1 ? errno : rc));
		goto fail;
	}
	*qrcode = QRcode_encodeInput(qrinput);
	
	QRinput_free(qrinput);
	
	if (*qrcode == NULL) {
		fprintf(stderr, "failed to encode string as QRcode: (%d) %s\n", errno, strerror(errno));
		goto fail;
	}
	
	return 0;
	fail:
	if (qrinput)
		QRinput_free(qrinput);
	return -1;
}

int create_and_print_qr(const char * const string, FILE* f) {
	
	QRcode *qrcode = NULL;
	
	if ( create_qr(string, &qrcode) ) {
		fprintf(stderr, "failed to create qr code\n");
		goto fail;
	}
	
	/* display qrcode */
	if ( print_qrcode(f, qrcode) ) {
		fprintf(stderr, "failed to print qr code\n");
		goto fail;
	}
	
	QRcode_free(qrcode);
	
	return 0;
	
	fail:
	if (qrcode)
		QRcode_free(qrcode);
	return -1;
}
