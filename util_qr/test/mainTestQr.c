#include "qr_code.h"

int main(int argc, char *argv[]) {
	if (argc != 2){
		fprintf(stderr, "wrong number of argument\n");
		return -1;
	}
	create_and_print_qr(argv[1], stdout);
}
