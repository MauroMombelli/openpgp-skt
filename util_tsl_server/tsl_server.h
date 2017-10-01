#define PSK_BYTES 16

#include <stdlib.h>

int server_bind(const int port);

int server_create(char * const pskhex);

int server_accept();

int server_close() ;

int client_close(const int i);

int client_read(const int i, void * const buffer, const size_t size);
