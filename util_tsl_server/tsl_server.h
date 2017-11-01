#ifndef TSL_SERVER_H
#define TSL_SERVER_H

#define PSK_BYTES 16

#include <stdlib.h>

int server_bind(const int port);

int server_create(char * const pskhex, size_t pskhexsz);

int server_accept();

int server_close() ;

int client_close(const int fd) ;

int client_update(const int fd, void * const buffer, const size_t size);

int client_write(const int fd, const void * const data, const size_t len);


#endif
