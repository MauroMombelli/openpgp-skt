#ifndef TSL_SERVER_H
#define TSL_SERVER_H

#define PSK_BYTES 16

#include <stdlib.h>
#include <stdint.h>

int server_bind(const uint16_t port);

int server_create(char * const pskhex, size_t pskhexsz);

int server_accept(void);

int server_close(void);

int client_close(const size_t fd) ;

int client_update(const size_t fd, void * const buffer, const size_t size);

int client_write(const size_t fd, const void * const data, const size_t len);


#endif
