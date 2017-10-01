#define PSK_BYTES 16

int server_bind(const int port);

int server_create(char * const pskhex);

int server_accept();

int server_handshake();

int server_close() ;
