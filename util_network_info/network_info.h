#ifndef NETWORK_INFO_H
#define NETWORK_INFO_H

struct network_info{
	char *ssid;
	char *ip;
};

int get_info(struct network_info * const info);

#endif
