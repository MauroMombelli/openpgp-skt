#include <stdio.h>
#include <stdlib.h>

#include "network_info.h"

int main(void) {
	
	struct network_info info;
	
	get_info(&info);
	
	printf("%s - %s\n", info.ssid, info.ip);
	
	free(info.ssid);
	free(info.ip);
	
	return 0;
}
