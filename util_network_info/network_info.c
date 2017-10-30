#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <ifaddrs.h>
#include <errno.h>
#include <arpa/inet.h> //INET6_ADDRSTRLEN
//#include <net/if.h>
#include "iwlib.h"

#include "util_network_info/network_info.h"

int get_info(struct network_info * const info) {
	/* pick an IP address with getifaddrs instead of using in6addr_any */
	
	struct ifaddrs *ifap, *ifa;
	
	if (getifaddrs(&ifap)) {
		fprintf(stderr, "getifaddrs failed: (%d) %s\n", errno, strerror(errno));
		return -1;
	}
	
	int iwcfgfd = iw_sockets_open();
	
	struct wireless_config x; /* just for size info */
	struct {
		int myfamily;
		struct sockaddr *myaddr;
		bool has_essid;
		size_t essid_len;
		size_t ip_len;
		bool is_wifi;
		char essid[sizeof(x.essid)];
		char addrstring[INET6_ADDRSTRLEN];
	} selected = { .myaddr = NULL };

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		char addrstring[INET6_ADDRSTRLEN] = {0};
		bool skip = false;
		int family = 0;
		bool is_wifi = false;
		struct wireless_config cfg;
		
		if (ifa->ifa_addr) {
			family = ((struct sockaddr_storage*)(ifa->ifa_addr))->ss_family;
			void * ptr = NULL;
			
			if (family == AF_INET6) {
				ptr = &((struct sockaddr_in6*)(ifa->ifa_addr))->sin6_addr;
			} else if (family == AF_INET) {
				ptr = &((struct sockaddr_in*)(ifa->ifa_addr))->sin_addr;
			} else if (family == AF_PACKET) {
				skip = true; /* struct rtnl_link_stats *stats = ifa->ifa_data */
			}
			
			if (!skip){
				inet_ntop(family, ptr, addrstring, sizeof(addrstring));
			} else {
				strcpy(addrstring, "<unknown family>");
			}
			
		} else {
			strcpy(addrstring, "<no address>");
		}
		
		if (ifa->ifa_flags & IFF_LOOPBACK) {
			fprintf(stderr, "skipping %s because it is loopback\n", ifa->ifa_name);
			continue;
		}
		
		if (!(ifa->ifa_flags & IFF_UP)) {
			fprintf(stderr, "skipping %s because it is not up\n", ifa->ifa_name);
			continue;
		}
		
		if (!skip) {
			if (iwcfgfd >= 0) {
				if (iw_get_basic_config(iwcfgfd, ifa->ifa_name, &cfg)) {
					if (errno == EOPNOTSUPP) {
						fprintf(stderr, "interface %s is not Wi-Fi\n", ifa->ifa_name);
					} else {
						fprintf(stderr, "failed to get wireless info: (%d) %s\n", errno, strerror(errno));
					}
				} else {
					is_wifi = true;
					if (cfg.has_essid) {
						if (cfg.essid_len >= sizeof(cfg.essid)) {
							fprintf(stderr, "essid is longer (%d octets) than we can handle (%zd octets)\n",
									cfg.essid_len, sizeof(cfg.essid)-1);              
						} else {
							bool essid_printable = true;
							/* avoid un-URL-able symbols in the essid */
							for (const char *c = cfg.essid; c < cfg.essid + cfg.essid_len; c++) {
								if (!(isascii(*c) && isgraph(*c) && (NULL == strchr("%&+", *c)))) {
									fprintf(stderr, "unprintable octet 0x%02x in essid, we will not log it raw\n", *c);
									essid_printable = false;
									break;
								}
							}
							fprintf(stderr, "%s has ESSID: ", ifa->ifa_name);
							if (essid_printable) 
								fwrite(cfg.essid, cfg.essid_len, 1, stderr);
							else {
								fprintf(stderr, "(hex:)");
								for (const char *c = cfg.essid; c < cfg.essid + cfg.essid_len; c++) 
									fprintf(stderr, "%02X", *c);
							}
							fprintf(stderr, "\n");
						}
					} else {
						fprintf(stderr, "Interface %s is wifi, but has no ESSID!\n", ifa->ifa_name);
					}
				}
			}
			/* if a wifi NIC is up and has a printable ESSID, we'll take it.
			*      Otherwise, we will just take the first up, non-loopback address */
			/* FIXME: be cleverer about preferring link-local addresses, and RFC1918 addressses. */
			bool takeit = selected.myaddr == NULL || (is_wifi && (!selected.is_wifi || (cfg.has_essid && !selected.has_essid)));
			fprintf(stdout, "%s %s: %s (flags: 0x%x)\n", takeit?"*":" ", ifa->ifa_name, addrstring, ifa->ifa_flags);
			
			if (takeit) {
				selected.myfamily = family;
				selected.myaddr = ifa->ifa_addr;
				selected.is_wifi = is_wifi;
				if (cfg.has_essid) {
					selected.has_essid = true;
					memcpy(selected.essid, cfg.essid, cfg.essid_len);
					selected.essid_len = cfg.essid_len;
					memcpy(selected.addrstring, addrstring, sizeof(addrstring));
					selected.ip_len = strlen(addrstring);
				}
			}
			
			//FIXME: clear properl all structure!
		}
	}
	
	if (selected.myaddr == NULL)
		return -1;
	
	if (selected.has_essid) {
		info->ssid = malloc(selected.essid_len * 2 + 1);
		if (info->ssid) {
			for (int ix = 0; ix < selected.essid_len; ix++)
				sprintf(info->ssid + (ix * 2), "%02X", selected.essid[ix]);
			info->ssid[selected.essid_len * 2] = '\0';
		}else{
			perror("failed to allocate space for SSID, out of RAM?");
			return -1;
		}
	}
	
	info->ip = malloc(selected.ip_len);
	if (info->ip == NULL) {
		perror("failed to allocate space for IP, out of RAM?");
		free(info->ssid);
		return -1;
	}
	memcpy(info->ip, selected.addrstring, selected.ip_len);
	info->ip[selected.ip_len] = '\0';
	
	
	return 0;
}
