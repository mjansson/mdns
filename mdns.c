
#ifdef _WIN32
#  define _CRT_SECURE_NO_WARNINGS 1
#endif

#include "mdns.h"

#include <stdio.h>
#include <errno.h>

#ifdef _WIN32
#  define sleep(x) Sleep(x * 1000)
#else
#  include <netdb.h>
#endif

static char addrbuffer[64];
static char namebuffer[256];
static mdns_record_txt_t txtbuffer[128];

static mdns_string_t
ipv4_address_to_string(char* buffer, size_t capacity, const struct sockaddr_in* addr, size_t addrlen) {
	char host[NI_MAXHOST] = {0};
	char service[NI_MAXSERV] = {0};
	int ret = getnameinfo((const struct sockaddr*)addr, addrlen,
	                      host, NI_MAXHOST, service, NI_MAXSERV,
	                      NI_NUMERICSERV | NI_NUMERICHOST);
	int len = 0;
	if (ret == 0) {
		if (addr->sin_port != 0)
			len = snprintf(buffer, capacity, "%s:%s", host, service);
		else
			len = snprintf(buffer, capacity, "%s", host);
	}
	if (len >= (int)capacity)
		len = (int)capacity - 1;
	mdns_string_t str = {buffer, len};
	return str;
}

static mdns_string_t
ipv6_address_to_string(char* buffer, size_t capacity, const struct sockaddr_in6* addr, size_t addrlen) {
	char host[NI_MAXHOST] = {0};
	char service[NI_MAXSERV] = {0};
	int ret = getnameinfo((const struct sockaddr*)addr, addrlen,
	                      host, NI_MAXHOST, service, NI_MAXSERV,
	                      NI_NUMERICSERV | NI_NUMERICHOST);
	int len = 0;
	if (ret == 0) {
		if (addr->sin6_port != 0)
			len = snprintf(buffer, capacity, "[%s]:%s", host, service);
		else
			len = snprintf(buffer, capacity, "%s", host);
	}
	if (len >= (int)capacity)
		len = (int)capacity - 1;
	mdns_string_t str = {buffer, len};
	return str;
}

static mdns_string_t
ip_address_to_string(char* buffer, size_t capacity, const struct sockaddr* addr, size_t addrlen) {
	if (addr->sa_family == AF_INET6)
		return ipv6_address_to_string(buffer, capacity, (const struct sockaddr_in6*)addr, addrlen);
	return ipv4_address_to_string(buffer, capacity, (const struct sockaddr_in*)addr, addrlen);
}

static int
query_callback(const struct sockaddr* from, size_t addrlen,
               mdns_entry_type_t entry, uint16_t type,
               uint16_t rclass, uint32_t ttl,
               const void* data, size_t size, size_t offset, size_t length,
               void* user_data) {
	mdns_string_t fromaddrstr = ip_address_to_string(addrbuffer, sizeof(addrbuffer), from, addrlen);
	const char* entrytype = (entry == MDNS_ENTRYTYPE_ANSWER) ? "answer" :
	                        ((entry == MDNS_ENTRYTYPE_AUTHORITY) ? "authority" : "additional");
	if (type == MDNS_RECORDTYPE_PTR) {
		mdns_string_t namestr = mdns_record_parse_ptr(data, size, offset, length,
		                                              namebuffer, sizeof(namebuffer));
		printf("%.*s : %s PTR %.*s type %u rclass 0x%x ttl %u length %d\n",
		       MDNS_STRING_FORMAT(fromaddrstr), entrytype,
		       MDNS_STRING_FORMAT(namestr), type, rclass, ttl, (int)length);
	}
	else if (type == MDNS_RECORDTYPE_SRV) {
		mdns_record_srv_t srv = mdns_record_parse_srv(data, size, offset, length,
		                                              namebuffer, sizeof(namebuffer));
		printf("%.*s : %s SRV %.*s priority %d weight %d port %d\n",
		       MDNS_STRING_FORMAT(fromaddrstr), entrytype,
		       MDNS_STRING_FORMAT(srv.name), srv.priority, srv.weight, srv.port);
	}
	else if (type == MDNS_RECORDTYPE_A) {
		struct sockaddr_in addr;
		mdns_record_parse_a(data, size, offset, length, &addr);
		mdns_string_t addrstr = ipv4_address_to_string(namebuffer, sizeof(namebuffer), &addr, sizeof(addr));
		printf("%.*s : %s A %.*s\n",
		       MDNS_STRING_FORMAT(fromaddrstr), entrytype,
		       MDNS_STRING_FORMAT(addrstr));
	}
	else if (type == MDNS_RECORDTYPE_AAAA) {
		struct sockaddr_in6 addr;
		mdns_record_parse_aaaa(data, size, offset, length, &addr);
		mdns_string_t addrstr = ipv6_address_to_string(namebuffer, sizeof(namebuffer), &addr, sizeof(addr));
		printf("%.*s : %s AAAA %.*s\n",
		       MDNS_STRING_FORMAT(fromaddrstr), entrytype,
		       MDNS_STRING_FORMAT(addrstr));
	}
	else if (type == MDNS_RECORDTYPE_TXT) {
		size_t parsed = mdns_record_parse_txt(data, size, offset, length,
		                                      txtbuffer, sizeof(txtbuffer) / sizeof(mdns_record_txt_t));
		for (size_t itxt = 0; itxt < parsed; ++itxt) {
			if (txtbuffer[itxt].value.length) {
				printf("%.*s : %s TXT %.*s = %.*s\n",
				       MDNS_STRING_FORMAT(fromaddrstr), entrytype,
				       MDNS_STRING_FORMAT(txtbuffer[itxt].key),
				       MDNS_STRING_FORMAT(txtbuffer[itxt].value));
			}
			else {
				printf("%.*s : %s TXT %.*s\n",
				       MDNS_STRING_FORMAT(fromaddrstr), entrytype,
				       MDNS_STRING_FORMAT(txtbuffer[itxt].key));
			}
		}
	}
	else {
		printf("%.*s : %s type %u rclass 0x%x ttl %u length %d\n",
		       MDNS_STRING_FORMAT(fromaddrstr), entrytype,
		       type, rclass, ttl, (int)length);
	}
	return 0;
}

static int
service_callback(const struct sockaddr* from, size_t addrlen,
                mdns_entry_type_t entry, uint16_t type,
                uint16_t rclass, uint32_t ttl,
                const void* data, size_t size, size_t offset, size_t length,
                void* user_data) {
	mdns_string_t fromaddrstr = ip_address_to_string(addrbuffer, sizeof(addrbuffer), from, addrlen);
	const char* entrytype = "question";
	if (entry == MDNS_ENTRYTYPE_ANSWER) 
		entrytype = "answer";
	if (entry == MDNS_ENTRYTYPE_AUTHORITY) 
		entrytype = "authority";
	if (entry == MDNS_ENTRYTYPE_ADDITIONAL)
		entrytype = "additional";
	if (type == MDNS_RECORDTYPE_PTR) {
		mdns_string_t namestr = mdns_record_parse_ptr(data, size, offset, length,
		                                              namebuffer, sizeof(namebuffer));
		printf("%.*s : %s PTR %.*s type %u rclass 0x%x ttl %u length %d\n",
		       MDNS_STRING_FORMAT(fromaddrstr), entrytype,
		       MDNS_STRING_FORMAT(namestr), type, rclass, ttl, (int)length);
	}
	return 0;
}

int
main(int argc, const char* const* argv) {
#ifdef _WIN32
	WORD versionWanted = MAKEWORD(1, 1);
	WSADATA wsaData;
	if (WSAStartup(versionWanted, &wsaData)) {
		printf("Failed to initialize WinSock\n");
		return -1;
	}
#endif

	size_t capacity = 2048;
	void* buffer = malloc(capacity);
	void* user_data = 0;
	size_t records;

	int mode = 0;
	const char* service = "_test_mdns._tcp.local";
	for (int iarg = 0; iarg < argc; ++iarg) {
		if (strcmp(argv[iarg], "--discovery") == 0) {
			mode = 0;
		}
		else if (strcmp(argv[iarg], "--query") == 0) {
			mode = 1;
			++iarg;
			if (iarg < argc)
				service = argv[iarg];
		}
		else if (strcmp(argv[iarg], "--service") == 0) {
			mode = 2;
			++iarg;
			if (iarg < argc)
				service = argv[iarg];
		}
	}

	int port = (mode == 2) ? MDNS_PORT : 0;
	int sock = mdns_socket_open_ipv4(port);
	if (sock < 0) {
		printf("Failed to open socket: %s\n", strerror(errno));
		return -1;
	}
	printf("Opened IPv4 socket for mDNS/DNS-SD\n");

	if (mode == 0) {
		printf("Sending DNS-SD discovery\n");
		if (mdns_discovery_send(sock)) {
			printf("Failed to send DNS-DS discovery: %s\n", strerror(errno));
			goto quit;
		}

		printf("Reading DNS-SD replies\n");
		for (int i = 0; i < 10; ++i) {
			do {
				records = mdns_discovery_recv(sock, buffer, capacity, query_callback,
				                              user_data);
			} while (records);
			if (records)
				i = 0;
			sleep(1);
		}
	} else if (mode == 1) {
		printf("Sending mDNS query: %s\n", service);
		if (mdns_query_send(sock, MDNS_RECORDTYPE_PTR,
		                    service, strlen(service),
		                    buffer, capacity)) {
			printf("Failed to send mDNS query: %s\n", strerror(errno));
			goto quit;
		}

		printf("Reading mDNS replies\n");
		for (int i = 0; i < 5; ++i) {
			do {
				records = mdns_query_recv(sock, buffer, capacity, query_callback, user_data, 1);
			} while (records);
			if (records)
				i = 0;
			sleep(1);
		}
	} else if (mode == 2) {
		printf("Service mDNS: %s\n", service);
		for (int i = 0; i < 60; ++i) {
			do {
				records = mdns_socket_listen(sock, buffer, capacity, service_callback, service);
			} while (records);
			if (records)
				i = 0;
			sleep(1);
		}
	}

quit:
	free(buffer);

	mdns_socket_close(sock);
	printf("Closed socket\n");

#ifdef _WIN32
	WSACleanup();
#endif

	return 0;
}
