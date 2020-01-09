
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

static int mdns_sock;
static char addrbuffer[64];
static char namebuffer[256];
static char sendbuffer[256];
static mdns_record_txt_t txtbuffer[128];

typedef struct {
	const char* service;
	const char* hostname;
	int port;
} service_record_t;

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
               mdns_entry_type_t entry, uint16_t transaction_id,
               uint16_t rtype, uint16_t rclass, uint32_t ttl,
               const void* data, size_t size, size_t offset, size_t length,
               void* user_data) {
	mdns_string_t fromaddrstr = ip_address_to_string(addrbuffer, sizeof(addrbuffer), from, addrlen);
	const char* entrytype = (entry == MDNS_ENTRYTYPE_ANSWER) ? "answer" :
	                        ((entry == MDNS_ENTRYTYPE_AUTHORITY) ? "authority" : "additional");
	if (rtype == MDNS_RECORDTYPE_PTR) {
		mdns_string_t namestr = mdns_record_parse_ptr(data, size, offset, length,
		                                              namebuffer, sizeof(namebuffer));
		printf("%.*s : %s PTR %.*s rclass 0x%x ttl %u length %d\n",
		       MDNS_STRING_FORMAT(fromaddrstr), entrytype,
		       MDNS_STRING_FORMAT(namestr), rclass, ttl, (int)length);
	}
	else if (rtype == MDNS_RECORDTYPE_SRV) {
		mdns_record_srv_t srv = mdns_record_parse_srv(data, size, offset, length,
		                                              namebuffer, sizeof(namebuffer));
		printf("%.*s : %s SRV %.*s priority %d weight %d port %d\n",
		       MDNS_STRING_FORMAT(fromaddrstr), entrytype,
		       MDNS_STRING_FORMAT(srv.name), srv.priority, srv.weight, srv.port);
	}
	else if (rtype == MDNS_RECORDTYPE_A) {
		struct sockaddr_in addr;
		mdns_record_parse_a(data, size, offset, length, &addr);
		mdns_string_t addrstr = ipv4_address_to_string(namebuffer, sizeof(namebuffer), &addr, sizeof(addr));
		printf("%.*s : %s A %.*s\n",
		       MDNS_STRING_FORMAT(fromaddrstr), entrytype,
		       MDNS_STRING_FORMAT(addrstr));
	}
	else if (rtype == MDNS_RECORDTYPE_AAAA) {
		struct sockaddr_in6 addr;
		mdns_record_parse_aaaa(data, size, offset, length, &addr);
		mdns_string_t addrstr = ipv6_address_to_string(namebuffer, sizeof(namebuffer), &addr, sizeof(addr));
		printf("%.*s : %s AAAA %.*s\n",
		       MDNS_STRING_FORMAT(fromaddrstr), entrytype,
		       MDNS_STRING_FORMAT(addrstr));
	}
	else if (rtype == MDNS_RECORDTYPE_TXT) {
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
		       rtype, rclass, ttl, (int)length);
	}
	return 0;
}

static int
service_callback(const struct sockaddr* from, size_t addrlen,
                mdns_entry_type_t entry, uint16_t transaction_id,
                uint16_t rtype, uint16_t rclass, uint32_t ttl,
                const void* data, size_t size, size_t offset, size_t length,
                void* user_data) {
	if (entry != MDNS_ENTRYTYPE_QUESTION) 
		return 0;
	mdns_string_t fromaddrstr = ip_address_to_string(addrbuffer, sizeof(addrbuffer), from, addrlen);
	if (rtype == MDNS_RECORDTYPE_PTR) {
		mdns_string_t service = mdns_string_extract(data, size, &offset,
		                                            namebuffer, sizeof(namebuffer));
		printf("%.*s : question PTR %.*s\n",
		       MDNS_STRING_FORMAT(fromaddrstr), MDNS_STRING_FORMAT(service));

		const char dns_sd[] = "_services._dns-sd._udp.local.";
		const service_record_t* service_record = (const service_record_t*)user_data;
		size_t service_length = strlen(service_record->service);
		if ((service.length == (sizeof(dns_sd) - 1)) && (strcmp(service.str, dns_sd) == 0)) {
			printf("  --> answer %s\n", service_record->service);
			mdns_discovery_answer(mdns_sock, from, addrlen, sendbuffer,
                                  sizeof(sendbuffer), service_record->service, service_length);
		}
		else if ((service.length == service_length) && (strcmp(service.str, service_record->service) == 0)) {
			printf("  --> answer %s.%s port %d\n", service_record->hostname, service_record->service, service_record->port);
			mdns_query_answer(mdns_sock, from, addrlen, sendbuffer, sizeof(sendbuffer),
			                  transaction_id, service_record->service, service_length,
			                  service_record->hostname, strlen(service_record->hostname),
			                  (uint16_t)service_record->port);
		}
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
	const char* service = "_test_mdns._tcp.local.";
	const char* hostname = "dummy-host";
	int service_port = 42424;
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
		else if (strcmp(argv[iarg], "--hostname") == 0) {
			++iarg;
			if (iarg < argc)
				hostname = argv[iarg];
		}
		else if (strcmp(argv[iarg], "--port") == 0) {
			++iarg;
			if (iarg < argc)
				service_port = atoi(argv[iarg]);
		}
	}

	int port = (mode == 2) ? MDNS_PORT : 0;
	mdns_sock = mdns_socket_open_ipv4(port);
	if (mdns_sock < 0) {
		printf("Failed to open socket: %s\n", strerror(errno));
		return -1;
	}
	printf("Opened IPv4 socket for mDNS/DNS-SD\n");

	if (mode == 0) {
		printf("Sending DNS-SD discovery\n");
		if (mdns_discovery_send(mdns_sock)) {
			printf("Failed to send DNS-DS discovery: %s\n", strerror(errno));
			goto quit;
		}

		printf("Reading DNS-SD replies\n");
		for (int i = 0; i < 10; ++i) {
			do {
				records = mdns_discovery_recv(mdns_sock, buffer, capacity, query_callback,
				                              user_data);
			} while (records);
			if (records)
				i = 0;
			sleep(1);
		}
	} else if (mode == 1) {
		printf("Sending mDNS query: %s\n", service);
		if (mdns_query_send(mdns_sock, MDNS_RECORDTYPE_PTR,
		                    service, strlen(service),
		                    buffer, capacity)) {
			printf("Failed to send mDNS query: %s\n", strerror(errno));
			goto quit;
		}

		printf("Reading mDNS replies\n");
		for (int i = 0; i < 5; ++i) {
			do {
				records = mdns_query_recv(mdns_sock, buffer, capacity, query_callback, user_data, 1);
			} while (records);
			if (records)
				i = 0;
			sleep(1);
		}
	} else if (mode == 2) {
		printf("Service mDNS: %s\n", service);
#ifdef _WIN32
		unsigned long param = 0;
		ioctlsocket(mdns_sock, FIONBIO, &param);
#else
		const int flags = fcntl(sock, F_GETFL, 0);
		fcntl(mdns_sock, F_SETFL, flags & ~O_NONBLOCK);
#endif

		service_record_t service_record = {
			service,
			hostname,
			service_port
		};

		int error_code = 0;
		do {
			mdns_socket_listen(mdns_sock, buffer, capacity, service_callback, &service_record);
			int error_code_size = sizeof(error_code);
			getsockopt(mdns_sock, SOL_SOCKET, SO_ERROR, (char*)&error_code, &error_code_size);			
		} while (!error_code);
	}

quit:
	free(buffer);

	mdns_socket_close(mdns_sock);
	printf("Closed socket\n");

#ifdef _WIN32
	WSACleanup();
#endif

	return 0;
}
