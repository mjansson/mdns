
#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS 1
#endif

#include "mdns.h"

#include <stdio.h>
#include <errno.h>

#ifdef _WIN32
#include <iphlpapi.h>
#define sleep(x) Sleep(x * 1000)
#else
#include <netdb.h>
#include <ifaddrs.h>
#endif

static char addrbuffer[64];
static char namebuffer[256];
static char sendbuffer[256];
static mdns_record_txt_t txtbuffer[128];

static uint32_t service_address_ipv4;
static uint8_t service_address_ipv6[16];

typedef struct {
	const char* service;
	const char* hostname;
	uint32_t address_ipv4;
	uint8_t* address_ipv6;
	int port;
} service_record_t;

static mdns_string_t
ipv4_address_to_string(char* buffer, size_t capacity, const struct sockaddr_in* addr,
                       size_t addrlen) {
	char host[NI_MAXHOST] = {0};
	char service[NI_MAXSERV] = {0};
	int ret = getnameinfo((const struct sockaddr*)addr, addrlen, host, NI_MAXHOST, service,
	                      NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);
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
ipv6_address_to_string(char* buffer, size_t capacity, const struct sockaddr_in6* addr,
                       size_t addrlen) {
	char host[NI_MAXHOST] = {0};
	char service[NI_MAXSERV] = {0};
	int ret = getnameinfo((const struct sockaddr*)addr, addrlen, host, NI_MAXHOST, service,
	                      NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);
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
query_callback(int sock, const struct sockaddr* from, size_t addrlen, mdns_entry_type_t entry,
               uint16_t transaction_id, uint16_t rtype, uint16_t rclass, uint32_t ttl,
               const void* data, size_t size, size_t offset, size_t length, void* user_data) {
	mdns_string_t fromaddrstr = ip_address_to_string(addrbuffer, sizeof(addrbuffer), from, addrlen);
	const char* entrytype = (entry == MDNS_ENTRYTYPE_ANSWER) ?
	                            "answer" :
	                            ((entry == MDNS_ENTRYTYPE_AUTHORITY) ? "authority" : "additional");
	if (rtype == MDNS_RECORDTYPE_PTR) {
		mdns_string_t namestr =
		    mdns_record_parse_ptr(data, size, offset, length, namebuffer, sizeof(namebuffer));
		printf("%.*s : %s PTR %.*s rclass 0x%x ttl %u length %d\n", MDNS_STRING_FORMAT(fromaddrstr),
		       entrytype, MDNS_STRING_FORMAT(namestr), rclass, ttl, (int)length);
	} else if (rtype == MDNS_RECORDTYPE_SRV) {
		mdns_record_srv_t srv =
		    mdns_record_parse_srv(data, size, offset, length, namebuffer, sizeof(namebuffer));
		printf("%.*s : %s SRV %.*s priority %d weight %d port %d\n",
		       MDNS_STRING_FORMAT(fromaddrstr), entrytype, MDNS_STRING_FORMAT(srv.name),
		       srv.priority, srv.weight, srv.port);
	} else if (rtype == MDNS_RECORDTYPE_A) {
		struct sockaddr_in addr;
		mdns_record_parse_a(data, size, offset, length, &addr);
		mdns_string_t addrstr =
		    ipv4_address_to_string(namebuffer, sizeof(namebuffer), &addr, sizeof(addr));
		printf("%.*s : %s A %.*s\n", MDNS_STRING_FORMAT(fromaddrstr), entrytype,
		       MDNS_STRING_FORMAT(addrstr));
	} else if (rtype == MDNS_RECORDTYPE_AAAA) {
		struct sockaddr_in6 addr;
		mdns_record_parse_aaaa(data, size, offset, length, &addr);
		mdns_string_t addrstr =
		    ipv6_address_to_string(namebuffer, sizeof(namebuffer), &addr, sizeof(addr));
		printf("%.*s : %s AAAA %.*s\n", MDNS_STRING_FORMAT(fromaddrstr), entrytype,
		       MDNS_STRING_FORMAT(addrstr));
	} else if (rtype == MDNS_RECORDTYPE_TXT) {
		size_t parsed = mdns_record_parse_txt(data, size, offset, length, txtbuffer,
		                                      sizeof(txtbuffer) / sizeof(mdns_record_txt_t));
		for (size_t itxt = 0; itxt < parsed; ++itxt) {
			if (txtbuffer[itxt].value.length) {
				printf("%.*s : %s TXT %.*s = %.*s\n", MDNS_STRING_FORMAT(fromaddrstr), entrytype,
				       MDNS_STRING_FORMAT(txtbuffer[itxt].key),
				       MDNS_STRING_FORMAT(txtbuffer[itxt].value));
			} else {
				printf("%.*s : %s TXT %.*s\n", MDNS_STRING_FORMAT(fromaddrstr), entrytype,
				       MDNS_STRING_FORMAT(txtbuffer[itxt].key));
			}
		}
	} else {
		printf("%.*s : %s type %u rclass 0x%x ttl %u length %d\n", MDNS_STRING_FORMAT(fromaddrstr),
		       entrytype, rtype, rclass, ttl, (int)length);
	}
	return 0;
}

static int
service_callback(int sock, const struct sockaddr* from, size_t addrlen, mdns_entry_type_t entry,
                 uint16_t transaction_id, uint16_t rtype, uint16_t rclass, uint32_t ttl,
                 const void* data, size_t size, size_t offset, size_t length, void* user_data) {
	if (entry != MDNS_ENTRYTYPE_QUESTION)
		return 0;
	mdns_string_t fromaddrstr = ip_address_to_string(addrbuffer, sizeof(addrbuffer), from, addrlen);
	if (rtype == MDNS_RECORDTYPE_PTR) {
		mdns_string_t service =
		    mdns_string_extract(data, size, &offset, namebuffer, sizeof(namebuffer));
		printf("%.*s : question PTR %.*s\n", MDNS_STRING_FORMAT(fromaddrstr),
		       MDNS_STRING_FORMAT(service));

		const char dns_sd[] = "_services._dns-sd._udp.local.";
		const service_record_t* service_record = (const service_record_t*)user_data;
		size_t service_length = strlen(service_record->service);
		if ((service.length == (sizeof(dns_sd) - 1)) &&
		    (strncmp(service.str, dns_sd, sizeof(dns_sd) - 1) == 0)) {
			printf("  --> answer %s\n", service_record->service);
			mdns_discovery_answer(sock, from, addrlen, sendbuffer, sizeof(sendbuffer),
			                      service_record->service, service_length);
		} else if ((service.length == service_length) &&
		           (strncmp(service.str, service_record->service, service_length) == 0)) {
			printf("  --> answer %s.%s port %d\n", service_record->hostname,
			       service_record->service, service_record->port);
			mdns_query_answer(sock, from, addrlen, sendbuffer, sizeof(sendbuffer), transaction_id,
			                  service_record->service, service_length, service_record->hostname,
			                  strlen(service_record->hostname), service_record->address_ipv4,
			                  service_record->address_ipv6, (uint16_t)service_record->port, 0, 0);
		}
	}
	return 0;
}

static int
open_client_sockets(int* sockets, int max_sockets) {
	// When sending, each socket can only send to one network interface
	// Thus we need to open one socket for each interface and address family
	int num_sockets = 0;

#ifdef _WIN32

	IP_ADAPTER_ADDRESSES* adapter_address = 0;
	unsigned int address_size = 8000;
	unsigned int ret;
	unsigned int num_retries = 4;
	do {
		adapter_address = malloc(address_size);
		ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, 0,
		                           adapter_address, &address_size);
		if (ret == ERROR_BUFFER_OVERFLOW) {
			free(adapter_address);
			adapter_address = 0;
		} else {
			break;
		}
	} while (num_retries-- > 0);

	if (!adapter_address || (ret != NO_ERROR)) {
		free(adapter_address);
		printf("Failed to get network adapter addresses\n");
		return num_sockets;
	}

	int first_ipv4 = 1;
	int first_ipv6 = 1;
	for (PIP_ADAPTER_ADDRESSES adapter = adapter_address; adapter; adapter = adapter->Next) {
		if (adapter->TunnelType == TUNNEL_TYPE_TEREDO)
			continue;
		if (adapter->OperStatus != IfOperStatusUp)
			continue;

		for (IP_ADAPTER_UNICAST_ADDRESS* unicast = adapter->FirstUnicastAddress; unicast;
		     unicast = unicast->Next) {
			if (unicast->Address.lpSockaddr->sa_family == AF_INET) {
				struct sockaddr_in* saddr = (struct sockaddr_in*)unicast->Address.lpSockaddr;
				if ((saddr->sin_addr.S_un.S_un_b.s_b1 != 127) ||
				    (saddr->sin_addr.S_un.S_un_b.s_b2 != 0) ||
				    (saddr->sin_addr.S_un.S_un_b.s_b3 != 0) ||
				    (saddr->sin_addr.S_un.S_un_b.s_b4 != 1)) {
					int log_addr = 0;
					if (first_ipv4) {
						service_address_ipv4 = saddr->sin_addr.S_un.S_addr;
						first_ipv4 = 0;
						log_addr = 1;
					}
					if (num_sockets < max_sockets) {
						saddr->sin_port = 0;
						int sock = mdns_socket_open_ipv4(saddr);
						if (sock >= 0) {
							sockets[num_sockets++] = sock;
							log_addr = 1;
						} else {
							log_addr = 0;
						}
					}
					if (log_addr) {
						char buffer[128];
						mdns_string_t addr = ipv4_address_to_string(
						    buffer, sizeof(buffer), saddr, sizeof(struct sockaddr_in));
						printf("Local IPv4 address: %.*s\n", MDNS_STRING_FORMAT(addr));
					}
				}
			} else if (unicast->Address.lpSockaddr->sa_family == AF_INET6) {
				struct sockaddr_in6* saddr = (struct sockaddr_in6*)unicast->Address.lpSockaddr;
				static const unsigned char localhost[] = {0, 0, 0, 0, 0, 0, 0, 0,
				                                          0, 0, 0, 0, 0, 0, 0, 1};
				static const unsigned char localhost_mapped[] = {0, 0, 0,    0,    0,    0, 0, 0,
				                                                 0, 0, 0xff, 0xff, 0x7f, 0, 0, 1};
				if ((unicast->DadState == NldsPreferred) &&
				    memcmp(saddr->sin6_addr.s6_addr, localhost, 16) &&
				    memcmp(saddr->sin6_addr.s6_addr, localhost_mapped, 16)) {
					int log_addr = 0;
					if (first_ipv6) {
						memcpy(service_address_ipv6, &saddr->sin6_addr, 16);
						first_ipv6 = 0;
						log_addr = 1;
					}
					if (num_sockets < max_sockets) {
						saddr->sin6_port = 0;
						int sock = mdns_socket_open_ipv6(saddr);
						if (sock >= 0) {
							sockets[num_sockets++] = sock;
							log_addr = 1;
						} else {
							log_addr = 0;
						}
					}
					if (log_addr) {
						char buffer[128];
						mdns_string_t addr = ipv6_address_to_string(
						    buffer, sizeof(buffer), saddr, sizeof(struct sockaddr_in6));
						printf("Local IPv6 address: %.*s\n", MDNS_STRING_FORMAT(addr));
					}
				}
			}
		}
	}

	free(adapter_address);

#else

	struct ifaddrs* ifaddr = 0;
	struct ifaddrs* ifa = 0;

	if (getifaddrs(&ifaddr) < 0)
		printf("Unable to get interface addresses\n");

	int first_ipv4 = 1;
	int first_ipv6 = 1;
	for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr)
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET) {
			struct sockaddr_in* saddr = (struct sockaddr_in*)ifa->ifa_addr;
			if (saddr->sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
				int log_addr = 0;
				if (first_ipv4) {
					service_address_ipv4 = saddr->sin_addr.s_addr;
					first_ipv4 = 0;
					log_addr = 1;
				}
				if (num_sockets < max_sockets) {
					saddr->sin_port = 0;
					int sock = mdns_socket_open_ipv4(saddr);
					if (sock >= 0) {
						sockets[num_sockets++] = sock;
						log_addr = 1;
					} else {
						log_addr = 0;
					}
				}
				if (log_addr) {
					char buffer[128];
					mdns_string_t addr = ipv4_address_to_string(
					    buffer, sizeof(buffer), saddr, sizeof(struct sockaddr_in));
					printf("Local IPv4 address: %.*s\n", MDNS_STRING_FORMAT(addr));
				}
			}
		} else if (ifa->ifa_addr->sa_family == AF_INET6) {
			struct sockaddr_in6* saddr = (struct sockaddr_in6*)ifa->ifa_addr;
			static const unsigned char localhost[] = {0, 0, 0, 0, 0, 0, 0, 0,
			                                          0, 0, 0, 0, 0, 0, 0, 1};
			static const unsigned char localhost_mapped[] = {0, 0, 0,    0,    0,    0, 0, 0,
			                                                 0, 0, 0xff, 0xff, 0x7f, 0, 0, 1};
			if (memcmp(saddr->sin6_addr.s6_addr, localhost, 16) &&
			    memcmp(saddr->sin6_addr.s6_addr, localhost_mapped, 16)) {
				int log_addr = 0;
				if (first_ipv6) {
					memcpy(service_address_ipv6, &saddr->sin6_addr, 16);
					first_ipv6 = 0;
					log_addr = 1;
				}
				if (num_sockets < max_sockets) {
					saddr->sin6_port = 0;
					int sock = mdns_socket_open_ipv6(saddr);
					if (sock >= 0) {
						sockets[num_sockets++] = sock;
						log_addr = 1;
					} else {
						log_addr = 0;
					}
				}
				if (log_addr) {
					char buffer[128];
					mdns_string_t addr = ipv6_address_to_string(
					    buffer, sizeof(buffer), saddr, sizeof(struct sockaddr_in6));
					printf("Local IPv6 address: %.*s\n", MDNS_STRING_FORMAT(addr));
				}
			}
		}
	}

	freeifaddrs(ifaddr);

#endif

	for (int isock = 0; isock < num_sockets; ++isock) {
#ifdef _WIN32
		unsigned long param = 1;
		ioctlsocket(sockets[isock], FIONBIO, &param);
#else
		const int flags = fcntl(sockets[isock], F_GETFL, 0);
		fcntl(sockets[isock], F_SETFL, flags | O_NONBLOCK);
#endif
	}

	return num_sockets;
}

static int
open_service_sockets(int* sockets, int max_sockets) {
	// When recieving, each socket can recieve data from all network interfaces
	// Thus we only need to open one socket for each address family
	int num_sockets = 0;

	// Call the client socket function to enumerate and get local addresses
	open_client_sockets(0, 0);

	if (num_sockets < max_sockets) {
		struct sockaddr_in sock_addr;
		memset(&sock_addr, 0, sizeof(struct sockaddr_in));
		sock_addr.sin_family = AF_INET;
#ifdef _WIN32
		sock_addr.sin_addr = in4addr_any;
#else
		sock_addr.sin_addr.s_addr = INADDR_ANY;
#endif
		sock_addr.sin_port = htons(MDNS_PORT);
#ifdef __APPLE__
		sock_addr.sin_len = sizeof(struct sockaddr_in);
#endif
		int sock = mdns_socket_open_ipv4(&sock_addr);
		if (sock >= 0)
			sockets[num_sockets++] = sock;
	}

	if (num_sockets < max_sockets) {
		struct sockaddr_in6 sock_addr;
		memset(&sock_addr, 0, sizeof(struct sockaddr_in6));
		sock_addr.sin6_family = AF_INET6;
		sock_addr.sin6_addr = in6addr_any;
		sock_addr.sin6_port = htons(MDNS_PORT);
#ifdef __APPLE__
		sock_addr.sin6_len = sizeof(struct sockaddr_in6);
#endif
		int sock = mdns_socket_open_ipv6(&sock_addr);
		if (sock >= 0)
			sockets[num_sockets++] = sock;
	}

	for (int isock = 0; isock < num_sockets; ++isock) {
#ifdef _WIN32
		unsigned long param = 1;
		ioctlsocket(sockets[isock], FIONBIO, &param);
#else
		const int flags = fcntl(sockets[isock], F_GETFL, 0);
		fcntl(sockets[isock], F_SETFL, flags | O_NONBLOCK);
#endif
	}

	return num_sockets;
}

static int
send_dns_sd(void) {
	int sockets[32];
	int num_sockets = open_client_sockets(sockets, sizeof(sockets) / sizeof(sockets[0]));
	if (num_sockets <= 0) {
		printf("Failed to open any client sockets\n");
		return -1;
	}
	printf("Opened %d socket%s for DNS-SD\n", num_sockets, num_sockets ? "s" : "");

	printf("Sending DNS-SD discovery\n");
	for (int isock = 0; isock < num_sockets; ++isock) {
		if (mdns_discovery_send(sockets[isock]))
			printf("Failed to send DNS-DS discovery: %s\n", strerror(errno));
	}

	size_t capacity = 2048;
	void* buffer = malloc(capacity);
	void* user_data = 0;

	// This is a simple implementation that loops for 10 seconds or as long as we get replies
	// A real world implementation would probably use select, poll or similar syscall to wait
	// until data is available on a socket and then read it
	printf("Reading DNS-SD replies\n");
	for (int i = 0; i < 10; ++i) {
		size_t records;
		do {
			records = 0;
			for (int isock = 0; isock < num_sockets; ++isock) {
				records += mdns_discovery_recv(sockets[isock], buffer, capacity, query_callback,
				                               user_data);
			}
		} while (records);
		if (records)
			i = 0;
		sleep(1);
	}

	free(buffer);

	for (int isock = 0; isock < num_sockets; ++isock)
		mdns_socket_close(sockets[isock]);
	printf("Closed socket%s\n", num_sockets ? "s" : "");

	return 0;
}

static int
send_mdns_query(const char* service) {
	int sockets[32];
	int num_sockets = open_client_sockets(sockets, sizeof(sockets) / sizeof(sockets[0]));
	if (num_sockets <= 0) {
		printf("Failed to open any client sockets\n");
		return -1;
	}
	printf("Opened %d socket%s for mDNS query\n", num_sockets, num_sockets ? "s" : "");

	size_t capacity = 2048;
	void* buffer = malloc(capacity);
	void* user_data = 0;

	printf("Sending mDNS query: %s\n", service);
	for (int isock = 0; isock < num_sockets; ++isock) {
		if (mdns_query_send(sockets[isock], MDNS_RECORDTYPE_PTR, service, strlen(service), buffer,
		                    capacity))
			printf("Failed to send mDNS query: %s\n", strerror(errno));
	}

	// This is a simple implementation that loops for 10 seconds or as long as we get replies
	// A real world implementation would probably use select, poll or similar syscall to wait
	// until data is available on a socket and then read it
	printf("Reading mDNS query replies\n");
	for (int i = 0; i < 10; ++i) {
		size_t records;
		do {
			records = 0;
			for (int isock = 0; isock < num_sockets; ++isock) {
				records +=
				    mdns_query_recv(sockets[isock], buffer, capacity, query_callback, user_data, 1);
			}
		} while (records);
		if (records)
			i = 0;
		sleep(1);
	}

	free(buffer);

	for (int isock = 0; isock < num_sockets; ++isock)
		mdns_socket_close(sockets[isock]);
	printf("Closed socket%s\n", num_sockets ? "s" : "");

	return 0;
}

static int
service_mdns(const char* hostname, const char* service, int service_port) {
	int sockets[32];
	int num_sockets = open_service_sockets(sockets, sizeof(sockets) / sizeof(sockets[0]));
	if (num_sockets <= 0) {
		printf("Failed to open any client sockets\n");
		return -1;
	}
	printf("Opened %d socket%s for mDNS service\n", num_sockets, num_sockets ? "s" : "");

	printf("Service mDNS: %s:%d\n", service, service_port);
	printf("Hostname: %s\n", hostname);

	size_t capacity = 2048;
	void* buffer = malloc(capacity);

	service_record_t service_record = {service, hostname, service_address_ipv4,
	                                   service_address_ipv6, service_port};

	// This is a crude implementation that loops and checks for incoming queries, then sleeps
	// for one second. A real world implementation would probably use select, poll or similar
	// syscall to wait until data is available on a socket and then read it
	int error_code = 0;
	do {
		for (int isock = 0; isock < num_sockets; ++isock) {
			mdns_socket_listen(sockets[isock], buffer, capacity, service_callback, &service_record);

			int error_code_size = sizeof(error_code);
			getsockopt(sockets[isock], SOL_SOCKET, SO_ERROR, (char*)&error_code,
			           (socklen_t*)&error_code_size);
		}
		sleep(1);
	} while (num_sockets && !error_code);

	free(buffer);

	for (int isock = 0; isock < num_sockets; ++isock)
		mdns_socket_close(sockets[isock]);
	printf("Closed socket%s\n", num_sockets ? "s" : "");

	return 0;
}

int
main(int argc, const char* const* argv) {
	int mode = 0;
	const char* service = "_test_mdns._tcp.local.";
	const char* hostname = "dummy-host";
	int service_port = 42424;

#ifdef _WIN32

	WORD versionWanted = MAKEWORD(1, 1);
	WSADATA wsaData;
	if (WSAStartup(versionWanted, &wsaData)) {
		printf("Failed to initialize WinSock\n");
		return -1;
	}

	char hostname_buffer[256];
	DWORD hostname_size = (DWORD)sizeof(hostname_buffer);
	if (GetComputerNameA(hostname_buffer, &hostname_size))
		hostname = hostname_buffer;

#else

	char hostname_buffer[256];
	size_t hostname_size = sizeof(hostname_buffer);
	if (gethostname(hostname_buffer, hostname_size) == 0)
		hostname = hostname_buffer;

#endif

	for (int iarg = 0; iarg < argc; ++iarg) {
		if (strcmp(argv[iarg], "--discovery") == 0) {
			mode = 0;
		} else if (strcmp(argv[iarg], "--query") == 0) {
			mode = 1;
			++iarg;
			if (iarg < argc)
				service = argv[iarg];
		} else if (strcmp(argv[iarg], "--service") == 0) {
			mode = 2;
			++iarg;
			if (iarg < argc)
				service = argv[iarg];
		} else if (strcmp(argv[iarg], "--hostname") == 0) {
			++iarg;
			if (iarg < argc)
				hostname = argv[iarg];
		} else if (strcmp(argv[iarg], "--port") == 0) {
			++iarg;
			if (iarg < argc)
				service_port = atoi(argv[iarg]);
		}
	}

	int ret;
	if (mode == 0)
		ret = send_dns_sd();
	else if (mode == 1)
		ret = send_mdns_query(service);
	else if (mode == 2)
		ret = service_mdns(hostname, service, service_port);

#ifdef _WIN32
	WSACleanup();
#endif

	return 0;
}
