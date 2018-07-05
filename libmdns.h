/* mdns.h  -  mDNS/DNS-SD library  -  Public Domain  -  2017 Mattias Jansson / Rampant Pixels
 *
 * This library provides a cross-platform mDNS and DNS-SD library in C.
 * The implementation is based on RFC 6762 and RFC 6763.
 *
 * The latest source code maintained by Rampant Pixels is always available at
 *
 * https://github.com/rampantpixels/mdns
 *
 * This library is put in the public domain; you can redistribute it and/or modify it without any restrictions.
 *
 */

#ifndef MDNS_H
#define MDNS_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MDNS_INVALID_POS ((size_t)-1)

#define MDNS_STRING_CONST(s) (s), (sizeof((s))-1)
#define MDNS_STRING_FORMAT(s) (int)((s).length), s.str

enum mdns_record_type {
	MDNS_RECORDTYPE_IGNORE = 0,
	//Address
	MDNS_RECORDTYPE_A = 1,
	//Domain Name pointer
	MDNS_RECORDTYPE_PTR = 12,
	//Arbitrary text string
	MDNS_RECORDTYPE_TXT = 16,
	//IP6 Address [Thomson]
	MDNS_RECORDTYPE_AAAA = 28,
	//Server Selection [RFC2782]
	MDNS_RECORDTYPE_SRV = 33
};

enum mdns_entry_type {
	MDNS_ENTRYTYPE_ANSWER = 1,
	MDNS_ENTRYTYPE_AUTHORITY = 2,
	MDNS_ENTRYTYPE_ADDITIONAL = 3
};

enum mdns_class {
	MDNS_CLASS_IN = 1
};

typedef enum mdns_record_type  mdns_record_type_t;
typedef enum mdns_entry_type   mdns_entry_type_t;
typedef enum mdns_class        mdns_class_t;

typedef int (* mdns_record_callback_fn)(const struct sockaddr* from,
                                        mdns_entry_type_t entry, uint16_t type,
                                        uint16_t rclass, uint32_t ttl,
                                        const void* data, size_t size, size_t offset, size_t length);

typedef struct mdns_string_t       mdns_string_t;
typedef struct mdns_string_pair_t  mdns_string_pair_t;
typedef struct mdns_record_srv_t   mdns_record_srv_t;
typedef struct mdns_record_txt_t   mdns_record_txt_t;

struct mdns_string_t {
	const char* str;
	size_t length;
};

struct mdns_string_pair_t {
	size_t  offset;
	size_t  length;
	int     ref;
};

struct mdns_record_srv_t {
	uint16_t priority;
	uint16_t weight;
	uint16_t port;
	mdns_string_t name;
};

struct mdns_record_txt_t {
	mdns_string_t key;
	mdns_string_t value;
};

int mdns_socket_open_ipv4(void);

int mdns_socket_setup_ipv4(int sock);

int mdns_socket_open_ipv6(void);

int mdns_socket_setup_ipv6(int sock);

void mdns_socket_close(int sock);

int mdns_discovery_send(int sock);

size_t mdns_discovery_recv(int sock, void* buffer, size_t capacity,
                    mdns_record_callback_fn callback);

int mdns_query_send(int sock, mdns_record_type_t type, const char* name, size_t length,
                void* buffer, size_t capacity);

size_t mdns_query_recv(int sock, void* buffer, size_t capacity,
                mdns_record_callback_fn callback);

mdns_string_t mdns_string_extract(const void* buffer, size_t size, size_t* offset,
                    char* str, size_t capacity);

int mdns_string_skip(const void* buffer, size_t size, size_t* offset);

int mdns_string_equal(const void* buffer_lhs, size_t size_lhs, size_t* ofs_lhs,
                  const void* buffer_rhs, size_t size_rhs, size_t* ofs_rhs);

void* mdns_string_make(void* data, size_t capacity, const char* name, size_t length);

mdns_string_t mdns_record_parse_ptr(const void* buffer, size_t size, size_t offset, size_t length,
                      char* strbuffer, size_t capacity);

mdns_record_srv_t mdns_record_parse_srv(const void* buffer, size_t size, size_t offset, size_t length,
                      char* strbuffer, size_t capacity);

struct sockaddr_in* mdns_record_parse_a(const void* buffer, size_t size, size_t offset, size_t length,
                    struct sockaddr_in* addr);

struct sockaddr_in6* mdns_record_parse_aaaa(const void* buffer, size_t size, size_t offset, size_t length,
                       struct sockaddr_in6* addr);

size_t mdns_record_parse_txt(const void* buffer, size_t size, size_t offset, size_t length,
                      mdns_record_txt_t* records, size_t capacity);

#endif
