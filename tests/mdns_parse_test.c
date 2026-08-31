#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "mdns.h"

struct parsed_record {
	int callback_count;
	mdns_entry_type_t entry;
	uint16_t query_id;
	uint16_t type;
	uint16_t rclass;
	uint32_t ttl;
	char name[64];
	size_t name_length;
	struct sockaddr_in address;
	int address_parsed;
};

static int
make_receiver(struct sockaddr_in* address) {
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	socklen_t length = sizeof(*address);
	assert_true(sock >= 0);
	memset(address, 0, sizeof(*address));
	address->sin_family = AF_INET;
	address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	assert_int_equal(bind(sock, (const struct sockaddr*)address, sizeof(*address)), 0);
	assert_int_equal(getsockname(sock, (struct sockaddr*)address, &length), 0);
	return sock;
}

static int
capture_record(int sock, const struct sockaddr* from, size_t addrlen, mdns_entry_type_t entry,
               uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void* data,
               size_t size, size_t name_offset, size_t name_length, size_t record_offset,
               size_t record_length, void* user_data) {
	struct parsed_record* record = user_data;
	mdns_string_t name;

	(void)sock;
	(void)from;
	(void)addrlen;
	(void)name_length;

	++record->callback_count;
	record->entry = entry;
	record->query_id = query_id;
	record->type = rtype;
	record->rclass = rclass;
	record->ttl = ttl;
	name = mdns_string_extract(data, size, &name_offset, record->name, sizeof(record->name));
	record->name_length = name.length;
	record->address_parsed =
	    mdns_record_parse_a(data, size, record_offset, record_length, &record->address) != NULL;
	return 0;
}

static void
test_parses_simple_a_response(void** state) {
	static const uint8_t packet[] = {
	    0x00, 0x00, /* Query ID */
	    0x84, 0x00, /* Response and authoritative-answer flags */
	    0x00, 0x00, /* Questions */
	    0x00, 0x01, /* Answer records */
	    0x00, 0x00, /* Authority records */
	    0x00, 0x00, /* Additional records */
	    0x04, 'h',  'o',  's',  't', 0x05, 'l', 'o', 'c', 'a', 'l', 0x00, /* host.local. */
	    0x00, 0x01,                                                       /* A record */
	    0x80, 0x01,             /* Cache flush and class IN */
	    0x00, 0x00, 0x00, 0x78, /* TTL: 120 seconds */
	    0x00, 0x04,             /* Record data length */
	    0xc0, 0xa8, 0x01, 0x2a, /* 192.168.1.42 */
	};
	static const uint8_t expected_address[] = {0xc0, 0xa8, 0x01, 0x2a};
	struct parsed_record record = {0};
	size_t offset = 12;
	uint16_t query_id = mdns_ntohs(packet);
	size_t answer_count = mdns_ntohs(packet + 6);
	size_t parsed;

	(void)state;

	parsed = mdns_records_parse(-1, NULL, 0, packet, sizeof(packet), &offset, MDNS_ENTRYTYPE_ANSWER,
	                            query_id, answer_count, capture_record, &record);

	assert_int_equal(parsed, 1);
	assert_int_equal(offset, sizeof(packet));
	assert_int_equal(record.callback_count, 1);
	assert_int_equal(record.entry, MDNS_ENTRYTYPE_ANSWER);
	assert_int_equal(record.query_id, 0);
	assert_int_equal(record.type, MDNS_RECORDTYPE_A);
	assert_int_equal(record.rclass, MDNS_CACHE_FLUSH | MDNS_CLASS_IN);
	assert_int_equal(record.ttl, 120);
	assert_int_equal(record.name_length, strlen("host.local."));
	assert_memory_equal(record.name, "host.local.", record.name_length);
	assert_true(record.address_parsed);
	assert_int_equal(record.address.sin_family, AF_INET);
	assert_memory_equal(&record.address.sin_addr, expected_address, sizeof(expected_address));
}

static void
test_listen_rejects_question_without_type_and_class(void** state) {
	uint8_t packet[sizeof(struct mdns_header_t) + 1] = {0};
	uint8_t receive_buffer[sizeof(packet) + 4] = {0};
	struct parsed_record record = {0};
	struct sockaddr_in receiver_address;
	int receiver = make_receiver(&receiver_address);
	int sender = socket(AF_INET, SOCK_DGRAM, 0);

	(void)state;
	assert_true(sender >= 0);
	packet[5] = 1;
	/* Bytes after the received datagram look like a valid QTYPE and QCLASS. */
	receive_buffer[sizeof(packet) + 1] = MDNS_RECORDTYPE_A;
	receive_buffer[sizeof(packet) + 3] = MDNS_CLASS_IN;
	assert_int_equal(sendto(sender, packet, sizeof(packet), 0,
	                        (const struct sockaddr*)&receiver_address, sizeof(receiver_address)),
	                 sizeof(packet));
	assert_int_equal(mdns_socket_listen(receiver, receive_buffer, sizeof(receive_buffer),
	                                    capture_record, &record),
	                 0);
	assert_int_equal(record.callback_count, 0);
	close(sender);
	close(receiver);
}

int
main(void) {
	const struct CMUnitTest tests[] = {
	    cmocka_unit_test(test_parses_simple_a_response),
	    cmocka_unit_test(test_listen_rejects_question_without_type_and_class),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
