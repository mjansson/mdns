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
test_record_parsers_reject_wrapped_ranges(void** state) {
	uint8_t a_data[4] = {1, 2, 3, 4};
	uint8_t aaaa_data[16] = {1, 2, 3, 4};
	uint8_t srv_data[8] = {0, 1, 0, 2, 0, 3, 0};
	struct sockaddr_in address;
	struct sockaddr_in6 address6;
	char name_buffer[32];
	mdns_record_srv_t srv;

	(void)state;
	mdns_record_parse_a(a_data, 1, SIZE_MAX - 3, 4, &address);
	mdns_record_parse_aaaa(aaaa_data, 1, SIZE_MAX - 15, 16, &address6);
	srv = mdns_record_parse_srv(srv_data, 1, SIZE_MAX - 7, 8, name_buffer,
	                            sizeof(name_buffer));
	assert_int_equal(address.sin_addr.s_addr, 0);
	assert_memory_equal(&address6.sin6_addr, (uint8_t[16]){0}, 16);
	assert_int_equal(srv.priority, 0);
	assert_int_equal(srv.weight, 0);
	assert_int_equal(srv.port, 0);
}

static void
test_record_names_stay_within_rdata(void** state) {
	static const uint8_t ptr_data[] = {3, 'b', 'a', 'd', 0};
	static const uint8_t srv_data[] = {0, 1, 0, 2, 0, 3, 3, 'b', 'a', 'd', 0};
	char ptr_buffer[32] = {0};
	char srv_buffer[32] = {0};
	mdns_string_t ptr;
	mdns_record_srv_t srv;

	(void)state;
	ptr = mdns_record_parse_ptr(ptr_data, sizeof(ptr_data), 0, 2, ptr_buffer,
	                            sizeof(ptr_buffer));
	srv = mdns_record_parse_srv(srv_data, sizeof(srv_data), 0, 8, srv_buffer,
	                            sizeof(srv_buffer));
	assert_int_equal(ptr.length, 0);
	assert_int_equal(srv.priority, 0);
	assert_int_equal(srv.weight, 0);
	assert_int_equal(srv.port, 0);
	assert_int_equal(srv.name.length, 0);
}

static void
test_srv_accepts_root_target(void** state) {
	static const uint8_t data[] = {0, 1, 0, 2, 0x13, 0x37, 0};
	char name_buffer[32];
	mdns_record_srv_t srv;

	(void)state;
	srv = mdns_record_parse_srv(data, sizeof(data), 0, sizeof(data), name_buffer,
	                            sizeof(name_buffer));
	assert_int_equal(srv.priority, 1);
	assert_int_equal(srv.weight, 2);
	assert_int_equal(srv.port, 0x1337);
	assert_int_equal(srv.name.length, 0);
}

static void
test_ptr_allows_compression_target_outside_rdata(void** state) {
	static const uint8_t data[] = {3, 'f', 'o', 'o', 0, 0xc0, 0};
	char name_buffer[32] = {0};
	mdns_string_t name;

	(void)state;
	name = mdns_record_parse_ptr(data, sizeof(data), 5, 2, name_buffer, sizeof(name_buffer));
	assert_int_equal(name.length, 4);
	assert_memory_equal(name.str, "foo.", 4);
}

int
main(void) {
	const struct CMUnitTest tests[] = {
	    cmocka_unit_test(test_parses_simple_a_response),
	    cmocka_unit_test(test_record_parsers_reject_wrapped_ranges),
	    cmocka_unit_test(test_record_names_stay_within_rdata),
	    cmocka_unit_test(test_srv_accepts_root_target),
	    cmocka_unit_test(test_ptr_allows_compression_target_outside_rdata),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
