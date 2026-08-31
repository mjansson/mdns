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
test_query_send_rejects_empty_name_without_touching_buffer(void** state) {
	uint8_t buffer[128];
	uint8_t expected[sizeof(buffer)];

	(void)state;
	memset(buffer, 0xa5, sizeof(buffer));
	memcpy(expected, buffer, sizeof(buffer));
	assert_int_equal(mdns_query_send(-1, MDNS_RECORDTYPE_PTR, "", 0, buffer, sizeof(buffer), 1),
	                 -1);
	assert_memory_equal(buffer, expected, sizeof(buffer));
}

int
main(void) {
	const struct CMUnitTest tests[] = {
	    cmocka_unit_test(test_parses_simple_a_response),
	    cmocka_unit_test(test_query_send_rejects_empty_name_without_touching_buffer),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
