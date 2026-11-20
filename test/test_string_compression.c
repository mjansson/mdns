// Tests for name compression in mdns_string_make(): names written into one buffer with a shared
// string table must decode back to themselves, and shared suffixes must still be compressed.

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "mdns.h"

static uint8_t buffer[512];
static mdns_string_table_t table;
static size_t write_pos;
static int failures;

// Strict decoder: a compression pointer must point to a prior occurrence of a name (RFC 1035
// 4.1.4), i.e. before the start of the labels it was reached from, which also rules out loops.
// Returns 0 on success with the dotted name (with trailing dot) in out, -1 for a pointer that is
// not to a prior occurrence, -2 for other bad data.
static int
decode_name(size_t pos, char* out, size_t capacity) {
	size_t used = 0;
	size_t limit = pos;
	out[0] = 0;
	while (pos < sizeof(buffer)) {
		uint8_t length = buffer[pos];
		if (!length)
			return 0;
		if ((length & 0xC0) == 0xC0) {
			if (pos + 1 >= sizeof(buffer))
				return -2;
			size_t target = ((size_t)(length & 0x3F) << 8) | buffer[pos + 1];
			if (target >= limit)
				return -1;
			pos = limit = target;
			continue;
		}
		if ((pos + 1 + length > sizeof(buffer)) || (used + length + 2 > capacity))
			return -2;
		memcpy(out + used, buffer + pos + 1, length);
		used += length;
		out[used++] = '.';
		out[used] = 0;
		pos += 1 + length;
	}
	return -1;
}

static void
reset(void) {
	memset(buffer, 0, sizeof(buffer));
	memset(&table, 0, sizeof(table));
	write_pos = 12;  // after the DNS header
}

// Writes name at the current position, checks it decodes to itself and, if expected_size is
// non-zero, that it was encoded in exactly that many bytes.
static void
check_name(const char* name, size_t expected_size) {
	void* start = buffer + write_pos;
	void* end = mdns_string_make(buffer, sizeof(buffer), start, name, strlen(name), &table);
	if (!end) {
		printf("FAIL %s: mdns_string_make failed\n", name);
		++failures;
		return;
	}
	size_t size = (size_t)((uint8_t*)end - (uint8_t*)start);
	char decoded[256];
	int result = decode_name(write_pos, decoded, sizeof(decoded));
	if (result == -1) {
		printf("FAIL %s: compression pointer is not to a prior name (loop)\n", name);
		++failures;
	} else if (result) {
		printf("FAIL %s: does not decode\n", name);
		++failures;
	} else if (strcmp(decoded, name)) {
		printf("FAIL %s: decodes as %s\n", name, decoded);
		++failures;
	} else if (expected_size && (size != expected_size)) {
		printf("FAIL %s: encoded in %u bytes, expected %u\n", name, (unsigned)size,
		       (unsigned)expected_size);
		++failures;
	} else {
		printf("ok   %s (%u bytes)\n", name, (unsigned)size);
	}
	write_pos += size;
}

int
main(void) {
	// A repeated label must not be compressed into a reference to the name being written
	reset();
	check_name("a.b.b.", 7);
	reset();
	check_name("host.local.local.", 18);

	// A suffix must not reference a stored name that only starts with the same labels
	reset();
	check_name("local.foo.", 11);
	check_name("x.local.", 9);

	// Shared suffixes are still compressed
	reset();
	check_name("_service._udp.local.", 21);
	check_name("instance._service._udp.local.", 11);  // label + reference
	check_name("host.local.", 7);                     // label + reference to "local"
	check_name("other.local.", 8);
	check_name("x.host.local.", 4);  // reference to a name that itself ends in a reference

	// Names with more labels than the string table holds still share their last labels
	reset();
	check_name("l1.l2.l3.l4.l5.l6.l7.l8.l9.l10.l11.l12.l13.l14.l15.l16.l17.l18.local.", 0);
	check_name("x.local.", 4);
	check_name("x.l18.local.", 4);

	if (failures)
		printf("%d failure(s)\n", failures);
	return failures ? 1 : 0;
}
