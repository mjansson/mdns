// Reject a near-SIZE_MAX offset instead of wrapping past the bounds check.

#define MDNS_IMPLEMENTATION
#include "mdns.h"

#include <stdint.h>

int main(void) {
	uint8_t buffer[16] = {0};
	char strbuffer[16] = {0};
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
	mdns_record_txt_t txtrec[1];

	mdns_string_t ptr =
	    mdns_record_parse_ptr(buffer, sizeof(buffer), (size_t)0 - 2, 2, strbuffer, sizeof(strbuffer));
	mdns_record_srv_t srv =
	    mdns_record_parse_srv(buffer, sizeof(buffer), (size_t)0 - 8, 8, strbuffer, sizeof(strbuffer));
	struct sockaddr_in* a =
	    mdns_record_parse_a(buffer, sizeof(buffer), (size_t)0 - 4, 4, &addr4);
	struct sockaddr_in6* aaaa =
	    mdns_record_parse_aaaa(buffer, sizeof(buffer), (size_t)0 - 16, 16, &addr6);
	size_t txt =
	    mdns_record_parse_txt(buffer, sizeof(buffer), (size_t)0 - 4, 4, txtrec, 1);

	if (ptr.length || srv.port || a->sin_addr.s_addr || aaaa->sin6_addr.s6_addr[0] || txt)
		return 1;
	return 0;
}
