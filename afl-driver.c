
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#define MAX_PACKET_SIZE 10000

unsigned char * g_buf;
int g_len;
int g_offset;

ssize_t fake_recvfrom(int sockfd, void *buf, size_t len, int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen)
{
    int remainder = g_len - g_offset;
    int tocopy = remainder > len ? len : remainder;

    if (tocopy) {
        memcpy(buf, &g_buf[g_offset], tocopy);
        g_offset += tocopy;
    }

    return tocopy;
}


#include "mdns.h"

#ifdef DISABLED__AFL_HAVE_MANUAL_CONTROL
    __AFL_FUZZ_INIT();
#endif

static char namebuffer[256];

static
int service_callback(int sock, const struct sockaddr* from, size_t addrlen, mdns_entry_type_t entry,
                 uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void* data,
                 size_t size, size_t name_offset, size_t name_length, size_t record_offset,
                 size_t record_length, void* user_data) {
    if (entry != MDNS_ENTRYTYPE_QUESTION)
		return 0;

    if (rtype == MDNS_RECORDTYPE_PTR) {
        mdns_record_parse_ptr(data, size, record_offset, record_length,
		                      namebuffer, sizeof(namebuffer));
    } else if (rtype == MDNS_RECORDTYPE_SRV) {
		mdns_record_parse_srv(data, size, record_offset, record_length,
		                      namebuffer, sizeof(namebuffer));
    }

    return 0;
}

void process_buffer()
{
    if (g_len > MAX_PACKET_SIZE || g_len < 2) return;

    memset(namebuffer, 0, sizeof(namebuffer));
    
    // first byte dictates which one we call
    int choice = g_buf[0] % 3;
    g_offset += 1;

    unsigned char udpbuf[MAX_PACKET_SIZE];

    switch (g_buf[0] % 3) {
    case 0:
        mdns_socket_listen(0, udpbuf, sizeof(udpbuf), service_callback, NULL);
        break;
    case 1:
        mdns_discovery_recv(0, udpbuf, sizeof(udpbuf), service_callback, NULL);
        break;
    case 2:
        mdns_query_recv(0, udpbuf, sizeof(udpbuf), service_callback, NULL, 0);
        break;
    }
}


int main(int argc, char** argv) {

    #ifdef DISABLED__AFL_HAVE_MANUAL_CONTROL
        __AFL_INIT();
    

        g_buf = __AFL_FUZZ_TESTCASE_BUF;
        while (__AFL_LOOP(1000)) {
            g_len = __AFL_FUZZ_TESTCASE_LEN;
            g_offset = 0;

            process_buffer();
        }
    
    #else

    if (argc != 2) {
        fprintf(stderr, "%s file\n", argv[0]);
        return 1;
    }

    unsigned char udpbuf[MAX_PACKET_SIZE];
    g_buf = udpbuf;
    
    FILE * fp = fopen(argv[1], "rb");
    g_len = fread(g_buf, 1, sizeof(udpbuf), fp);
    g_offset = 0;
    fclose(fp);

    process_buffer();

    #endif

}

