# Public domain mDNS/DNS-SD library in C

This library provides a header only cross-platform mDNS and DNS-DS library in C. The latest source code is always available at

https://github.com/mjansson/mdns

This library is put in the public domain; you can redistribute it and/or modify it without any restrictions.

Created by Mattias Jansson ([@maniccoder](https://twitter.com/maniccoder))

## Features

The library does DNS-SD discovery and service as well as one-shot single record mDNS query and response. There are no memory allocations done by the library, all buffers used must be passed in by the caller. Custom data for use in processing can be passed along using a user data opaque pointer.

## Usage

The `mdns.c` test executable file demonstrates the use of all features, including discovery, query and service response.

### Sockets

Socket for mDNS communication can either be opened by the library by using `mdns_socket_open_ipv4` or `mdns_socket_open_ipv6`, or by initializing an existing socket with `mdns_socket_setup_ipv4` or `mdns_socket_setup_ipv6`. The socket open/setup functions will initialize the socket with multicast membership (including loopback) and set to non-blocking mode.

Call `mdns_socket_close` to close a socket opened with `mdns_socket_open_ipv4` or `mdns_socket_open_ipv6`.

#### Port

To open/setup the socket for one-shot queries you can pass a null pointer socket address, or set the port in the passed socket address to 0. This will bind the socket to a random ephemeral local UDP port as required by the RFCs for one-shot queries.

To open/setup the socket for service, responding to incoming queries, you need pass in a socket address structure with the port set to 5353 (defined by MDNS_PORT in the header).

#### Network interface

To do discovery or queries on the default network interface, you can pass a null pointer as socket address in the socket create/setup functions. This will bind the socket to the default network interface. Otherwise you should enumerate the available interfaces and pass the appropriate socket address to the create/setup function. See the example program in `mdns.c` for an example implementation of doing this for both IPv4 and IPv6.

If you want to do mDNS service response to incoming queries, you do not need to enumerate interfaces to do service response on all interfaces as sockets receive data from all interfaces. See the example program in `mdns.c` for an example of setting up a service socket for both IPv4 and IPv6.

### Discovery

To send a DNS-SD service discovery request use `mdns_discovery_send`. This will send a single multicast packet (single PTR question record for `_services._dns-sd._udp.local.`) requesting a unicast response.

To read discovery responses use `mdns_discovery_recv`. All records received since last call will be piped to the callback supplied in the function call. The entry type will be one of `MDNS_ENTRYTYPE_ANSWER`, `MDNS_ENTRYTYPE_AUTHORITY` and `MDNS_ENTRYTYPE_ADDITIONAL`.

### Query

To send a one-shot mDNS query for a single record use `mdns_query_send`. This will send a single multicast packet for the given record (single PTR question record, for example `_http._tcp.local.`). You can optionally pass in a query ID for the query for later filtering of responses (even though this is discouraged by the RFC), or pass 0 to be fully compliant. The function returns the query ID associated with this query, which if non-zero can be used to filter responses in `mdns_query_recv`. If the socket is bound to port 5353 a multicast response is requested, otherwise a unicast response.

To read query responses use `mdns_query_recv`. All records received since last call will be piped to the callback supplied in the function call. If `query_id` parameter is non-zero the function will filter out any response with a query ID that does not match the given query ID. The entry type will be one of `MDNS_ENTRYTYPE_ANSWER`, `MDNS_ENTRYTYPE_AUTHORITY` and `MDNS_ENTRYTYPE_ADDITIONAL`.

### Service

To listen for incoming DNS-SD requests and mDNS queries the socket can be opened/setup on the default interface by passing 0 as socket address in the call to the socket open/setup functions (the socket will receive data from all network interfaces). Then call `mdns_socket_listen` either on notification of incoming data, or by setting blocking mode and calling `mdns_socket_listen` to block until data is available and parsed.

The entry type passed to the callback will be `MDNS_ENTRYTYPE_QUESTION` and record type `MDNS_RECORDTYPE_PTR`. Use the `mdns_record_parse_ptr` function to get the name string of the service record that was asked for.

If service record name is `_services._dns-sd._udp.local.` you should use `mdns_discovery_answer` to send the records of the services you provide (DNS-SD).

If the service record name is a service you provide, use `mdns_query_answer` to send the service details back in response to the query.

See the test executable implementation for more details on how to handle the parameters to the given functions.

## Test executable
The `mdns.c` file contains a test executable implementation using the library to do DNS-SD and mDNS queries. Compile into an executable and run to see command line options for discovery, query and service modes.

### Windows

#### Microsoft compiler
`cl mdns.c /Zi /Fdmdns.pdb /link /out:mdns.exe ws2_32.lib iphlpapi.lib`

### Linux

#### GCC
`gcc -o mdns mdns.c`

#### clang
`clang -o mdns mdns.c`

## Using with cmake or conan

* use cmake with `FetchContent` or install and `find_package`
* use conan with dependency name `mdns/20200130`, and `find_package` -> https://conan.io/center/mdns/20200130
