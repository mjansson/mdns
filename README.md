# Public domain mDNS/DNS-SD library in C

This library provides a header only cross-platform mDNS and DNS-DS library in C. The latest source code is always available at

https://github.com/mjansson/mdns

This library is put in the public domain; you can redistribute it and/or modify it without any restrictions.

Created by Mattias Jansson ([@maniccoder](https://twitter.com/maniccoder))

## Features

The library does DNS-SD discovery and service as well as single record mDNS query and response.

## Test executable
The mdns.c file contains a test executable implementation using the library to do DNS-SD and mDNS queries.

### Microsoft compiler
`cl mdns.c /Zi /Fdmdns.pdb /link /out:mdns.exe ws2_32.lib iphlpapi.lib`
