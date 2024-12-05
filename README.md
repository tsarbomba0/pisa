# Pisa
A **very** minimalistic DHCP Server written in GO.

## Features
1. Basic handling of most crucial DHCP messages.
- **DHCPDISCOVER** - Will respond to client broadcasts and send a Offer.
- **DHCPOFFER** - Will send an offer with options and a IP address.
- **DHCPREQUEST** - Will respond to a request.
- **DHCPACK** - Will send an ACK to the client to confirm the lease.

2. A simple configuration file
The configuration file (**config.txt**) follows a very simple format:
**key**=**value**

Examples:
- `interface=eno1`
- `addresses=10.0.0.2-10.0.0.5` 

3. Generation of IP addresses
The server will create addresses starting from the first address specified in the range to the last one.
If the pool is exhausted, the server won't send any DHCP offers.

4. Logging
My thing utilizes Go's standard log package for stuff like: 
- Client requests
- Messages sent to clients
- Errors
- More!

## Plans
- Maybe IPv6.
- More message types.
- Maybe a different way of generating addresses.

