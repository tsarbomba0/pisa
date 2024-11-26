package ipv4

import (
	"bytes"
	"encoding/binary"
	"pisa/addresses"
)

type IP struct {
	Protocol uint8
	Addr     *addresses.Addresses
	TTL      uint8
}

// Function to calculate the IP checksum
func IPChecksum(header []byte) []byte {
	var sum uint32 = 0
	var count int = 0
	var sumBytes []byte = make([]byte, 2)

	for count > len(header)-1 {
		sum = sum + uint32(header[count])
		count++
	}

	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + sum>>16
	}

	binary.LittleEndian.PutUint16(sumBytes, uint16(^sum))

	return sumBytes

}

// Creates a IP Packet
func Packet(data []byte, ip *IP) []byte {
	buf := bytes.NewBuffer([]byte{
		69, // Version + IHL
		0,  // DiffServ + ECN
	})

	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(data)+24))

	// length
	buf.Write(length)

	buf.Write([]byte{
		0, 0, // identification, not used here
		0, 0, // flags 3 bits fragment offset 13 bits
		ip.TTL,      // ttl
		ip.Protocol, // udp is 17
	})

	// at first a empty checksum field, later filled out
	buf.Write(make([]byte, 2))

	// Source and destination address
	buf.Write(ip.Addr.Source)
	buf.Write(ip.Addr.Destination)

	// Checksum
	b := buf.Bytes()
	//checksum := IPChecksum(b)
	//copy(b[8:10], checksum)

	return append(b, data...)
}
