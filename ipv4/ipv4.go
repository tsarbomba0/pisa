package ipv4

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"pisa/addresses"
)

// Struct representing a part of the IP header
type IP struct {
	Protocol uint8
	Addr     *addresses.Addresses
	TTL      uint8
}

// Function to calculate the IP checksum
//
// Takes a []byte as input, returns a []byte
func IPChecksum(header []byte, src []byte, dest []byte) []byte {
	var sum uint32 = 0
	var sumBytes []byte = make([]byte, 2)
	length := len(header)

	// add all 16-bit words of the header to a sum as uint32
	for i := 0; i <= length-1; i += 2 {
		sum += uint32(header[i] + header[i+1])
		fmt.Println(sum)
	}

	// the sum is shortened to 16 bits and the overflow is added to the end
	for sum > 0xffff {
		sum = (sum & 0xffff) + sum>>16
	}

	fmt.Println("CHECK", sum)
	// Turns it into a byte array
	binary.BigEndian.PutUint16(sumBytes, uint16(^sum))
	fmt.Println(sumBytes)
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

	// checksum
	buf.Write([]byte{0, 0})

	// Source and destination address
	buf.Write(ip.Addr.Source)
	buf.Write(ip.Addr.Destination)

	// Checksum
	b := buf.Bytes()
	checksum := IPChecksum(b, ip.Addr.Source, ip.Addr.Destination)
	copy(b[10:12], checksum)

	return append(buf.Bytes(), data...)
}
