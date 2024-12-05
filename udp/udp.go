package udp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"pisa/addresses"
)

type HeaderUDP struct {
	SrcPort  uint16
	DestPort uint16
}

type pseudoHeader struct {
	srcAddr  []byte
	destAddr []byte
	zeroes   []byte
	protocol []byte
	length   []byte
}

func Datagram(data []byte, udp *HeaderUDP, addr *addresses.Addresses) []byte {
	// Calculating length
	dataLength := len(data) + 8
	if dataLength > 65535 {
		panic(errors.New("packet too large"))
	}

	// Length
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(dataLength))

	// Source port
	src := make([]byte, 2)
	binary.BigEndian.PutUint16(src, udp.SrcPort)

	// Destination port
	dest := make([]byte, 2)
	binary.BigEndian.PutUint16(dest, udp.DestPort)

	var header []byte = []byte{
		src[0], src[1],
		dest[0], dest[1],
		length[0], length[1],
		0, 0,
	}

	// datagram
	datagram := append(header, data...)

	// Checksum into bytearray
	//copy(datagram[6:8], checksum(&pseudoHeader{
	//	srcAddr:  addr.Source,
	//	destAddr: addr.Destination,
	//	protocol: []byte{17},
	//	length:   length,
	//}, datagram))

	// Return
	return datagram
}

// This creates a UDP Checksum.
func checksum(head *pseudoHeader, data []byte) []byte {

	// Pseudo IP header
	buf := bytes.NewBuffer(head.srcAddr)
	buf.Write(head.destAddr)
	buf.Write(head.zeroes)
	buf.WriteByte(0)
	buf.WriteByte(17)
	buf.Write(head.length)

	// UDP Datagram
	buf.Write(data)

	// Get buffer and length
	packet := buf.Bytes()
	length := len(packet)
	var sum uint32
	for i := 0; i <= length-1; i += 2 {
		sum += uint32(packet[i]) << 8
		sum += uint32(packet[i+1])
	}

	if length == 1 {
		sum += uint32(packet[length-1])
	}

	checksumBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(checksumBytes, ^uint16(sum&0xffff+sum>>16))
	return checksumBytes
}
