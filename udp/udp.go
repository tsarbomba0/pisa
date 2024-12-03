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
	len := make([]byte, 2)
	binary.BigEndian.PutUint16(len, uint16(dataLength))

	// Source port
	src := make([]byte, 2)
	binary.BigEndian.PutUint16(src, udp.SrcPort)
	buffer := bytes.NewBuffer(src)

	// Destination port
	dest := make([]byte, 2)
	binary.BigEndian.PutUint16(dest, udp.DestPort)
	buffer.Write(dest)

	// Write length
	buffer.Write(len)

	// 2 zero bytes as checksum
	buffer.Write([]byte{0, 0})

	// data
	buffer.Write(data)

	datagram := buffer.Bytes()

	// Checksum into bytearray
	copy(datagram[6:8], checksum(&pseudoHeader{
		srcAddr:  addr.Source,
		destAddr: addr.Destination,
		protocol: []byte{17},
		length:   len,
	}, datagram))

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
	for i := 0; i <= len(packet)-1; i += 2 {
		sum += uint32(packet[i]) << 8
		sum += uint32(packet[i+1])
	}

	if length%2 == 1 {
		sum += uint32(packet[length-1])
	}

	checksumBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(checksumBytes, ^uint16(sum&0xffff+sum>>16))
	return checksumBytes
}
