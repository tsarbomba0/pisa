package udp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
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
	buffer.Write([]byte{0, 0})
	buffer.Write(data)

	datagram := buffer.Bytes()
	fmt.Println("Checksum: ", Checksum(&pseudoHeader{
		srcAddr:  addr.Source,
		destAddr: addr.Destination,
		protocol: []byte{17},
		length:   len,
	}, datagram))

	// Return
	return buffer.Bytes()
}

func Checksum(head *pseudoHeader, data []byte) []byte {
	// sum variable
	var sum uint16 = 0
	var n uint16
	// Pseudo IP header
	buf := bytes.NewBuffer(head.srcAddr)
	buf.Write(head.destAddr)
	buf.Write(head.zeroes)
	buf.WriteByte(0)
	buf.WriteByte(17)
	buf.Write(head.length)

	// UDP Datagram
	buf.Write(data)

	// Get buffer
	packet := buf.Bytes()

	for i := 0; i < len(packet); i += 2 {
		n = binary.BigEndian.Uint16(packet[i : i+2])
		sum += n&0xFFFF + n>>16
	}
	return nil
}
