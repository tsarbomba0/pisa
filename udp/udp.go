package udp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"pisa/addresses"
)

func Checksum(length []byte, src []byte, dest []byte) []byte {
	var sum uint32 = 0
	//count := 0

	buf := bytes.NewBuffer(src)
	buf.Write(dest)
	buf.Write([]byte{
		0, 17,
	})
	buf.Write(length)

	pseudoHeader := binary.BigEndian.Uint32(buf.Bytes())

	// i think this bad
	sum = pseudoHeader&0xFFFF + pseudoHeader>>16

	sumBytes := make([]byte, 2)
	fmt.Println("sum: ", sum)
	if sum == 0 {
		sumBytes = []byte{255, 255}
	} else {
		binary.BigEndian.PutUint16(sumBytes, uint16(sum))
	}
	return sumBytes
}

func Datagram(data []byte, udp *PacketUDP, addr *addresses.Addresses) []byte {
	// Calculating length
	dataLength := len(data) + 8
	if dataLength > 65535 {
		panic(errors.New("packet too large"))
	}
	len := make([]byte, 2)
	binary.BigEndian.PutUint16(len, uint16(dataLength))

	// Source and destination port to bytes
	src := make([]byte, 2)
	binary.BigEndian.PutUint16(src, udp.SrcPort)
	buffer := bytes.NewBuffer(src)

	dest := make([]byte, 2)
	binary.BigEndian.PutUint16(dest, udp.DestPort)
	buffer.Write(dest)

	buffer.Write(len)
	buffer.Write(Checksum(len, addr.Source, addr.Destination))
	buffer.Write(data)

	fmt.Println("Checksum: ", Checksum(len, addr.Source, addr.Destination))
	fmt.Println(buffer.Bytes())

	return buffer.Bytes()
}

type PacketUDP struct {
	SrcPort  uint16
	DestPort uint16
}
