package ipv4

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"pisa/util"
)

// Struct for an IP Header (No options)
type IPv4Header struct {
	HeaderLen       byte
	TotalLength     uint16
	Identification  uint16
	Flags           byte
	FragOffset      uint16
	TTL             byte
	Protocol        byte
	Checksum        uint16
	SourceAddr      []byte
	DestinationAddr []byte
}

// Function to create packets "fast"
//
// Ignores stuff like identification, flags, fragmanting, diffserv or ecn.
func CreateFastPacket(h *IPv4Header, data []byte) []byte {
	packetBuf := bytes.NewBuffer([]byte{
		69, // Version + IHL
		0,  // DiffServ + ECN
	})

	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(data)+24))

	packetBuf.Write(length)
	packetBuf.Write([]byte{
		0, 0, // identification
		0, 0, // flags and fragment offset
		h.TTL,
		h.Protocol,
		0, 0,
	})

	// addresses
	packetBuf.Write(h.SourceAddr)
	packetBuf.Write(h.DestinationAddr)

	// Checksum
	b := packetBuf.Bytes()

	checksumBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(checksumBytes, checksum(b))

	copy(b[10:12], checksumBytes)

	err := verifyChecksum(b)
	util.NonFatalError(err)

	return append(b, data...)
}

// Creates a Internet Checksum.
func checksum(header []byte) uint16 {
	var length int = len(header)
	var sum uint32
	for i := 0; i <= length-1; i += 2 {
		sum += uint32(header[i]) << 8
		sum += uint32(header[i+1])
	}
	return ^uint16(sum&0xffff + sum>>16)
}

// Verifies a checksum.
func verifyChecksum(header []byte) error {
	var length int = len(header)
	var sum uint32

	for i := 0; i <= length-1; i += 2 {
		sum += uint32(header[i]) << 8
		sum += uint32(header[i+1])
	}
	if length%2 == 1 {
		sum += uint32(header[length-1]) << 8
	}

	result := uint16(sum>>16 + sum&0xFFFF)
	if result == 0xFFFF {
		return nil
	} else {
		return fmt.Errorf("wrong checksum: %d", ^result)
	}
}
