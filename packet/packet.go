package packet

import (
	"encoding/binary"
	"encoding/hex"
)

// Represents a DHCP Packet
type Packet struct {
	Opcode                uint8
	HardwareAddressType   uint8
	HardwareAddressLength uint8
	Hops                  uint8

	TransactionID uint32
	ElapsedSince  uint16
	Flags         uint16

	ClientAddress   uint32
	ServerAddress   uint32
	AssignedAddress uint32
	GatewayAddress  uint32

	ClientMAC []byte
	Hostname  []byte
	File      []byte
	Options   []byte

	StringMAC  string
	DHCPAction uint8
	Payload    []byte
}

func FromBytes(data []byte) *Packet {
	options := data[232:]
	var action uint8
	for i := 0; i <= len(options)-1; i++ {
		if options[i] == byte(53) {
			action = uint8(options[i+2])
			break
		}
	}

	return &Packet{
		Opcode:                uint8(data[0]),
		HardwareAddressType:   uint8(data[1]),
		HardwareAddressLength: uint8(data[2]),
		Hops:                  uint8(data[3]),

		TransactionID: binary.LittleEndian.Uint32(data[4:8]),
		ElapsedSince:  binary.LittleEndian.Uint16(data[8:10]),
		Flags:         binary.LittleEndian.Uint16(data[10:12]),

		ClientAddress:   binary.LittleEndian.Uint32(data[12:16]),
		ServerAddress:   binary.LittleEndian.Uint32(data[16:20]),
		AssignedAddress: binary.LittleEndian.Uint32(data[20:24]),
		GatewayAddress:  binary.LittleEndian.Uint32(data[24:28]),

		ClientMAC: data[28 : 28+uint8(data[2])], // max is 12 so 28:40
		Hostname:  data[40:104],
		File:      data[104:232],
		Options:   data[232:],

		StringMAC:  hex.EncodeToString(data[28 : 28+uint8(data[2])]),
		DHCPAction: action,
		Payload:    data,
	}
}
