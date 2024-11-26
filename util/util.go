package util

import (
	"encoding/binary"
)

var MagicCookie []byte = []byte{99, 130, 83, 99}

// Error handling
func OnError(err error) {
	if err != nil {
		panic(err)
	}
}

// uint32 -> bytes
func Uint32Bytes(u uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, u)
	return b

}

// uint16 -> bytes
func Uint16Bytes(u uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, u)
	return b

}
