package util

import (
	"encoding/binary"
	"regexp"
	"strconv"
	"strings"
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

// Function to test a address
func CheckAddress(addr string) bool {
	m, _ := regexp.MatchString(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`, addr)
	return m
}

// Converts a address string into a uint32.
func AddressIntoUint32(addr string) uint32 {
	octets := strings.Split(addr, ".")

	var result int = 0
	for i := 0; i <= 3; i++ {
		v, _ := strconv.Atoi(octets[i])
		result += v
	}
	return uint32(result)
}

// Converts a address string into a byte array.
func AddressIntoBytearray(addr string) []byte {
	octets := strings.Split(addr, ".")
	b := make([]byte, 4)
	for i := 0; i <= 3; i++ {
		n, _ := strconv.ParseUint(octets[i], 10, 8)
		b[i] = byte(n)
	}
	return b
}
