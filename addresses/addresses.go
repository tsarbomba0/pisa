package addresses

import (
	"bytes"
	"errors"
	"pisa/util"
	"regexp"
	"strconv"
	"strings"
)

// Type to define Source and Destination address
type Addresses struct {
	Source      []byte
	Destination []byte
}

// Parse IP
func ParseIP(addr string) []byte {

	addressSlice := strings.Split(addr, ".")
	bad, _ := regexp.MatchString("[a-zA-z]", addr)

	if len(addressSlice) < 4 || bad {
		panic(errors.New("parsed incorrect address"))
	}

	buf := new(bytes.Buffer)

	for i := 0; i <= 3; i++ {
		n, err := strconv.Atoi(addressSlice[i])
		util.OnError(err)
		buf.WriteByte(byte(n))
	}

	return buf.Bytes()
}
