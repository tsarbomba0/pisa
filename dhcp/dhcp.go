package dhcp

import (
	"bufio"
	"net"
)

// Struct representing the DHCP server
type DHCPServer struct {
	SrvConn    *net.UDPConn
	ClientConn *net.UDPConn
	Reader     *bufio.Reader
	Writer     *bufio.Writer
	Buffer     []byte
	Clients    map[string]map[string]string
}

// Reads from the connection (Port 67)
func (s *DHCPServer) Read() ([]byte, error) {
	length, err := s.Reader.Read(s.Buffer)
	return s.Buffer[:length], err
}

// Sends to the connection (Port 68)
func (s *DHCPServer) Write(data []byte) error {
	_, err := s.Writer.Write(data)
	return err
}

func (s *DHCPServer) SendResponse() error {
	return nil
}
