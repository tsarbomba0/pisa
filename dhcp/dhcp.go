package dhcp

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"pisa/addresses"
	"pisa/ethernet"
	"pisa/packet"
	"pisa/udp"
	"pisa/util"
)

// Struct representing the DHCP server.
type DHCPServer struct {
	SrvConn     *net.UDPConn
	Reader      *bufio.Reader
	Options     map[string]interface{}
	Buffer      []byte
	Clients     map[uint32]string
	RangeFirst  uint32
	RangeLast   uint32
	HighestAddr uint32
}

// Reads from the connection (Port 67).
func (s *DHCPServer) Read() ([]byte, error) {
	length, err := s.Reader.Read(s.Buffer)
	return s.Buffer[:length], err
}

// Generates an IP address.
func (s *DHCPServer) generateAddress() []byte {
	fmt.Println("Highest", s.HighestAddr)
	s.HighestAddr += 1
	temporary := s.HighestAddr
	address := make([]byte, 4)
	binary.BigEndian.PutUint32(address, temporary)

	return address
}

// Sends a DHCP Offer.
func (s *DHCPServer) SendDHCPOffer(p *packet.Packet, dev string) error {
	offer := new(bytes.Buffer)

	// Generate a IP address from the ranges
	ip := s.generateAddress()

	offer.Write([]byte{
		2, 1, 6, 0,
	})

	offer.Write(util.Uint32Bytes(p.TransactionID))
	fmt.Println("IP", ip)
	// Fields
	offer.Write([]byte{
		0, 0, // SECONDS
		0, 0, // FLAGS
		192, 168, 0, 2, // CLIENT IP
		192, 168, 0, 1, // YOUR IP
		0, 0, 0, 0, // NEXT SERVERIP
		0, 0, 0, 0, // GATEWAY IP
	})

	// Client's MAC Address
	offer.Write(p.ClientMAC)

	// server hostname not needed, will be added
	offer.Write(make([]byte, 64))
	// bootfile
	offer.Write(make([]byte, 128))

	// Write Magic Cookie at the start
	offer.Write(util.MagicCookie)
	// Append options rn not ready
	offer.Write(make([]byte, 192))

	// Send frame directory to the specified interface
	device, err := net.InterfaceByName(dev)
	util.OnError(err)

	// Source Destination address pair
	address := addresses.Addresses{
		Source:      addresses.ParseIP("192.168.0.1"),
		Destination: addresses.ParseIP("192.168.0.2"),
	}
	err = ethernet.SendEthernet(offer.Bytes(), &address, &udp.HeaderUDP{
		SrcPort:  67,
		DestPort: 68,
	}, *device, p.ClientMAC)

	// Log
	log.Println("Sent DHCPOffer to a client!")

	return err
}

// Sends a DHCP Acknowledge.
func (s *DHCPServer) SendDHCPAck() error {

	return nil
}
