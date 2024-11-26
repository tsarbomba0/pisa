package dhcp

import (
	"bufio"
	"bytes"
	"log"

	//"encoding/binary"
	"net"
	"pisa/addresses"
	"pisa/ethernet"
	"pisa/packet"
	"pisa/udp"
	"pisa/util"
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

func (s *DHCPServer) SendDHCPOffer(p *packet.Packet) error {
	offer := new(bytes.Buffer)

	offer.Write([]byte{
		2, 1, 6, 0,
	})

	offer.Write(util.Uint32Bytes(p.TransactionID))

	offer.Write([]byte{
		0, 0, // FLAGS
		0, 0, 0, 0, // CLIENT IP
		192, 168, 0, 2, // ASSIGNED IP
		192, 168, 0, 1, // SERVER IP
		0, 0, 0, 0, // GATEWAY IP
	})

	offer.Write(p.ClientMAC)

	offer.Write(make([]byte, 64))  // server hostname not needed, will be added
	offer.Write(make([]byte, 128)) // file

	offer.Write(util.MagicCookie)

	device, err := net.InterfaceByName("enp0s8")
	util.OnError(err)

	address := addresses.Addresses{
		Source:      addresses.ParseIP("192.168.0.1"),
		Destination: addresses.ParseIP("192.168.0.2"),
	}
	err = ethernet.SendEthernet(offer.Bytes(), &address, &udp.PacketUDP{
		SrcPort:  67,
		DestPort: 68,
	}, *device, p.ClientMAC)

	log.Println("Sent DHCPOffer to a client!")

	return err
}

func (s *DHCPServer) SendDHCPAck() error {

	return nil
}
