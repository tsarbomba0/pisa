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
	SrvConn *net.UDPConn
	Reader  *bufio.Reader
	Options map[string]string
	Buffer  []byte

	// Clients mapped by address -> will soon be actually used.
	Clients map[uint32]string

	// First address assignable
	RangeFirst uint32
	// Last address assignable
	RangeLast uint32

	// Current highest address -> will be probably removed.
	HighestAddr uint32

	// Options actually set in the configuration.
	availableOptions []string

	// Lease time.
	leaseTime uint

	// Parsed options in []byte.
	//
	// This lets the server need to calculate (most) of the options only once.
	//
	// Stuff like addresses is dynamic ofc.
	parsedOptions []byte
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

// Start server.
//
// Requires a map of options.
//
// first used address in uint32 form.
//
// last used address in uint32 form.
//
// available options as an slice of strings.
func StartServer(options map[string]string, rangeFirst uint32, rangeLast uint32, availableOptions []string, lease uint) *DHCPServer {
	// Connection
	s, err := net.ListenUDP("udp", &net.UDPAddr{
		Port: 67,
		IP:   net.ParseIP("0.0.0.0"),
	})

	util.OnError(err)

	reader := bufio.NewReader(s)

	// Buffer for data.
	buffer := make([]byte, 512)

	Server := &DHCPServer{
		// Related to the connection
		SrvConn: s,
		Reader:  reader,
		Buffer:  buffer,

		// Related to configuration
		Options:          options,
		Clients:          make(map[uint32]string),
		RangeFirst:       rangeFirst,
		RangeLast:        rangeLast,
		HighestAddr:      rangeFirst,
		availableOptions: availableOptions,
		leaseTime:        lease,
	}

	// Sets a ready byte array of options.
	Server.createOptions()

	// Logging.
	log.Println("Started server!")

	return Server
}

// Create a []byte of options ready to be appended to a packet.
//
// DNS, Time Server, Router options can be multiple addresses.
//
// I will include that later.
func (s *DHCPServer) createOptions() {
	optBuffer := new(bytes.Buffer)

	for i := 0; i < len(s.availableOptions)-1; i++ {
		value := s.Options[s.availableOptions[i]]
		switch s.availableOptions[i] {

		case "router":
			optBuffer.Write([]byte{3, byte(len(value) * 4)})
			for i := 0; i <= len(value); i++ {
				optBuffer.Write(util.AddressIntoBytearray(value))
			}

		case "subnetmask":
			optBuffer.Write([]byte{1, byte(len(value) * 4)})
			for i := 0; i <= len(value); i++ {
				optBuffer.Write(util.AddressIntoBytearray(value))
			}

		case "dns":
			optBuffer.Write([]byte{6, byte(len(value) * 4)})
			for i := 0; i <= len(value); i++ {
				optBuffer.Write(util.AddressIntoBytearray(value))
			}

		case "timesvr":
			optBuffer.Write([]byte{4, byte(len(value) * 4)})
			for i := 0; i <= len(value); i++ {
				optBuffer.Write(util.AddressIntoBytearray(value))
			}
		}

	}

	// Padding with 0s
	optBuffer.Write(make([]byte, len(optBuffer.Bytes())))

	s.parsedOptions = optBuffer.Bytes()
}

// Sends a DHCP Offer.
//
// Returns a error.
func (s *DHCPServer) SendDHCPOffer(p *packet.Packet, dev string) error {
	offer := new(bytes.Buffer)

	// Generate a IP address from the ranges
	ip := s.generateAddress()

	offer.Write([]byte{
		2, 1, 6, 0,
	})

	offer.Write(p.TransactionID)
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
//
// Returns a error.
func (s *DHCPServer) SendDHCPAck(packet *packet.Packet, dev string) error {
	// opcode, hardware type, hardware addres length and hops
	ack := bytes.NewBuffer([]byte{
		2, 1, 6, 0,
	})
	// transaction id
	ack.Write(packet.TransactionID)
	// secs and flags
	ack.Write([]byte{
		0, 0,
		0, 0,
	})

	ack.Write([]byte{
		0, 0, 0, 0, // client ip
		192, 168, 0, 1, // your ip
		0, 0, 0, 0, // next server ip
		0, 0, 0, 0, // gateway ip
	})

	// Client MAC
	ack.Write(packet.ClientMAC)

	// Server hostname
	ack.Write(make([]byte, 64))

	// Write Magic Cookie at the start
	ack.Write(util.MagicCookie)
	// Options
	ack.Write(s.parsedOptions)

	// Send frame directory to the specified interface
	device, err := net.InterfaceByName(dev)
	util.OnError(err)

	// Source Destination address pair
	address := addresses.Addresses{
		Source:      addresses.ParseIP("192.168.0.1"),
		Destination: addresses.ParseIP("192.168.0.2"),
	}
	// Write to the socket.
	err = ethernet.SendEthernet(ack.Bytes(), &address, &udp.HeaderUDP{
		SrcPort:  67,
		DestPort: 68,
	}, *device, packet.ClientMAC)

	return err
}
