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
	"strings"
)

// Struct representing options given to the DHCP server from the configuration file.
type DHCPOptions struct {
	Router     []string
	SubnetMask string
	DNS        []string
	TimeServer []string
	Interface  string
	Lease      uint
}

// Struct representing the DHCP server.
type DHCPServer struct {
	SrvConn *net.UDPConn
	Reader  *bufio.Reader
	Options *DHCPOptions
	Buffer  []byte

	// Clients mapped by MAC to Address -> will soon be actually used.
	Clients map[string]uint32

	// First address assignable
	RangeFirst uint32
	// Last address assignable
	RangeLast uint32

	// Current highest address -> will be probably removed.
	HighestAddr uint32

	// Local address represented as []byte
	LocalAddress []byte

	// Released addresses in []uint32
	ReleasedAddresses []uint32
	// Options actually set in the configuration.
	availableOptions []string

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
func (s *DHCPServer) generateAddress(mac string) []byte {
	address := make([]byte, 4)
	binary.BigEndian.PutUint32(address, s.HighestAddr)
	s.HighestAddr += 1
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
func StartServer(opt *DHCPOptions, rangeFirst uint32, rangeLast uint32, availableOptions []string) *DHCPServer {
	// Get local address
	device, err := net.InterfaceByName(opt.Interface)
	util.OnError(err)
	addrs, err := device.Addrs()
	util.OnError(err)
	address := strings.Split(addrs[0].String(), "/")

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
		Options:           opt,
		RangeFirst:        rangeFirst,
		RangeLast:         rangeLast,
		HighestAddr:       rangeFirst,
		availableOptions:  availableOptions,
		Clients:           make(map[string]uint32),
		LocalAddress:      addresses.ParseIP(address[0]),
		ReleasedAddresses: make([]uint32),
	}

	// Sets a ready byte array of options.
	Server.createOptions(opt)

	// Logging.
	log.Println("Started server on address:", address[0], "!")

	return Server
}

// Create a []byte of options ready to be appended to a packet.
//
// DNS, Time Server, Router options can be multiple addresses.
//
// I will include that later.
func (s *DHCPServer) createOptions(opt *DHCPOptions) {
	optBuffer := new(bytes.Buffer)
	optBuffer.Write(util.MagicCookie)
	for i := 0; i <= len(s.availableOptions)-1; i++ {
		fmt.Println(s.availableOptions[i])
		switch s.availableOptions[i] {

		case "router":
			optBuffer.Write([]byte{3, byte(len(opt.Router) * 4)})
			for i := 0; i <= len(opt.Router)-1; i++ {
				optBuffer.Write(util.AddressIntoBytearray(opt.Router[i]))
			}

		case "subnetmask":
			optBuffer.Write([]byte{1, 4})
			optBuffer.Write(util.AddressIntoBytearray(opt.SubnetMask))

		case "dns":
			optBuffer.Write([]byte{6, byte(len(opt.DNS) * 4)})
			for i := 0; i <= len(opt.DNS)-1; i++ {
				optBuffer.Write(util.AddressIntoBytearray(opt.DNS[i]))
			}

		case "timesvr":
			optBuffer.Write([]byte{4, byte(len(opt.TimeServer) * 4)})
			for i := 0; i <= len(opt.TimeServer)-1; i++ {
				optBuffer.Write(util.AddressIntoBytearray(opt.TimeServer[i]))
			}
		case "lease":
			// Option 51: Lease time
			optBuffer.Write([]byte{51, 4})
			valueInt := uint32(opt.Lease)

			leaseBytes := make([]byte, 4)
			binary.BigEndian.PutUint32(leaseBytes, uint32(valueInt))
			optBuffer.Write(leaseBytes)

			// T1 time
			optBuffer.Write([]byte{58, 4})
			binary.BigEndian.PutUint32(leaseBytes, uint32(valueInt/2))
			optBuffer.Write(leaseBytes)

			// T2 time
			optBuffer.Write([]byte{59, 4})
			binary.BigEndian.PutUint32(leaseBytes, uint32(valueInt*825/1000))
			optBuffer.Write(leaseBytes)
		}
	}

	// Padding with 0s
	//optBuffer.Write(make([]byte, 191-len(optBuffer.Bytes())))
	s.parsedOptions = optBuffer.Bytes()
}

// Sends a DHCP Offer.
//
// Returns a error.
func (s *DHCPServer) SendDHCPOffer(p *packet.Packet) error {
	offer := new(bytes.Buffer)

	// Generate a IP address from the ranges.
	if s.RangeFirst+1 > s.RangeLast {
		return fmt.Errorf("Address range exhausted!")
	}
	var ip []byte
	if s.Clients[p.StringMAC] == 0 {
		if len(s.ReleasedAddresses) > 0 {
			ip = s.ReleasedAddresses[0]
			s.ReleasedAddresses = s.ReleasedAddresses[1:]
		} else {
			ip = s.generateAddress(p.StringMAC)
			s.Clients[mac] = s.HighestAddr
		}
	} else {
		ip = util.Uint32Bytes(s.Clients[p.StringMAC])
	}

	// opcode, htype, hlen, hops
	offer.Write([]byte{
		2, 1, 6, 0,
	})

	// Transaction ID
	offer.Write(p.TransactionID)

	// Fields
	offer.Write([]byte{
		0, 0, // SECONDS
		0, 0, // FLAGS
		0, 0, 0, 0, // CLIENT IP
		ip[0], ip[1], ip[2], ip[3], // YOUR IP
		s.LocalAddress[0], s.LocalAddress[1], s.LocalAddress[2], s.LocalAddress[3], // SERVER IP
		0, 0, 0, 0, // GATEWAY IP
	})

	// Client's MAC Address
	offer.Write(p.ClientMAC)

	// server hostname not needed, will be added
	offer.Write(make([]byte, 64))
	// bootfile
	offer.Write(make([]byte, 138))

	// Append options
	offer.Write(s.parsedOptions)
	// Option 53: DHCP Message type and Option 255 End
	offer.Write([]byte{53, 1, 2, 255})
	// Send frame directory to the specified interface
	device, err := net.InterfaceByName(s.Options.Interface)
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

	return err
}

// Sends a DHCP Acknowledge.
//
// Returns a error.
func (s *DHCPServer) SendDHCPAck(packet *packet.Packet) error {
	// opcode, hardware type, hardware addres length and hops
	ack := bytes.NewBuffer([]byte{
		2, 1, 6, 0,
	})

	// transaction id
	ack.Write(packet.TransactionID)

	assignedAddr := s.Clients[packet.StringMAC]

	ack.Write([]byte{
		0, 0,
		0, 0,
		0, 0, 0, 0,
	})
	binary.Write(ack, binary.BigEndian, assignedAddr)
	ack.Write([]byte{
		s.LocalAddress[0], s.LocalAddress[1], s.LocalAddress[2], s.LocalAddress[3], // SERVER IP
		0, 0, 0, 0, // gateway ip
	})

	// Client MAC
	ack.Write(packet.ClientMAC)

	// Server hostname
	ack.Write(make([]byte, 64))
	// Bootfile
	ack.Write(make([]byte, 138))
	// Option 53: DHCP Message type and Option 255 End
	ack.Write(s.parsedOptions)
	ack.Write([]byte{53, 1, 5, 255})

	// Send frame directory to the specified interface
	device, err := net.InterfaceByName(s.Options.Interface)
	util.OnError(err)

	// Source Destination address pair
	address := addresses.Addresses{
		Source:      s.LocalAddress,
		Destination: util.Uint32Bytes(assignedAddr),
	}
	// Write to the socket.
	err = ethernet.SendEthernet(ack.Bytes(), &address, &udp.HeaderUDP{
		SrcPort:  67,
		DestPort: 68,
	}, *device, packet.ClientMAC)

	log.Println("DHCPACK to: ", packet.StringMAC)
	return err
}

func (s *DHCPserver) Release(p *packet.Packet) {
	s.Clients[p.StringMAC] = 0
	s.ReleasedAddresses = append(s.ReleasedAddresses, binary.BigEndian.Uint32(p.YourAddress))
}
