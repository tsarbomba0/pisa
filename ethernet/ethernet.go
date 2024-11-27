package ethernet

import (
	"bytes"
	"hash/crc32"
	"net"
	"pisa/addresses"
	"pisa/ipv4"
	"pisa/udp"
	"syscall"
)

func SendEthernet(payload []byte, addr *addresses.Addresses, udpinfo *udp.HeaderUDP, device net.Interface, targetMAC []byte) error {
	// Applying the headers
	udpPacket := udp.Datagram(payload, udpinfo, addr)
	ipPacket := ipv4.Packet(udpPacket, &ipv4.IP{
		Protocol: 17,
		Addr:     addr,
		TTL:      128,
	})

	// Destination and Source MAC
	ethernetPacket := bytes.NewBuffer(targetMAC)
	ethernetPacket.Write(device.HardwareAddr)

	// EtherType, here: IPv4
	ethernetPacket.Write([]byte{
		8, 0,
	})

	// Data with ip and udp header
	ethernetPacket.Write(ipPacket)

	// Checksum
	h := crc32.NewIEEE()
	h.Write(ethernetPacket.Bytes())
	ethernetPacket.Write(crc32.NewIEEE().Sum(nil))

	// Set up socket
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, 0)
	if err != nil {
		syscall.Close(fd)
		return (err)
	}

	// Bind to device
	err = syscall.BindToDevice(fd, device.Name)
	if err != nil {
		syscall.Close(fd)
		return (err)
	}
	// Defer closing
	defer syscall.Close(fd)

	// Ethernet address
	hardwareAddress := make([]byte, 8)
	copy(hardwareAddress, targetMAC)
	ethernetAddress := syscall.SockaddrLinklayer{
		Protocol: 0,
		Ifindex:  device.Index,
		Halen:    6,
		Addr:     [8]byte(hardwareAddress),
	}

	// Send data to target
	err = syscall.Sendto(fd, ethernetPacket.Bytes(), 0, &ethernetAddress)
	if err != nil {
		syscall.Close(fd)
		return (err)
	}

	return err

}
