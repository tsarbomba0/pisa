package main

import (
	"bufio"
	"log"
	"net"
	"pisa/dhcp"
	"pisa/packet"
	"pisa/util"
)

func main() {
	s, err := net.ListenUDP("udp", &net.UDPAddr{
		Port: 67,
		IP:   net.ParseIP("0.0.0.0"),
	})
	util.OnError(err)
	defer s.Close()
	reader := bufio.NewReader(s)

	c, err := net.ListenUDP("udp", &net.UDPAddr{
		Port: 68,
		IP:   net.ParseIP("0.0.0.0"),
	})
	util.OnError(err)
	defer c.Close()
	writer := bufio.NewWriter(c)

	buffer := make([]byte, 512)

	Server := &dhcp.DHCPServer{
		SrvConn:    s,
		ClientConn: c,
		Reader:     reader,
		Writer:     writer,
		Buffer:     buffer,
		Clients:    make(map[string]map[string]string),
	}

	// Reading from UDP
	log.Println("Started server!")
	for {
		data, err := Server.Read()
		if len(data) > 0 {
			packet := packet.FromBytes(data)
			//fmt.Println(packet.ClientMAC)
			//fmt.Println(packet.StringMAC)
			//fmt.Println(packet.ServerAddress)

			if Server.Clients[packet.StringMAC] != nil {
				switch packet.DHCPAction {
				case 1:
					// send reply to discover (offer)
				case 2:
					// send reply to request (ack)
				}
			} else {
				Server.Clients[packet.StringMAC] = make(map[string]string)
			}
		}
		util.OnError(err)

	}

}
