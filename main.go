package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"pisa/dhcp"
	"pisa/packet"
	"pisa/util"
	"strings"
)

func main() {
	var config map[string]string = make(map[string]string)

	// Load config
	configFile, err := os.Open("config.txt")
	util.OnError(err)

	scanner := bufio.NewScanner(configFile)
	for {
		entry := strings.Split(scanner.Text(), "=")
		if len(entry) > 1 {
			config[entry[0]] = entry[1]
		} else {
			break
		}
	}

	log.Println("Loaded the configuration!")

	s, err := net.ListenUDP("udp", &net.UDPAddr{
		Port: 67,
		IP:   net.ParseIP("0.0.0.0"),
	})
	util.OnError(err)
	defer s.Close()
	reader := bufio.NewReader(s)

	buffer := make([]byte, 512)

	Server := &dhcp.DHCPServer{
		SrvConn: s,
		Reader:  reader,
		Buffer:  buffer,
		Clients: make(map[string]map[string]string),
	}

	// Reading from UDP
	log.Println("Started server!")
	for {
		data, err := Server.Read()
		if len(data) > 0 {
			packet := packet.FromBytes(data)
			//fmt.Println(packet.ClientMAC)
			//fmt.Println(packet.StringMAC)
			fmt.Println(packet.Options)

			if Server.Clients[packet.StringMAC] != nil {
				switch packet.DHCPAction {
				case 1:
					err := Server.SendDHCPOffer(packet)
					if err != nil {
						log.Println(err)
					}
				case 2:
					fmt.Println("DHCP REQUEST!")
				}
			} else {
				Server.Clients[packet.StringMAC] = make(map[string]string)
			}
		}
		util.OnError(err)

	}

}
