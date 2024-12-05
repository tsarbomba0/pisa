package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"pisa/dhcp"
	"pisa/packet"
	"pisa/util"
	"regexp"
	"strconv"
	"strings"
)

func main() {
	var rangeFirst uint32
	var rangeLast uint32
	var availableOptions []string

	var dhcpOptions dhcp.DHCPOptions

	addressRegex := regexp.MustCompile(`\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}-\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}`)
	//rangeRegex := regexp.MustCompile(`.-.`)

	// Load config
	configFile, err := os.Open("config.txt")
	util.OnError(err)

	scanner := bufio.NewScanner(configFile)
	for scanner.Scan() {
		line := scanner.Text()
		entry := strings.Split(line, "=")
		if len(entry) > 1 {
			switch entry[0] {
			case "addresses":
				m := addressRegex.MatchString(entry[1])
				if !m {
					panic(fmt.Errorf("invalid address entry: " + line))
				}

				// Split the string into highest and lowest address
				addrs := strings.Split(entry[1], "-")
				rangeFirst = util.AddressIntoUint32(addrs[0])
				rangeLast = util.AddressIntoUint32(addrs[1])

			// interface
			case "interface":
				availableOptions = append(availableOptions, entry[0])
				dhcpOptions.Interface = entry[1]

			// Router
			case "router":
				addressSlice := strings.Split(entry[1], ",")
				if len(addressSlice) > 1 {
					for i := 0; i <= len(addressSlice); i++ {
						if !util.CheckAddress(addressSlice[i]) {
							log.Panic("Invalid address entry: " + addressSlice[i])
						}
					}
				}
				dhcpOptions.Router = addressSlice
				availableOptions = append(availableOptions, entry[0])

			// Subnet Mask
			case "subnetmask":
				addressSlice := strings.Split(entry[1], ",")
				if len(addressSlice) > 1 {
					for i := 0; i <= len(addressSlice); i++ {
						if !util.CheckAddress(addressSlice[i]) {
							log.Panic("Invalid address entry: " + addressSlice[i])
						}
					}
				}
				dhcpOptions.SubnetMask = entry[1]
				availableOptions = append(availableOptions, entry[0])

			// Time server
			case "timesvr":
				addressSlice := strings.Split(entry[1], ",")
				if len(addressSlice) > 1 {
					for i := 0; i <= len(addressSlice); i++ {
						if !util.CheckAddress(addressSlice[i]) {
							log.Panic("Invalid address entry: " + addressSlice[i])
						}
					}
				}
				dhcpOptions.TimeServer = addressSlice
				availableOptions = append(availableOptions, entry[0])

			// Domain Name server
			case "dns":
				addressSlice := strings.Split(entry[1], ",")
				if len(addressSlice) > 1 {
					for i := 0; i <= len(addressSlice); i++ {
						if !util.CheckAddress(addressSlice[i]) {
							log.Panic("Invalid address entry: " + addressSlice[i])
						}
					}
				}
				dhcpOptions.DNS = addressSlice
				availableOptions = append(availableOptions, entry[0])

			// Lease time
			case "lease":
				time, err := strconv.ParseUint(entry[1], 10, 0)
				util.OnError(err)
				dhcpOptions.Lease = uint(time)
				availableOptions = append(availableOptions, entry[0])
			default:
				// Panics if a setting is unknown.
				panic(fmt.Errorf("unknown setting: " + line))
			}

		} else {
			// Panics if a configuration entry isn't in the format of:
			// key=value
			panic(fmt.Errorf("invalid configuration entry: " + line))
		}
	}
	// Panics if no interface was provided
	if dhcpOptions.Interface == "" {
		panic(fmt.Errorf("no interface provided"))
	}

	// If all went well, logs that the configuration was accepted.
	log.Println("Loaded the configuration!")

	// Starts the server.
	Server := dhcp.StartServer(&dhcpOptions, rangeFirst, rangeLast, availableOptions)
	defer Server.SrvConn.Close()

	// Reading from UDP.
	for {
		data, err := Server.Read()
		if len(data) > 0 {
			packet := packet.FromBytes(data)
			fmt.Println(packet.DHCPAction)
			// Client sends DHCP discover
			switch packet.DHCPAction {
			case 1:
				log.Println("Received DHCPDISCOVER from ", packet.StringMAC, ".Sending DHCPOFFER")
				err := Server.SendDHCPOffer(packet)
				util.NonFatalError(err)
			// Client sends DHCP request
			case 3:
				log.Println("Received DHCPREQUEST from ", packet.StringMAC, ".Sending DHCPOFFER")
				err := Server.SendDHCPAck(packet)
				util.NonFatalError(err)
			}
		}
		util.OnError(err)
	}
}
