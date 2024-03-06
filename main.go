package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"github.com/rs/zerolog"
)

const DebugLevel = 0

var myIp = "192.168.5.37"
var bac0 = 47808

func main() {
	_, ipNet, err := net.ParseCIDR(findCIDR(myIp))
	if err != nil {
		log.Printf(err.Error())
		return
	}
	mw := io.MultiWriter(zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: "2006.01.02 15:04:05.000",
	})
	l := zerolog.New(mw).With().Timestamp().Logger()
	l = l.Level(zerolog.Level(DebugLevel))
	broadcast := net.IP(make([]byte, 4))
	for i := range broadcast {
		broadcast[i] = ipNet.IP[i] | ^ipNet.Mask[i]
	}

	// myAddr := IPPortToAddress(ip, bac0)
	broadcastAddr := IPPortToAddress(broadcast, bac0)
	listenAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", myIp, bac0))

	list, err := net.ListenUDP("udp", listenAddr)

	if err != nil {
		l.Fatal().Err(err)
		return
	}

	l.Info().Msgf("listening on started %s", listenAddr)
	for {
		d, err := broadcastAddr.UDPAddr()
		if err != nil {
			l.Err(err)
			return
		}
		b := make([]byte, 1476)
		n, source, err := list.ReadFromUDP(b)
		if err != nil {
			l.Err(err)
			continue
		}
		decoder := NewDecoder(b)
		go func(b []byte) {

			if !decoder.IsWhoIs(b[:n]) {
				return
			}

			l.Info().Msgf("received Who is")

			if UDPToAddress(source).IsBroadcast() {
				_, err = list.WriteToUDP(testiamSADR, &d)
				l.Info().Msgf("Iam To broadcast")
			} else {
				source.IP = source.IP.To4()
				_, err = list.WriteToUDP(testiamSADR, source)
				l.Info().Msgf("Iam To %v ", source)
			}

			if err != nil {
				l.Err(err)
				return
			}
		}(b)
	}
}

func (a *Address) IsBroadcast() bool {
	if a.Net == broadcastNetwork || a.MacLen == 0 {
		return true
	}
	return false
}

func (a *Address) UDPAddr() (net.UDPAddr, error) {
	if len(a.Mac) != 6 {
		return net.UDPAddr{}, fmt.Errorf("mac is too short at %d", len(a.Mac))
	}
	port := uint(a.Mac[4])<<8 | uint(a.Mac[5])
	ip := net.IPv4(a.Mac[0], a.Mac[1], a.Mac[2], a.Mac[3])
	return net.UDPAddr{
		IP:   ip,
		Port: int(port),
	}, nil
}

func findCIDR(s string) string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}

	for _, a := range addrs {
		if strings.Contains(a.String(), s) {
			return a.String()
		}
	}
	return ""
}

func IPPortToAddress(ip net.IP, port int) *Address {
	return UDPToAddress(&net.UDPAddr{
		IP:   ip.To4(),
		Port: port,
	})
}

// UDPToAddress converts a given udp address into a bacnet address
func UDPToAddress(n *net.UDPAddr) *Address {
	a := &Address{}
	p := uint16(n.Port)
	// Length of IP plus the port
	length := net.IPv4len + 2
	a.Mac = make([]uint8, length)
	//Encode ip
	for i := 0; i < net.IPv4len; i++ {
		a.Mac[i] = n.IP[i]
	}
	// Encode port
	a.Mac[net.IPv4len+0] = uint8(p >> 8)
	a.Mac[net.IPv4len+1] = uint8(p & 0x00FF)

	a.MacLen = uint8(length)
	return a
}
