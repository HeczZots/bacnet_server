package btypes

import (
	"fmt"
	"net"
	"strings"
)

type NPDUMetadata byte

type Address struct {
	Net    uint16 // BACnet network number
	Len    uint8
	MacLen uint8   // mac len 0 is a broadcast address
	Mac    []uint8 //note: MAC for IP addresses uses 4 bytes for addr, 2 bytes for port
	Adr    []uint8 // hardware addr (MAC) address of ms-tp devices
}

func FindCIDR(s string) string {
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

func (a *Address) IsBroadcast() bool {
	if a.Net == BroadcastNetwork || a.MacLen == 0 {
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

func (n *NPDUMetadata) HasDestination() bool {
	return n.checkMask(maskDestination)
}

func (n *NPDUMetadata) SetDestination(b bool) {
	n.SetInfoMask(b, maskDestination)
}

func (n *NPDUMetadata) HasSource() bool {
	return n.checkMask(maskSource)
}

func (n *NPDUMetadata) SetSource(b bool) {
	n.SetInfoMask(b, maskSource)
}

func (n *NPDUMetadata) ExpectingReply() bool {
	return n.checkMask(maskExpectingReply)
}

func (n *NPDUMetadata) SetExpectingReply(b bool) {
	n.SetInfoMask(b, maskExpectingReply)
}

func (meta *NPDUMetadata) SetInfoMask(b bool, mask byte) {
	*meta = NPDUMetadata(SetInfoMask(byte(*meta), b, mask))
}

func SetInfoMask(in byte, b bool, mask byte) byte {
	if b {
		return in | mask
	} else {
		var m byte = 0xFF
		m = m - mask
		return in & m
	}
}

// CheckMask uses mask to check bit position
func (meta *NPDUMetadata) checkMask(mask byte) bool {
	return (*meta & NPDUMetadata(mask)) > 0

}

type NPDUPriority byte

func (n *NPDUMetadata) Priority() NPDUPriority {
	// Encoded in bit 0 and 1
	return NPDUPriority(byte(*n) & 3)
}
func (n *NPDUMetadata) IsNetworkLayerMessage() bool {
	return n.checkMask(maskNetworkLayerMessage)
}

func (n *NPDUMetadata) SetNetworkLayerMessage(b bool) {
	n.SetInfoMask(b, maskNetworkLayerMessage)
}
