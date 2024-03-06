package main

import (
	"bytes"
	"encoding/binary"
)

type Address struct {
	Net    uint16 // BACnet network number
	Len    uint8
	MacLen uint8   // mac len 0 is a broadcast address
	Mac    []uint8 //note: MAC for IP addresses uses 4 bytes for addr, 2 bytes for port
	Adr    []uint8 // hardware addr (MAC) address of ms-tp devices
}

var broadcast = []uint8{0xc0, 0xa8, 0x05, 0xff, 0xba, 0xc0}

var EncodingEndian binary.ByteOrder = binary.BigEndian

const GlobalBroadcast uint16 = 0xFFFF
const broadcastNetwork uint16 = 0xFFFF

type NPDU struct {
	IsNetworkLayerMessage   bool
	ExpectingReply          bool
	NetworkLayerMessageType NetworkMessageType
	Version                 uint8
	HopCount                uint8
	VendorId                uint16
	Priority                NPDUPriority
	Destination             *Address
	Source                  *Address
}

type APDU struct {
	SegmentedMessage          bool
	MoreFollows               bool
	SegmentedResponseAccepted bool
	MaxSegs                   uint
	MaxApdu                   uint
	DataType                  PDUType
	InvokeId                  uint8
	Sequence                  uint8
	WindowNumber              uint8
	Service                   uint8
	UnconfirmedService        ServiceUnconfirmed
	Error                     struct {
		Class uint16
		Code  uint16
	}

	// This is the raw data passed based on the service
	RawData []byte
}

type PDUType uint8

// pdu requests
const (
	ConfirmedServiceRequest   PDUType = 0
	UnconfirmedServiceRequest PDUType = 0x10
	SimpleAck                 PDUType = 0x20
	ComplexAck                PDUType = 0x30
	SegmentAck                PDUType = 0x40
	Error                     PDUType = 0x50
	Reject                    PDUType = 0x60
	Abort                     PDUType = 0x70
)

func (a *APDU) IsConfirmedServiceRequest() bool {
	return (0xF0 & a.DataType) == ConfirmedServiceRequest
}

type BacFunc byte

const BVLCTypeBacnetIP = 0x81

var (
	BacFuncUnicast   BacFunc = 10
	BacFuncBroadcast BacFunc = 11
)

type BVLC struct {
	Type     byte
	Function BacFunc

	// Length includes the length of Type, Function, and Length. (4 bytes) It also
	// has the length of the data field after
	Length uint16
	Data   []byte
}
type Decoder struct {
	buff *bytes.Buffer
	err  error
}

type NPDUMetadata byte

const maskNetworkLayerMessage = 1 << 7
const maskDestination = 1 << 5
const maskSource = 1 << 3
const maskExpectingReply = 1 << 2

type NetworkMessageType uint8

const (
	WhoIsRouterToNetwork NetworkMessageType = 0x00
	IamRouterToNetwork   NetworkMessageType = 0x01
	WhatIsNetworkNumber  NetworkMessageType = 0x12
	NetworkIs            NetworkMessageType = 0x13
)

func (n *NPDUMetadata) HasDestination() bool {
	return n.checkMask(maskDestination)
}

func (n *NPDUMetadata) SetDestination(b bool) {
	n.setInfoMask(b, maskDestination)
}

func (n *NPDUMetadata) HasSource() bool {
	return n.checkMask(maskSource)
}

func (n *NPDUMetadata) SetSource(b bool) {
	n.setInfoMask(b, maskSource)
}

func (n *NPDUMetadata) ExpectingReply() bool {
	return n.checkMask(maskExpectingReply)
}

func (n *NPDUMetadata) SetExpectingReply(b bool) {
	n.setInfoMask(b, maskExpectingReply)
}

func (meta *NPDUMetadata) setInfoMask(b bool, mask byte) {
	*meta = NPDUMetadata(setInfoMask(byte(*meta), b, mask))
}

func setInfoMask(in byte, b bool, mask byte) byte {
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
	n.setInfoMask(b, maskNetworkLayerMessage)
}
