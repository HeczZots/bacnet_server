package btypes

import "encoding/binary"

var Broadcast = []uint8{0xc0, 0xa8, 0x05, 0xff, 0xba, 0xc0}

var EncodingEndian binary.ByteOrder = binary.BigEndian

const GlobalBroadcast uint16 = 0xFFFF
const BroadcastNetwork uint16 = 0xFFFF

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

type ServiceUnconfirmed uint8

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
