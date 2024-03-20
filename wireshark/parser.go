package wireshark

import (
	"encoding/hex"
	"fmt"
)

type (
	ApduType      byte
	InvokeID      byte
	ServiceChoice byte
)

const ComplexAck ApduType = 0x30
const ReadProp InvokeID = 0x11
const ReadPropMultiply ServiceChoice = 0x0e

type ObjectList struct {
	hex string
}

func NewObjList(hexDumpPacket string) *ObjectList {
	return &ObjectList{hex: hexDumpPacket}
}

func (o *ObjectList) Parse(hexDumpPacket string) ([]byte, error) {
	data, err := hex.DecodeString(o.hex)
	if err != nil {
		return nil, err
	}

	l := len(data)

	for i := range data {
		if i == l-3 {
			err = fmt.Errorf("cannot convert to readmultiply property ack")
			break
		}
		if data[i] == byte(ComplexAck) && data[i+1] == byte(ReadProp) && data[i+2] == byte(ReadPropMultiply) {
			return data[i:], nil
		}

		continue
	}

	return nil, err
}
