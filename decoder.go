package main

import (
	"bytes"
	"encoding/binary"
	"log"
)

func NewDecoder(b []byte) *Decoder {
	return &Decoder{
		bytes.NewBuffer(b),
		nil,
	}
}

func (d *Decoder) decode(data interface{}) {
	if d.err != nil {
		return
	}

	d.err = binary.Read(d.buff, EncodingEndian, data)
}

func (d *Decoder) Address(a *Address) {
	d.decode(&a.Net) //decode the network address
	d.decode(&a.Len)
	// Make space for address
	a.Adr = make([]uint8, a.Len) //decode the device hardware mac addr
	d.decode(a.Adr)

}

func (d *Decoder) BVLC(b *BVLC) error {
	d.decode(&b.Type)
	d.decode(&b.Function)
	d.decode(&b.Length)
	d.decode(&b.Data)
	return d.err
}
func (d *Decoder) NPDU(n *NPDU) (addr []Address, err error) {
	d.decode(&n.Version)
	meta := NPDUMetadata(0)
	d.decode(&meta)
	n.ExpectingReply = meta.ExpectingReply()
	n.IsNetworkLayerMessage = meta.IsNetworkLayerMessage()
	n.Priority = meta.Priority()

	if meta.HasDestination() {
		n.Destination = &Address{}
		d.Address(n.Destination)
	}

	if meta.HasSource() {
		n.Source = &Address{}
		d.Address(n.Source)
	}

	if meta.HasDestination() {
		d.decode(&n.HopCount)
	} else {
		n.HopCount = 0
	}

	if meta.IsNetworkLayerMessage() {
		d.decode(&n.NetworkLayerMessageType)
		if n.NetworkLayerMessageType > 0x80 {
			d.decode(&n.VendorId)
		}
		if n.NetworkLayerMessageType == NetworkIs {
			n.Source = &Address{}
			d.decode(&n.Source.Net)
		}
		if n.NetworkLayerMessageType == IamRouterToNetwork {
			n.Source = &Address{}
			var nets []Address
			d.decode(&n.Source.Net)
			nets = append(nets, *n.Source)
			size := d.buff.Len()
			for i := d.buff.Len(); i <= size; i++ {
				d.decode(&n.Source.Net)
				for _, adr := range nets {
					if adr.Net != n.Source.Net {
						nets = append(nets, *n.Source)
					}
				}
			}
			addr = nets
		}
	}
	return addr, d.err
}

func (d *Decoder) IsWhoIs(message []byte) bool {
	var header BVLC
	var npdu NPDU
	var apdu APDU
	d.buff = bytes.NewBuffer(message)

	err := d.BVLC(&header)
	if err != nil {
		return false
	}

	_, err = d.NPDU(&npdu)
	if err != nil {
		return false
	}
	err = d.APDU(&apdu)
	if err != nil {
		log.Printf("error getting APDU")
		return false
	}

	if apdu.UnconfirmedService == ServiceUnconfirmedWhoIs {
		dec := NewDecoder(apdu.RawData)
		var low, high int32
		dec.WhoIs(&low, &high)
		if mod == 1 && npdu.Destination.Net == 65535 {
			return true
		}
		if mod == 2 && npdu.Destination.Net != 65535 {
			return true
		}
		if mod == 3 {
			return true
		}
	}

	return false
}

const WhoIsAll = -1
const ArrayAll = 0xFFFFFFFF

type ServiceUnconfirmed uint8

const ServiceUnconfirmedWhoIs ServiceUnconfirmed = 8

func (d *Decoder) WhoIs(low, high *int32) bool {
	if d.buff.Len() == 0 {
		*low = WhoIsAll
		*high = WhoIsAll
		return false
	}
	// Tag 0 - Low Value
	var expectedTag uint8
	tag, _, value := d.tagNumberAndValue()
	if tag != expectedTag {
		return false
	}
	l := d.unsigned(int(value))
	*low = int32(l)

	// Tag 1 - High Value
	expectedTag = 1
	tag, _, value = d.tagNumberAndValue()
	if tag != expectedTag {
		return false
	}
	h := d.unsigned(int(value))
	*high = int32(h)

	return true
}

func (d *Decoder) tagNumberAndValue() (tag uint8, meta tagMeta, value uint32) {
	tag, meta = d.tagNumber()
	return tag, meta, d.value(meta)
}

func (d *Decoder) tagNumber() (tag uint8, meta tagMeta) {
	// Read the first value
	d.decode(&meta)
	if meta.isExtendedTagNumber() {
		d.decode(&tag)
		return tag, meta
	}
	return uint8(meta) >> 4, meta
}

const (
	flag16bit uint8 = 254
	flag32bit uint8 = 255
)

type tagMeta uint8

const tagMask tagMeta = 7
const openingMask tagMeta = 6
const closingMask tagMeta = 7
const extendValueBits tagMeta = 5
const contextSpecificBit = 0x08
const (
	size8  = 1
	size16 = 2
	size24 = 3
	size32 = 4
)

func (d *Decoder) unsigned(length int) uint32 {
	switch length {
	case size8: //1
		var val uint8
		d.decode(&val)
		return uint32(val)
	case size16: //2
		var val uint16
		d.decode(&val)
		return uint32(val)
	case size24: //3
		return d.unsigned24()
	case size32: //4
		var val uint32
		d.decode(&val)
		return val
	default:
		return 0
	}
}

func (d *Decoder) unsigned24() uint32 {
	var a, b, c uint8
	d.decode(&a)
	d.decode(&b)
	d.decode(&c)

	var x uint32
	x = uint32((uint32(a) << 16) & 0x00ff0000)
	x |= uint32((uint32(b) << 8) & 0x0000ff00)
	x |= uint32(uint32(c) & 0x000000ff)
	return x
}

func (d *Decoder) value(meta tagMeta) (value uint32) {
	if meta.isExtendedValue() {
		var val uint8
		d.decode(&val)
		// Tagged as an uint32
		if val == flag32bit {
			var parse uint32
			d.decode(&parse)
			return parse

			// Tagged as a uint16
		} else if val == flag16bit {
			var parse uint16
			d.decode(&parse)
			return uint32(parse)

			// No tag, it must be a uint8
		} else {
			return uint32(val)
		}
	} else if meta.isOpening() || meta.isClosing() {
		return 0
	}
	return uint32(meta & 0x07)
}

func (t *tagMeta) isClosing() bool {
	return ((*t & closingMask) == closingMask)
}

func (t *tagMeta) isOpening() bool {
	return ((*t & openingMask) == openingMask)
}

func (t *tagMeta) Clear() {
	*t = 0
}

func (t *tagMeta) isExtendedValue() bool {
	return (*t & tagMask) == extendValueBits
}

func (t *tagMeta) isExtendedTagNumber() bool {
	return ((*t & 0xF0) == 0xF0)
}
