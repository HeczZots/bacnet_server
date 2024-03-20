package decoder

import (
	"bacnet_ecosystem_test/btypes"
	"fmt"
)

func (d *Decoder) APDU(a *btypes.APDU) error {
	var meta APDUMetadata
	d.decode(&meta)
	a.SegmentedMessage = meta.isSegmentedMessage()
	a.SegmentedResponseAccepted = meta.segmentedResponseAccepted()
	a.MoreFollows = meta.moreFollows()
	a.DataType = meta.DataType()

	switch a.DataType {
	case btypes.ComplexAck:
		return d.apduComplexAck(a)
	case btypes.SimpleAck:
		return d.apduSimpleAck(a)
	case btypes.UnconfirmedServiceRequest:
		return d.apduUnconfirmed(a)
	case btypes.ConfirmedServiceRequest:
		return d.apduConfirmed(a)
	case btypes.SegmentAck:
		return fmt.Errorf("Segmented")
	case btypes.Error:
		return fmt.Errorf("Got Error")
	case btypes.Reject:
		return fmt.Errorf("Rejected")
	case btypes.Abort:
		return fmt.Errorf("Aborted")
	default:
		return fmt.Errorf("Unknown PDU type:%d", a.DataType)
	}
}

func (d *Decoder) apduComplexAck(a *btypes.APDU) error {
	d.decode(&a.InvokeId)
	d.decode(&a.Service)
	return d.err
}

func (d *Decoder) apduSimpleAck(a *btypes.APDU) error {
	d.decode(&a.InvokeId)
	d.decode(&a.Service)
	return d.err
}

func (d *Decoder) apduUnconfirmed(a *btypes.APDU) error {
	d.decode(&a.UnconfirmedService)
	a.RawData = make([]byte, d.buff.Len())
	d.decode(a.RawData)
	return d.err
}
func (d *Decoder) maxSegsMaxApdu() (maxSegs uint, maxApdu uint) {
	var b uint8
	d.decode(&b)
	return decodeMaxSegs(b), decodeMaxApdu(b)
}

func decodeMaxSegs(a uint8) uint {
	a = a >> 4
	if a >= 0x07 {
		return 65
	}
	return 1 << (a)
}

func decodeMaxApdu(a uint8) uint {
	switch s := a & 0x0F; s {
	case 0:
		return 50
	case 1:
		return 128
	case 2:
		return 206
	case 3:
		return 480
	case 4:
		return 1024
	case 5:
		return 1476
	default:
		return 0
	}
}

func (d *Decoder) apduConfirmed(a *btypes.APDU) error {
	a.MaxSegs, a.MaxApdu = d.maxSegsMaxApdu()

	d.decode(&a.InvokeId)
	if a.SegmentedMessage {
		d.decode(&a.Sequence)
		d.decode(&a.WindowNumber)
	}

	d.decode(&a.Service)
	if d.buff.Len() > 0 {
		a.RawData = make([]byte, d.buff.Len())
		d.decode(&a.RawData)
	}

	return d.err
}

type APDUMetadata byte

const (
	apduMaskSegmented         = 1 << 3
	apduMaskMoreFollows       = 1 << 2
	apduMaskSegmentedAccepted = 1 << 1
	// Bit 0 is reserved
)

func (meta *APDUMetadata) setInfoMask(b bool, mask byte) {
	*meta = APDUMetadata(btypes.SetInfoMask(byte(*meta), b, mask))
}

// CheckMask uses mask to check bit position
func (meta *APDUMetadata) checkMask(mask byte) bool {
	return (*meta & APDUMetadata(mask)) > 0
}

func (meta *APDUMetadata) isSegmentedMessage() bool {
	return meta.checkMask(apduMaskSegmented)
}

func (meta *APDUMetadata) moreFollows() bool {
	return meta.checkMask(apduMaskMoreFollows)
}

func (meta *APDUMetadata) segmentedResponseAccepted() bool {
	return meta.checkMask(apduMaskSegmentedAccepted)
}

func (meta *APDUMetadata) setSegmentedMessage(b bool) {
	meta.setInfoMask(b, apduMaskSegmented)
}

func (meta *APDUMetadata) setMoreFollows(b bool) {
	meta.setInfoMask(b, apduMaskMoreFollows)
}

func (meta *APDUMetadata) setSegmentedAccepted(b bool) {
	meta.setInfoMask(b, apduMaskSegmentedAccepted)
}

func (meta *APDUMetadata) setDataType(t btypes.PDUType) {
	*meta = (*meta & APDUMetadata(0xF0)) | APDUMetadata(t)
}
func (meta *APDUMetadata) DataType() btypes.PDUType {
	return btypes.PDUType(0xF0) & btypes.PDUType(*meta)
}
