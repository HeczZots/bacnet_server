package decoder

import "bytes"

type Decoder struct {
	buff *bytes.Buffer
	err  error
}

func NewDecoder(b []byte) *Decoder {
	return &Decoder{
		bytes.NewBuffer(b),
		nil,
	}
}
