package main

var testiamSADR_0 = []byte{
	0x81, 0x0b, 0x00, 0x18, // bacnet virtual link control
	0x01, 0x08, 0x09, 0x62, 0x01, 0x01, //Building Automation and control Network NPDU
	0x10, 0x00, 0xc4, 0x02, 0x00, 0x5d, 0xc3, 0x22, 0x01, 0xe0, 0x91, 0x00, 0x21, 0x18, // APDU
}

var testiamSADR_1 = []byte{
	0x81, 0x0b, 0x00, 0x18, // bacnet virtual link control
	0x01, 0x08, 0x09, 0x62, 0x01, 0x02, //Building Automation and control Network NPDU
	0x10, 0x00, 0xc4, 0x02, 0x00, 0x5d, 0xc4, 0x22, 0x01, 0xe0, 0x91, 0x00, 0x21, 0x18, // APDU
}

var testiamSADR_2 = []byte{
	0x81, 0x0b, 0x00, 0x18, // bacnet virtual link control
	0x01, 0x08, 0x09, 0x62, 0x01, 0x03, //Building Automation and control Network NPDU
	0x10, 0x00, 0xc4, 0x02, 0x00, 0x5d, 0xc5, 0x22, 0x01, 0xe0, 0x91, 0x00, 0x21, 0x18, // APDU
}

var testiamSADR_3 = []byte{
	0x81, 0x0b, 0x00, 0x18, // bacnet virtual link control
	0x01, 0x08, 0x09, 0x62, 0x01, 0x04, //Building Automation and control Network NPDU
	0x10, 0x00, 0xc4, 0x02, 0x00, 0x5d, 0xc6, 0x22, 0x01, 0xe0, 0x91, 0x00, 0x21, 0x18, // APDU
}

var testiamSADR_4 = []byte{
	0x81, 0x0b, 0x00, 0x18, // bacnet virtual link control
	0x01, 0x08, 0x09, 0x62, 0x01, 0x05, //Building Automation and control Network NPDU
	0x10, 0x00, 0xc4, 0x02, 0x00, 0x5d, 0xc7, 0x22, 0x01, 0xe0, 0x91, 0x00, 0x21, 0x18, // APDU
}

var testiamSADR_5 = []byte{
	0x81, 0x0b, 0x00, 0x18, // bacnet virtual link control
	0x01, 0x08, 0x09, 0x62, 0x01, 0x06, //Building Automation and control Network NPDU
	0x10, 0x00, 0xc4, 0x02, 0x00, 0x5d, 0xc8, 0x22, 0x01, 0xe0, 0x91, 0x00, 0x21, 0x18, // APDU
}

var testiamSADR_6 = []byte{
	0x81, 0x0b, 0x00, 0x18, // bacnet virtual link control
	0x01, 0x08, 0x09, 0x62, 0x01, 0x07, //Building Automation and control Network NPDU
	0x10, 0x00, 0xc4, 0x02, 0x00, 0x5d, 0xa1, 0x22, 0x01, 0xe0, 0x91, 0x00, 0x21, 0x18, // APDU
}

var testiamSADR_7 = []byte{
	0x81, 0x0b, 0x00, 0x18, // bacnet virtual link control
	0x01, 0x08, 0x09, 0x62, 0x01, 0x08, //Building Automation and control Network NPDU
	0x10, 0x00, 0xc4, 0x02, 0x00, 0x5d, 0xa2, 0x22, 0x01, 0xe0, 0x91, 0x00, 0x21, 0x18, // APDU
}

var testiamSADR_8 = []byte{
	0x81, 0x0b, 0x00, 0x18, // bacnet virtual link control
	0x01, 0x08, 0x09, 0x62, 0x01, 0x09, //Building Automation and control Network NPDU
	0x10, 0x00, 0xc4, 0x02, 0x00, 0x5d, 0xa2, 0x22, 0x01, 0xe0, 0x91, 0x00, 0x21, 0x18, // APDU
}

var testiamSADR_9 = []byte{
	0x81, 0x0b, 0x00, 0x18, // bacnet virtual link control
	0x01, 0x08, 0x09, 0x62, 0x01, 0xa, //Building Automation and control Network NPDU
	0x10, 0x00, 0xc4, 0x02, 0x00, 0x5d, 0xa4, 0x22, 0x01, 0xe0, 0x91, 0x00, 0x21, 0x18, // APDU
}

var IAmArr = [][]byte{testiamSADR_0, testiamSADR_1, testiamSADR_2, testiamSADR_3, testiamSADR_4, testiamSADR_5, testiamSADR_6, testiamSADR_7, testiamSADR_8, testiamSADR_9}

var testiamRegular = []byte{
	0x81, 0x0b, 0x00, 0x14, // bacnet virtual link control
	0x01, 0x00, //Building Automation and control Network NPDU
	0x10, 0x00, 0xc4, 0x02, 0x36, 0xb1, 0x46, 0x22, 0x05, 0xc4, 0x91, 0x00, 0x21, 0x0a, // APDU
}
