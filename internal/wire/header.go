package wire

import (
	"encoding/binary"
	"errors"
)

var (
	ErrShortBuffer = errors.New("wire: buffer too short")
	ErrVersion     = errors.New("wire: unsupported protocol version")
	ErrType        = errors.New("wire: unknown message type")
)

// Header is the 4-byte prefix common to every Treccia datagram.
type Header struct {
	Type   uint8
	Flags  uint8
	PathID uint8
	Epoch  uint8
}

// Class extracts the traffic class from the flags byte.
func (h Header) Class() uint8 { return h.Flags >> 2 & 0x3 }

// ClassFlags returns the flag bits that encode the given traffic class.
func ClassFlags(class uint8) uint8 { return class << 2 & 0x0c }

// PutHeader encodes h into the first HeaderSize bytes of b.
func PutHeader(b []byte, h Header) {
	_ = b[HeaderSize-1]
	b[0] = Version<<4 | h.Type&0x0f
	b[1] = h.Flags
	b[2] = h.PathID
	b[3] = h.Epoch
}

// ParseHeader decodes and validates the common header.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < HeaderSize {
		return Header{}, ErrShortBuffer
	}
	if b[0]>>4 != Version {
		return Header{}, ErrVersion
	}
	h := Header{Type: b[0] & 0x0f, Flags: b[1], PathID: b[2], Epoch: b[3]}
	if h.Type > maxType {
		return Header{}, ErrType
	}
	return h, nil
}

// DataHeader is the framing of a DATA datagram. TxTS is the sender's
// monotonic clock in microseconds truncated to 32 bits: receivers only ever
// use differences between paths, never absolute values. FECGroup is a 24-bit
// group id, meaningful only when FlagFECInfo is set.
type DataHeader struct {
	Header
	Session   uint32
	GlobalSeq uint32
	PathSeq   uint32
	TxTS      uint32
	FECGroup  uint32
	FECIndex  uint8
}

// Len returns the encoded size of d: DataHeaderSize, or DataHeaderFECSize
// when FlagFECInfo is set.
func (d *DataHeader) Len() int {
	if d.Flags&FlagFECInfo != 0 {
		return DataHeaderFECSize
	}
	return DataHeaderSize
}

// PutDataHeader encodes d into b and returns the number of bytes written.
func PutDataHeader(b []byte, d *DataHeader) int {
	n := d.Len()
	_ = b[n-1]
	PutHeader(b, d.Header)
	binary.BigEndian.PutUint32(b[4:], d.Session)
	binary.BigEndian.PutUint32(b[8:], d.GlobalSeq)
	binary.BigEndian.PutUint32(b[12:], d.PathSeq)
	binary.BigEndian.PutUint32(b[16:], d.TxTS)
	if d.Flags&FlagFECInfo != 0 {
		b[20] = byte(d.FECGroup >> 16)
		b[21] = byte(d.FECGroup >> 8)
		b[22] = byte(d.FECGroup)
		b[23] = d.FECIndex
	}
	return n
}

// ParseDataHeader decodes a DATA datagram, returning the header and the
// payload (the WireGuard ciphertext) aliased into b.
func ParseDataHeader(b []byte) (DataHeader, []byte, error) {
	h, err := ParseHeader(b)
	if err != nil {
		return DataHeader{}, nil, err
	}
	if h.Type != TypeData {
		return DataHeader{}, nil, ErrType
	}
	d := DataHeader{Header: h}
	if len(b) < d.Len() {
		return DataHeader{}, nil, ErrShortBuffer
	}
	d.Session = binary.BigEndian.Uint32(b[4:])
	d.GlobalSeq = binary.BigEndian.Uint32(b[8:])
	d.PathSeq = binary.BigEndian.Uint32(b[12:])
	d.TxTS = binary.BigEndian.Uint32(b[16:])
	n := DataHeaderSize
	if d.Flags&FlagFECInfo != 0 {
		d.FECGroup = uint32(b[20])<<16 | uint32(b[21])<<8 | uint32(b[22])
		d.FECIndex = b[23]
		n = DataHeaderFECSize
	}
	return d, b[n:], nil
}
