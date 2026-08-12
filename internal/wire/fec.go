package wire

import "encoding/binary"

// FEC datagrams carry one Reed-Solomon parity shard of a group of DATA
// packets. Data-plane framing (no MAC): the shard protects WireGuard
// ciphertext which is authenticated end-to-end anyway.
//
// Layout: common header (4) + session (4) + group (3) + index (1) +
// k (1) + m (1) + shard_len (2) = 16 bytes, then the shard.
const FECHeaderSize = 16

// FECHeader describes one parity shard datagram. K is the number of data
// shards in the group (learned by receivers from parity, since DATA
// packets only carry group+index); Index is in [K, K+M).
type FECHeader struct {
	Header
	Session  uint32
	Group    uint32 // 24-bit rolling group id
	Index    uint8
	K        uint8
	M        uint8
	ShardLen uint16
}

// PutFECHeader encodes f into b and returns FECHeaderSize.
func PutFECHeader(b []byte, f *FECHeader) int {
	_ = b[FECHeaderSize-1]
	f.Type = TypeFEC
	PutHeader(b, f.Header)
	binary.BigEndian.PutUint32(b[4:], f.Session)
	b[8] = byte(f.Group >> 16)
	b[9] = byte(f.Group >> 8)
	b[10] = byte(f.Group)
	b[11] = f.Index
	b[12] = f.K
	b[13] = f.M
	binary.BigEndian.PutUint16(b[14:], f.ShardLen)
	return FECHeaderSize
}

// ParseFEC decodes a FEC datagram, returning the header and the shard
// aliased into b.
func ParseFEC(b []byte) (FECHeader, []byte, error) {
	h, err := ParseHeader(b)
	if err != nil {
		return FECHeader{}, nil, err
	}
	if h.Type != TypeFEC {
		return FECHeader{}, nil, ErrType
	}
	if len(b) < FECHeaderSize {
		return FECHeader{}, nil, ErrShortBuffer
	}
	f := FECHeader{
		Header:   h,
		Session:  binary.BigEndian.Uint32(b[4:]),
		Group:    uint32(b[8])<<16 | uint32(b[9])<<8 | uint32(b[10]),
		Index:    b[11],
		K:        b[12],
		M:        b[13],
		ShardLen: binary.BigEndian.Uint16(b[14:]),
	}
	if int(f.ShardLen) != len(b)-FECHeaderSize {
		return FECHeader{}, nil, ErrShortBuffer
	}
	return f, b[FECHeaderSize:], nil
}
