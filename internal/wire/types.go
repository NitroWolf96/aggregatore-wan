// Package wire defines the Treccia on-the-wire datagram format.
//
// Every datagram starts with a 4-byte common header. DATA and FEC datagrams
// carry the multipath framing needed to reorder and deduplicate packets that
// were striped across WAN links; all other types form the control plane and
// are authenticated with a keyed BLAKE2s-128 tag.
package wire

// Version is the protocol version carried in the high nibble of byte 0.
// A major mismatch is rejected at HELLO time.
const Version = 1

// Message types (low nibble of byte 0).
const (
	TypeData     uint8 = 0x0
	TypeProbe    uint8 = 0x1
	TypeProbeAck uint8 = 0x2
	TypeCtrl     uint8 = 0x3
	TypeFEC      uint8 = 0x4
	TypeHello    uint8 = 0x5
	TypeHelloAck uint8 = 0x6
	TypeBye      uint8 = 0x7

	maxType = TypeBye
)

// Flag bits (byte 1).
const (
	// FlagDup marks the redundant copy of a packet already sent on another
	// path, so receivers can count duplicates separately from path loss.
	FlagDup uint8 = 1 << 0
	// FlagFECInfo extends the DATA header with the FEC group/index fields.
	FlagFECInfo uint8 = 1 << 1
)

// Traffic classes, carried in bits 2-3 of the flags byte.
const (
	ClassBulk        uint8 = 0
	ClassRealtime    uint8 = 1
	ClassInteractive uint8 = 2
)

// Encoded sizes in bytes.
const (
	HeaderSize        = 4
	DataHeaderSize    = 20 // common + session + global_seq + path_seq + tx_ts
	DataHeaderFECSize = DataHeaderSize + 4
	MACSize           = 16 // keyed BLAKE2s-128 tag on control-plane messages
)
