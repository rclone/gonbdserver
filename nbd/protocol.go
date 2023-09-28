// Package nbd implements an NBD server with pluggable backends.
package nbd

/* --- START OF NBD PROTOCOL SECTION --- */

// this section is in essence a transcription of the protocol from
// NBD's proto.md; note that that file is *not* GPL. For details of
// what the options mean, see proto.md

// NBD commands
const (
	CmdRead        = 0
	CmdWrite       = 1
	CmdDisc        = 2
	CmdFlush       = 3
	CmdTrim        = 4
	CmdWriteZeroes = 5
	CmdClose       = 7
)

// NBD command flags
const (
	CmdFlagFua = uint16(1 << 0)
	CmdMayTrim = uint16(1 << 1)
	CmdFlagDf  = uint16(1 << 2)
)

// NBD negotiation flags
const (
	FlagHasFlags        = uint16(1 << 0)
	FlagReadOnly        = uint16(1 << 1)
	FlagSendFlush       = uint16(1 << 2)
	FlagSendFua         = uint16(1 << 3)
	FlagRotational      = uint16(1 << 4)
	FlagSendTrim        = uint16(1 << 5)
	FlagSendWriteZeroes = uint16(1 << 6)
	FlagSendDf          = uint16(1 << 7)
	FlagSendClose       = uint16(1 << 8)
)

// NBD magic numbers
const (
	NbdMagic             = 0x4e42444d41474943
	RequestMagic         = 0x25609513
	ReplyMagic           = 0x67446698
	CliservMagic         = 0x00420281861253
	OptsMagic            = 0x49484156454F5054
	RepMagic             = 0x3e889045565a9
	StructuredReplyMagic = 0x668e33ef
)

// NBD default port
const (
	DefaultPort = 10809
)

// NBD options
const (
	OptExportName      = 1
	OptAbort           = 2
	OptList            = 3
	OptPeekExport      = 4
	OptStarttls        = 5
	OptInfo            = 6
	OptGo              = 7
	OptStructuredReply = 8
)

// NBD option reply types
const (
	RepAck              = uint32(1)
	RepServer           = uint32(2)
	RepInfo             = uint32(3)
	RepFlagError        = uint32(1 << 31)
	RepErrUnsup         = 1 | RepFlagError
	RepErrPolicy        = 2 | RepFlagError
	RepErrInvalid       = 3 | RepFlagError
	RepErrPlatform      = 4 | RepFlagError
	RepErrTLSReqd       = 5 | RepFlagError
	RepErrUnknown       = 6 | RepFlagError
	RepErrShutdown      = 7 | RepFlagError
	RepErrBlockSizeReqd = 8 | RepFlagError
)

// NBD reply flags
const (
	ReplyFlagDone = 1 << 0
)

// NBD reply types
const (
	ReplyTypeNone        = 0
	ReplyTypeError       = 1
	ReplyTypeErrorOffset = 2
	ReplyTypeOffsetData  = 3
	ReplyTypeOffsetHole  = 4
)

// NBD hanshake flags
const (
	FlagFixedNewstyle = 1 << 0
	FlagNoZeroes      = 1 << 1
)

// NBD client flags
const (
	FlagCFixedNewstyle = 1 << 0
	FlagCNoZeroes      = 1 << 1
)

// NBD errors
const (
	EPERM     = 1
	EIO       = 5
	ENOMEM    = 12
	EINVAL    = 22
	ENOSPC    = 28
	EOVERFLOW = 75
)

// NBD info types
const (
	NbdInfoExport      = 0
	NbdInfoName        = 1
	NbdInfoDescription = 2
	NbdInfoBlockSize   = 3
)

// NewStyleHeader is a NBD new style header
type NewStyleHeader struct {
	Magic       uint64
	OptsMagic   uint64
	GlobalFlags uint16
}

// ClientFlags is a NBD client flags
type ClientFlags struct {
	Flags uint32
}

// ClientOpt is a NBD client options
type ClientOpt struct {
	Magic uint64
	ID    uint32
	Len   uint32
}

// ExportDetails is a NBD export details
type ExportDetails struct {
	Size  uint64
	Flags uint16
}

// OptReply is a NBD option reply
type OptReply struct {
	Magic  uint64
	ID     uint32
	Type   uint32
	Length uint32
}

// Request is a NBD request
type Request struct {
	Magic        uint32
	CommandFlags uint16
	CommandType  uint16
	Handle       uint64
	Offset       uint64
	Length       uint32
}

// Reply is a NBD simple reply
type Reply struct {
	Magic  uint32
	Error  uint32
	Handle uint64
}

// InfoExport is a NBD info export
type InfoExport struct {
	InfoType          uint16
	ExportSize        uint64
	TransmissionFlags uint16
}

// InfoBlockSize is a NBD info blocksize
type InfoBlockSize struct {
	InfoType           uint16
	MinimumBlockSize   uint32
	PreferredBlockSize uint32
	MaximumBlockSize   uint32
}

/* --- END OF NBD PROTOCOL SECTION --- */

// Our internal flags to characterize commands
const (
	CmdTCheckLengthOffset     = 1 << iota // length and offset must be valid
	CmdTReqPayload                        // request carries a payload
	CmdTReqFakePayload                    // request does not carry a payload, but we'll make a zero payload up
	CmdTRepPayload                        // reply carries a payload
	CmdTCheckNotReadOnly                  // not valid on read-only media
	CmdTSetDisconnectReceived             // a disconnect - don't process any further commands
)

// CmdTypeMap is a map specifying each command
var CmdTypeMap = map[int]uint64{
	CmdRead:        CmdTCheckLengthOffset | CmdTRepPayload,
	CmdWrite:       CmdTCheckLengthOffset | CmdTCheckNotReadOnly | CmdTReqPayload,
	CmdDisc:        CmdTSetDisconnectReceived,
	CmdFlush:       CmdTCheckNotReadOnly,
	CmdTrim:        CmdTCheckLengthOffset | CmdTCheckNotReadOnly,
	CmdWriteZeroes: CmdTCheckLengthOffset | CmdTCheckNotReadOnly | CmdTReqFakePayload,
	CmdClose:       CmdTSetDisconnectReceived,
}
