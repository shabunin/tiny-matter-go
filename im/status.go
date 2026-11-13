// Package im implements the Interaction Model (Matter Core Specification
// chapter 8) server side: Read, Write, Invoke and Timed interactions over a
// data model of endpoints and clusters, with chunked reports.
package im

import "strconv"

// Status is an Interaction Model status code (spec 8.10).
type Status uint8

const (
	Success                Status = 0x00
	Failure                Status = 0x01
	InvalidSubscription    Status = 0x7D
	UnsupportedAccess      Status = 0x7E
	UnsupportedEndpoint    Status = 0x7F
	InvalidAction          Status = 0x80
	UnsupportedCommand     Status = 0x81
	InvalidCommand         Status = 0x85
	UnsupportedAttribute   Status = 0x86
	ConstraintError        Status = 0x87
	UnsupportedWrite       Status = 0x88
	ResourceExhausted      Status = 0x89
	NotFound               Status = 0x8B
	UnreportableAttribute  Status = 0x8C
	InvalidDataType        Status = 0x8D
	UnsupportedRead        Status = 0x8F
	DataVersionMismatch    Status = 0x92
	Timeout                Status = 0x94
	Busy                   Status = 0x9C
	AccessRestricted       Status = 0x9D
	UnsupportedCluster     Status = 0xC3
	NoUpstreamSubscription Status = 0xC5
	NeedsTimedInteraction  Status = 0xC6
	UnsupportedEvent       Status = 0xC7
	PathsExhausted         Status = 0xC8
	TimedRequestMismatch   Status = 0xC9
	FailsafeRequired       Status = 0xCA
	InvalidInState         Status = 0xCB
	NoCommandResponse      Status = 0xCC
)

func (s Status) Error() string { return "im: status 0x" + strconv.FormatUint(uint64(s), 16) }

// Interaction Model opcodes.
const (
	OpStatusResponse   = 0x01
	OpReadRequest      = 0x02
	OpSubscribeRequest = 0x03
	OpSubscribeResp    = 0x04
	OpReportData       = 0x05
	OpWriteRequest     = 0x06
	OpWriteResponse    = 0x07
	OpInvokeRequest    = 0x08
	OpInvokeResponse   = 0x09
	OpTimedRequest     = 0x0A
)

// Revision is the Interaction Model revision this implementation speaks
// (Matter 1.4).
const Revision = 11

// tagIMRevision is the context tag of InteractionModelRevision in every
// message.
const tagIMRevision = 0xFF
