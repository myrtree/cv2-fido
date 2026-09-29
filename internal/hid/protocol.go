package hid

import "time"

// CTAPHID command bytes, before the initial-packet bit is set.
// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html
const (
	cmdPing      = 0x01
	cmdInit      = 0x06
	cmdCBOR      = 0x10
	cmdCancel    = 0x11
	cmdKeepalive = 0x3b
	cmdError     = 0x3f
)

const (
	errInvalidCommand = 0x01
	errInvalidLength  = 0x03
	errInvalidSeq     = 0x04
	errMessageTimeout = 0x05
	errChannelBusy    = 0x06
	errInvalidChannel = 0x0b
)

const (
	keepaliveProcessing = 0x01
	keepaliveUPNeeded   = 0x02
	capabilityCBOR      = 0x04
	capabilityNoMSG     = 0x08
)

// Only these CTAP payload values are interpreted by the transport, for
// keepalive and cancellation. The command handler remains an independent callback.
const (
	ctapMakeCredential    = 0x01
	ctapGetAssertion      = 0x02
	ctapKeepaliveCancel   = 0x2d
	ctapUserActionTimeout = 0x2f
)

const broadcastCID uint32 = 0xffffffff

const (
	initialPacketBit       = 0x80
	commandMask            = 0x7f
	reportSize             = 64
	commandOffset          = 4 // After the uint32 channel ID; continuation packets use a sequence byte here.
	lengthOffset           = 5
	initHeaderSize         = 7
	continuationHeaderSize = 5
	maxContinuationPackets = 128
	maxMessage             = (reportSize - initHeaderSize) + maxContinuationPackets*(reportSize-continuationHeaderSize)
	initNonceSize          = 8
	initResponseSize       = 17
	initProtocolOffset     = 12
	initVersionOffset      = 13
	initCapabilitiesOffset = 16
	protocolVersion        = 2
	deviceVersionMajor     = 1
)

// Local resource and timing limits.
const (
	maxChannels        = 128
	commandTimeout     = 30 * time.Second
	assemblyTimeout    = 3 * time.Second
	channelIdleTimeout = 5 * time.Minute
	pollInterval       = 100 * time.Millisecond
)
