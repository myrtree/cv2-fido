package hid

import (
	"context"
	"encoding/binary"
	"errors"
	"log"
	"time"
)

// All transport state and writes belong to one event loop. Only the current
// CTAP command runs in a worker, so CANCEL can interrupt fingerprint waiting.
type hidTransport struct {
	send     func([]byte) error
	handle   func(context.Context, byte, []byte) (byte, []byte)
	channels map[uint32]time.Time
	nextCID  uint32
	assembly *hidAssembly
	job      *hidJob
	results  chan hidResult
	wake     func()
	err      error
	debug    *log.Logger
}

type hidAssembly struct {
	cid   uint32
	cmd   byte
	total int
	seq   byte
	data  []byte
	seen  time.Time
}

type hidJob struct {
	cid    uint32
	cmd    byte
	ctx    context.Context
	cancel context.CancelFunc
	silent bool
	resync []byte
}

type hidResult struct {
	job    *hidJob
	status byte
	data   []byte
}

func newHID(send func([]byte) error, handle func(context.Context, byte, []byte) (byte, []byte)) *hidTransport {
	return &hidTransport{send: send, handle: handle, channels: make(map[uint32]time.Time), results: make(chan hidResult, 1)}
}

func (h *hidTransport) receive(ctx context.Context, p []byte) {
	if len(p) == reportSize+1 && p[0] == 0 {
		p = p[1:]
	}

	if len(p) != reportSize {
		return
	}

	cid := binary.BigEndian.Uint32(p)
	cmd := p[commandOffset] & commandMask
	initial := p[commandOffset]&initialPacketBit != 0
	size := int(binary.BigEndian.Uint16(p[lengthOffset:initHeaderSize]))
	if cid == 0 {
		h.failure(cid, errInvalidChannel)
		return
	}

	if initial && cmd == cmdInit {
		if size != initNonceSize {
			h.failure(cid, errInvalidLength)
			return
		}

		if cid != broadcastCID {
			if _, ok := h.channels[cid]; !ok {
				h.failure(cid, errInvalidChannel)
				return
			}

			if h.job != nil && h.job.cid != cid {
				h.failure(cid, errChannelBusy)
				return
			}

			if h.assembly != nil && h.assembly.cid != cid {
				h.failure(cid, errChannelBusy)
				return
			}

			if h.job != nil {
				if h.debug != nil {
					h.debug.Printf("HID resync: cancelling cmd=0x%02x", h.job.cmd)
				}

				h.job.silent = true
				h.job.resync = append([]byte(nil), p[initHeaderSize:initHeaderSize+initNonceSize]...)
				h.job.cancel()

				return // Acknowledge INIT only after the old worker releases ownership.
			}

			h.assembly = nil
		}

		h.init(cid, p[initHeaderSize:initHeaderSize+initNonceSize])
		return
	}

	if _, ok := h.channels[cid]; !ok {
		h.failure(cid, errInvalidChannel)
		return
	}

	h.channels[cid] = time.Now()
	if initial && cmd == cmdCancel {
		if size != 0 {
			h.failure(cid, errInvalidLength)
			return
		}

		if h.job != nil && h.job.cid == cid {
			if h.debug != nil {
				h.debug.Printf("HID cancel cmd=0x%02x", h.job.cmd)
			}

			h.job.cancel()
		}

		return
	}

	if h.job != nil {
		h.failure(cid, errChannelBusy)
		return
	}

	if initial {
		if h.assembly != nil {
			h.failure(cid, errChannelBusy)
			return
		}

		if size > maxMessage {
			h.failure(cid, errInvalidLength)
			return
		}

		if cmd != cmdPing && cmd != cmdCBOR {
			h.failure(cid, errInvalidCommand)
			return
		}

		n := min(size, reportSize-initHeaderSize)
		h.assembly = &hidAssembly{cid: cid, cmd: cmd, total: size, data: append([]byte(nil), p[initHeaderSize:initHeaderSize+n]...), seen: time.Now()}
	} else {
		a := h.assembly
		if a == nil {
			return
		} // CTAPHID ignores unexpected continuation packets.

		if a.cid != cid {
			h.failure(cid, errChannelBusy)
			return
		}

		if p[commandOffset] != a.seq {
			h.assembly = nil
			h.failure(cid, errInvalidSeq)
			return
		}

		n := min(a.total-len(a.data), reportSize-continuationHeaderSize)
		a.data = append(a.data, p[continuationHeaderSize:continuationHeaderSize+n]...)
		a.seq++
		a.seen = time.Now()
	}

	if len(h.assembly.data) == h.assembly.total {
		a := h.assembly
		h.assembly = nil
		if a.cmd == cmdPing {
			h.respond(cid, cmdPing, a.data)
			return
		}

		if len(a.data) == 0 {
			h.failure(cid, errInvalidLength)
			return
		}

		child, cancel := context.WithTimeout(ctx, commandTimeout)
		job := &hidJob{cid: cid, cmd: a.data[0], ctx: child, cancel: cancel}
		h.job = job

		go func() {
			status, data := h.handle(child, a.data[0], a.data[1:])
			h.results <- hidResult{job: job, status: status, data: data}
			if h.wake != nil {
				h.wake()
			}
		}()
	}
}

func (h *hidTransport) init(cid uint32, nonce []byte) {
	assigned := cid
	if cid == broadcastCID {
		if len(h.channels) >= maxChannels && !h.evictIdleChannel() {
			h.failure(cid, errChannelBusy)
			return
		}

		for {
			h.nextCID++
			if h.nextCID != 0 && h.nextCID != broadcastCID {
				if _, exists := h.channels[h.nextCID]; !exists {
					assigned = h.nextCID
					break
				}
			}
		}
	}

	h.channels[assigned] = time.Now()
	out := make([]byte, initResponseSize)
	copy(out, nonce)
	binary.BigEndian.PutUint32(out[initNonceSize:], assigned)
	out[initProtocolOffset] = protocolVersion
	out[initVersionOffset] = deviceVersionMajor
	out[initCapabilitiesOffset] = capabilityCBOR | capabilityNoMSG
	h.respond(cid, cmdInit, out)
}

// Channel IDs are routing identifiers, not authorization tokens. Reclaim only
// idle channels and leave allocation to nextCID so an evicted ID is not immediately reused.
func (h *hidTransport) evictIdleChannel() bool {
	var oldest uint32
	var seen time.Time
	for cid, last := range h.channels {
		if (h.job != nil && h.job.cid == cid) || (h.assembly != nil && h.assembly.cid == cid) {
			continue
		}

		if oldest == 0 || last.Before(seen) || (last.Equal(seen) && cid < oldest) {
			oldest, seen = cid, last
		}
	}

	if oldest == 0 {
		return false
	}

	delete(h.channels, oldest)
	return true
}

func (h *hidTransport) finish(result hidResult) {
	if result.job != h.job {
		return
	}

	job := h.job
	if job.ctx.Err() != nil {
		result.status = contextStatus(job.ctx)
		result.data = nil
	}

	job.cancel()
	h.job = nil
	if job.resync != nil {
		h.init(job.cid, job.resync)
		return
	}

	if !job.silent {
		if h.debug != nil {
			h.debug.Printf("HID response cmd=0x%02x status=0x%02x", job.cmd, result.status)
		}

		h.respond(job.cid, cmdCBOR, append([]byte{result.status}, result.data...))
	}
}

func (h *hidTransport) tick(now time.Time) {
	select {
	case result := <-h.results:
		h.finish(result)
	default:
	}

	if h.job != nil && !h.job.silent && h.job.ctx.Err() == nil {
		status := byte(keepaliveProcessing)
		if h.job.cmd == ctapMakeCredential || h.job.cmd == ctapGetAssertion {
			status = keepaliveUPNeeded
		}

		h.respond(h.job.cid, cmdKeepalive, []byte{status})
	}

	if h.assembly != nil && now.Sub(h.assembly.seen) > assemblyTimeout {
		cid := h.assembly.cid
		h.assembly = nil
		h.failure(cid, errMessageTimeout)
	}

	for cid, seen := range h.channels {
		if (h.job == nil || h.job.cid != cid) && (h.assembly == nil || h.assembly.cid != cid) && now.Sub(seen) > channelIdleTimeout {
			delete(h.channels, cid)
		}
	}
}

func (h *hidTransport) failure(cid uint32, code byte) {
	if h.debug != nil {
		h.debug.Printf("HID error=0x%02x", code)
	}

	h.respond(cid, cmdError, []byte{code})
}

func (h *hidTransport) respond(cid uint32, cmd byte, data []byte) {
	if h.err != nil {
		return
	}

	if len(data) > maxMessage {
		h.failure(cid, errInvalidLength)
		return
	}

	p := make([]byte, reportSize)
	binary.BigEndian.PutUint32(p, cid)
	p[commandOffset] = cmd | initialPacketBit
	binary.BigEndian.PutUint16(p[lengthOffset:], uint16(len(data)))
	n := copy(p[initHeaderSize:], data)
	h.err = h.send(p)
	data = data[n:]
	for seq := byte(0); len(data) > 0 && h.err == nil; seq++ {
		p = make([]byte, reportSize)
		binary.BigEndian.PutUint32(p, cid)
		p[commandOffset] = seq
		n = copy(p[continuationHeaderSize:], data)
		h.err = h.send(p)
		data = data[n:]
	}
}

// CTAP cancellation status is carried in the HID CBOR response.
func contextStatus(ctx context.Context) byte {
	if errors.Is(ctx.Err(), context.Canceled) {
		return ctapKeepaliveCancel
	}

	return ctapUserActionTimeout
}
