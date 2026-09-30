package hid

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"
)

func hidPacket(cid uint32, cmd byte, length int, payload []byte) []byte {
	p := make([]byte, 64)
	binary.BigEndian.PutUint32(p, cid)
	p[4] = cmd | 0x80
	binary.BigEndian.PutUint16(p[5:], uint16(length))
	copy(p[7:], payload)
	return p
}
func testHID(t *testing.T) (*hidTransport, *[][]byte, uint32) {
	t.Helper()
	packets := new([][]byte)
	h := newHID(func(p []byte) error { *packets = append(*packets, bytes.Clone(p)); return nil }, func(context.Context, byte, []byte) (byte, []byte) { return 0, nil })
	h.receive(context.Background(), hidPacket(0xffffffff, 6, 8, []byte("12345678")))
	if len(*packets) != 1 {
		t.Fatal("missing INIT response")
	}

	cid := binary.BigEndian.Uint32((*packets)[0][15:19])
	if cid == 0 || cid == 0xffffffff {
		t.Fatal("invalid allocated channel")
	}

	*packets = nil
	return h, packets, cid
}
func TestHIDFramingAndBounds(t *testing.T) {
	h, packets, cid := testHID(t)
	// A CID with a leading zero must not be mistaken for a report ID.
	h.receive(context.Background(), hidPacket(cid, 1, 3, []byte("abc")))
	if len(*packets) != 1 || string((*packets)[0][7:10]) != "abc" {
		t.Fatal("PING framing failed")
	}

	*packets = nil
	h.receive(context.Background(), hidPacket(cid, 1, maxMessage+1, nil))
	if len(*packets) != 1 || (*packets)[0][4] != 0xbf || (*packets)[0][7] != 3 {
		t.Fatal("oversized packet accepted")
	}

	*packets = nil
	h.receive(context.Background(), hidPacket(cid+100, 1, 0, nil))
	if (*packets)[0][7] != 0x0b {
		t.Fatal("unknown channel accepted")
	}
}
func TestHIDContinuation(t *testing.T) {
	h, packets, cid := testHID(t)
	payload := bytes.Repeat([]byte{0x42}, 100)
	h.receive(context.Background(), hidPacket(cid, 1, 100, payload[:57]))
	p := make([]byte, 64)
	binary.BigEndian.PutUint32(p, cid)
	copy(p[5:], payload[57:])
	h.receive(context.Background(), p)
	if len(*packets) != 2 || !bytes.Equal((*packets)[0][7:], payload[:57]) || !bytes.Equal((*packets)[1][5:48], payload[57:]) {
		t.Fatal("fragmented PING failed")
	}
}
func TestHIDCancelAndBusy(t *testing.T) {
	h, packets, cid := testHID(t)
	entered := make(chan struct{})
	h.handle = func(ctx context.Context, _ byte, _ []byte) (byte, []byte) {
		close(entered)
		<-ctx.Done()
		return 0, []byte("stale success")
	}
	h.receive(context.Background(), hidPacket(cid, 0x10, 1, []byte{1}))
	<-entered
	h.receive(context.Background(), hidPacket(cid, 0x10, 1, []byte{1}))
	if len(*packets) != 1 || (*packets)[0][7] != 6 {
		t.Fatal("concurrent request not rejected")
	}

	h.receive(context.Background(), hidPacket(cid, 0x11, 0, nil))
	select {
	case result := <-h.results:
		h.finish(result)
	case <-time.After(time.Second):
		t.Fatal("cancel not delivered")
	}

	last := (*packets)[len(*packets)-1]
	if last[4] != 0x90 || last[7] != 0x2d || binary.BigEndian.Uint16(last[5:7]) != 1 {
		t.Fatal("cancel released successful response")
	}

	if h.job != nil {
		t.Fatal("job not released")
	}
}
func TestUHIDOutputSize(t *testing.T) {
	data := make([]byte, 4099)
	data[4098] = 1
	copy(data, bytes.Repeat([]byte{1}, 64))
	binary.LittleEndian.PutUint16(data[4096:], 64)
	p, err := outputReport(data)
	if err != nil || len(p) != 64 {
		t.Fatalf("%d %v", len(p), err)
	}

	binary.LittleEndian.PutUint16(data[4096:], 4097)
	if _, err := outputReport(data); err == nil {
		t.Fatal("accepted oversized UHID report")
	}
}

func TestHIDResyncWaitsForWorker(t *testing.T) {
	h, packets, cid := testHID(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	h.handle = func(ctx context.Context, _ byte, _ []byte) (byte, []byte) {
		close(entered)
		<-ctx.Done()
		<-release
		return 0, nil
	}
	h.receive(context.Background(), hidPacket(cid, 0x10, 1, []byte{1}))
	<-entered
	h.receive(context.Background(), hidPacket(cid, 6, 8, []byte("87654321")))
	if len(*packets) != 0 {
		close(release)
		t.Fatal("INIT acknowledged before worker released device")
	}

	close(release)
	select {
	case r := <-h.results:
		h.finish(r)
	case <-time.After(time.Second):
		t.Fatal("worker did not finish")
	}

	if len(*packets) != 1 || (*packets)[0][4] != 0x86 {
		t.Fatal("missing resync response")
	}

	h.receive(context.Background(), hidPacket(cid, 1, 0, nil))
	if len(*packets) != 2 || (*packets)[1][4] != 0x81 {
		t.Fatal("device not idle after INIT response")
	}
}

func TestHIDAssemblyErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		code    byte
		timeout bool
	}{
		{"out of sequence", 4, false},
		{"assembly timeout", 5, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, packets, cid := testHID(t)
			h.receive(context.Background(), hidPacket(cid, 1, 100, nil))
			if tc.timeout {
				h.tick(h.assembly.seen.Add(assemblyTimeout))
				if len(*packets) != 0 {
					t.Fatal("assembly expired too early")
				}

				h.tick(h.assembly.seen.Add(assemblyTimeout + time.Nanosecond))
			} else {
				p := make([]byte, 64)
				binary.BigEndian.PutUint32(p, cid)
				p[4] = 1 // First continuation must have sequence zero.
				h.receive(context.Background(), p)
			}

			if h.assembly != nil || len(*packets) != 1 || (*packets)[0][4] != 0xbf || (*packets)[0][7] != tc.code {
				t.Fatalf("bad error response: %x", *packets)
			}

			h.receive(context.Background(), hidPacket(cid, 1, 1, []byte{42}))
			if len(*packets) != 2 || (*packets)[1][4] != 0x81 || (*packets)[1][7] != 42 {
				t.Fatal("channel not reusable after assembly failure")
			}
		})
	}
}

func TestHIDChannelLimit(t *testing.T) {
	h, packets, _ := testHID(t)
	for i := 1; i < 128; i++ {
		h.receive(context.Background(), hidPacket(0xffffffff, 6, 8, []byte("12345678")))
	}

	if len(h.channels) != 128 {
		t.Fatal("channels were not allocated")
	}

	*packets = nil
	h.receive(context.Background(), hidPacket(0xffffffff, 6, 8, []byte("12345678")))
	if len(*packets) != 1 || (*packets)[0][4] != 0x86 || len(h.channels) != 128 {
		t.Fatal("channel limit did not reclaim idle capacity")
	}

	h.tick(time.Now().Add(channelIdleTimeout + time.Second))
	*packets = nil
	h.receive(context.Background(), hidPacket(0xffffffff, 6, 8, []byte("12345678")))
	if len(h.channels) != 1 || len(*packets) != 1 || (*packets)[0][4] != 0x86 {
		t.Fatal("expired channels did not free capacity")
	}
}

func TestHIDMaximumMessage(t *testing.T) {
	h, packets, cid := testHID(t)
	payload := make([]byte, 7609)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	h.receive(context.Background(), hidPacket(cid, 1, len(payload), payload[:57]))
	for seq := 0; seq < 128; seq++ {
		p := make([]byte, 64)
		binary.BigEndian.PutUint32(p, cid)
		p[4] = byte(seq)
		copy(p[5:], payload[57+59*seq:57+59*(seq+1)])
		h.receive(context.Background(), p)
		if seq < 127 && len(*packets) != 0 {
			t.Fatal("response before full message")
		}
	}

	if len(*packets) != 129 || h.assembly != nil {
		t.Fatalf("wrong packet count: %d", len(*packets))
	}

	var received []byte
	for i, p := range *packets {
		if len(p) != 64 || binary.BigEndian.Uint32(p) != cid {
			t.Fatal("bad report header")
		}

		if i == 0 {
			if p[4] != 0x81 || binary.BigEndian.Uint16(p[5:7]) != 7609 {
				t.Fatal("bad initial header")
			}

			received = append(received, p[7:]...)
		} else {
			if p[4] != byte(i-1) {
				t.Fatalf("bad continuation sequence at %d", i)
			}

			received = append(received, p[5:]...)
		}
	}

	if !bytes.Equal(received, payload) {
		t.Fatal("chunked response corrupted payload")
	}
}

func TestInvalidOutputDoesNotInterruptTransport(t *testing.T) {
	h, packets, cid := testHID(t)
	body := make([]byte, uhidOutputBodySize)
	body[uhidOutputTypeOffset] = uhidOutputReport
	for _, size := range []uint16{0, 2, 63, 66, 4096} {
		binary.NativeEndian.PutUint16(body[uhidOutputSizeOffset:], size)
		h.receiveOutput(context.Background(), body)
	}

	h.receiveOutput(context.Background(), body[:3])
	if len(*packets) != 0 || h.err != nil {
		t.Fatal("invalid output affected transport")
	}

	copy(body, hidPacket(cid, cmdPing, 3, []byte("abc")))
	binary.NativeEndian.PutUint16(body[uhidOutputSizeOffset:], reportSize)
	h.receiveOutput(context.Background(), body)
	if len(*packets) != 1 || string((*packets)[0][7:10]) != "abc" {
		t.Fatal("valid request after invalid output failed")
	}

	// Invalid output must not prevent the event loop from completing queued jobs.
	ctx, cancel := context.WithCancel(context.Background())
	job := &hidJob{cid: cid, ctx: ctx, cancel: cancel}
	h.job = job
	h.results <- hidResult{job: job}
	h.receiveOutput(context.Background(), body[:3])
	h.tick(time.Now())
	if h.job != nil || len(*packets) != 2 {
		t.Fatal("queued result not completed")
	}
}

func TestHIDChannelEvictionProtectsTransactions(t *testing.T) {
	for _, assembling := range []bool{false, true} {
		h, _, cid := testHID(t)
		now := time.Now()
		for i := uint32(1); i <= maxChannels; i++ {
			h.channels[i] = now.Add(time.Duration(i) * time.Second)
		}

		h.nextCID = maxChannels
		if assembling {
			h.assembly = &hidAssembly{cid: cid}
		} else {
			h.job = &hidJob{cid: cid}
		}

		h.init(broadcastCID, []byte("12345678"))
		if _, ok := h.channels[cid]; !ok {
			t.Fatal("active channel evicted")
		}

		if _, ok := h.channels[2]; ok {
			t.Fatal("oldest idle channel retained")
		}

		if _, ok := h.channels[maxChannels+1]; !ok {
			t.Fatal("new CID missing")
		}

		if len(h.channels) != maxChannels {
			t.Fatal("channel bound exceeded")
		}
	}
}

func TestHIDWorkerSignalsReadyResult(t *testing.T) {
	h, packets, cid := testHID(t)
	ready := make(chan struct{}, 1)
	h.wake = func() { ready <- struct{}{} }
	h.receive(context.Background(), hidPacket(cid, cmdCBOR, 1, []byte{4}))
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("worker did not wake event loop")
	}

	select {
	case result := <-h.results:
		h.finish(result)
	default:
		t.Fatal("wakeup before result publication")
	}

	if len(*packets) != 1 || (*packets)[0][7] != 0 {
		t.Fatal("result required a timer tick")
	}
}
