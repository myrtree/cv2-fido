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
