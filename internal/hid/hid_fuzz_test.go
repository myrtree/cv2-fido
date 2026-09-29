package hid

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"
)

func FuzzHIDSequence(f *testing.F) {
	init := hidPacket(0xffffffff, 6, 8, []byte("12345678"))
	request := hidPacket(1, 0x10, 1, []byte{2})
	cancel := hidPacket(1, 0x11, 0, nil)
	resync := hidPacket(1, 6, 8, []byte("87654321"))
	continuation := make([]byte, 64)
	binary.BigEndian.PutUint32(continuation, 1)
	f.Add([]byte{})
	f.Add(init)
	f.Add(hidPacket(1, 1, 3, []byte("abc")))
	f.Add(append(hidPacket(1, 1, 100, nil), continuation...))
	f.Add(append(bytes.Clone(request), cancel...))
	f.Add(append(bytes.Clone(request), resync...))
	f.Add(append(hidPacket(1, 1, 7609, nil), cancel...))
	f.Add(hidPacket(1, 1, 7610, nil))
	f.Add(append([]byte{0}, request...)) // Optional zero report ID.
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 64*256 {
			return
		}

		h := newHID(func(p []byte) error {
			if len(p) != 64 {
				t.Fatal("invalid output report size", len(p))
			}

			// Workers below only finish after cancellation. Their dummy successful
			// result must be suppressed (INIT) or replaced by a cancellation status.
			if p[4] == 0x90 && (p[7] == 0 || binary.BigEndian.Uint16(p[5:7]) != 1) {
				t.Fatal("cancelled worker released a successful response")
			}

			return nil
		}, func(ctx context.Context, _ byte, _ []byte) (byte, []byte) {
			<-ctx.Done()
			return 0, []byte("stale success")
		})
		drain := func() {
			if h.job == nil {
				return
			}

			h.job.cancel()
			select {
			case result := <-h.results:
				h.finish(result)
			case <-time.After(time.Second):
				t.Fatal("worker did not stop after cancellation")
			}
		}
		defer drain()

		h.receive(context.Background(), init) // Allocate known channel 1.
		// Feed the complete input too, to cover short/long reports and report IDs.
		h.receive(context.Background(), input)
		drain()
		for len(input) > 0 {
			n := min(64, len(input))
			h.receive(context.Background(), input[:n])
			input = input[n:]
			if len(h.channels) > 128 {
				t.Fatal("channel limit exceeded")
			}

			if a := h.assembly; a != nil && (len(a.data) > a.total || a.total > 7609) {
				t.Fatal("assembly bounds exceeded")
			}
		}

		drain()
		h.tick(time.Now().Add(6 * time.Minute))
		if h.job != nil || h.assembly != nil || len(h.channels) != 0 {
			t.Fatal("transport did not release expired state")
		}
	})
}

func FuzzUHIDOutput(f *testing.F) {
	for _, size := range []uint16{0, 64, 65, 4097} {
		f.Add([]byte{0x42}, size, byte(1), uint16(4099))
	}

	f.Add([]byte{}, uint16(64), byte(1), uint16(4098))
	f.Add([]byte{}, uint16(64), byte(0), uint16(4099))
	f.Fuzz(func(t *testing.T, payload []byte, size uint16, kind byte, bodySize uint16) {
		if len(payload) > 8192 || bodySize > 8192 {
			return
		}

		// Mutate fields separately so reaching the size/type checks does not
		// require the fuzzer to preserve a 4096-byte prefix.
		body := make([]byte, int(bodySize))
		copy(body, payload)
		if len(body) >= 4099 {
			binary.NativeEndian.PutUint16(body[4096:4098], size)
			body[4098] = kind
		}

		p, err := outputReport(body)
		valid := len(body) >= 4099 && kind == 1 && (size == 64 || size == 65)
		if (err == nil) != valid {
			t.Fatal("incorrect UHID acceptance")
		}

		if err == nil && (!bytes.Equal(p, body[:len(p)]) || len(p) != int(size)) {
			t.Fatal("output report differs from declared payload")
		}
	})
}
