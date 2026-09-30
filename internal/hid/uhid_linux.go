package hid

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// Event types and report kind from linux/uhid.h.
const (
	uhidOutput         = 6
	uhidGetReport      = 9
	uhidGetReportReply = 10
	uhidCreate2        = 11
	uhidInput2         = 12
	uhidSetReport      = 13
	uhidSetReportReply = 14
	uhidOutputReport   = 1
)

// Packed ABI sizes/offsets include the event type except for the OUTPUT body.
const (
	uhidEventTypeSize       = 4
	uhidDataMax             = 4096
	uhidEventSize           = 4380
	uhidOutputSizeOffset    = uhidDataMax
	uhidOutputTypeOffset    = uhidOutputSizeOffset + 2
	uhidOutputBodySize      = uhidOutputTypeOffset + 1
	uhidCreateNameEnd       = 132
	uhidCreateRDSizeOffset  = 260
	uhidCreateBusOffset     = 262
	uhidCreateVendorOffset  = 264
	uhidCreateProductOffset = 268
	uhidCreateDataOffset    = 280
	uhidInputDataOffset     = 6
	uhidControlIDEnd        = 8
	uhidControlReplySize    = 12
)

// FIDO usage page, 64-byte input/output reports. Adapted from tpm-fido.
var reportDescriptor = []byte{
	0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0x09, 0x20,
	0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81, 0x02,
	0x09, 0x21, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91, 0x02, 0xc0,
}

// UHID is a packed native-endian Linux ABI (include/uapi/linux/uhid.h).
// Byte buffers avoid Go struct padding. INPUT2/CREATE2 support short writes.
func writeUHID(f *os.File, event []byte) error {
	n, err := f.Write(event)
	if err != nil {
		return err
	}

	if n != len(event) {
		return io.ErrShortWrite
	}

	return nil
}

func outputReport(body []byte) ([]byte, error) {
	if len(body) < uhidOutputBodySize {
		return nil, errors.New("short UHID_OUTPUT")
	}

	size := int(binary.NativeEndian.Uint16(body[uhidOutputSizeOffset:uhidOutputTypeOffset]))
	if size != reportSize && size != reportSize+1 {
		return nil, fmt.Errorf("unexpected HID report size %d", size)
	}

	if body[uhidOutputTypeOffset] != uhidOutputReport {
		return nil, errors.New("unexpected HID report type")
	}

	return body[:size], nil
}

// Malformed client reports must not tear down the virtual device. Return to
// the event loop so queued results and keepalives are still serviced.
func (h *hidTransport) receiveOutput(ctx context.Context, body []byte) {
	p, err := outputReport(body)
	if err != nil {
		if h.debug != nil {
			h.debug.Printf("discard UHID_OUTPUT: %v", err)
		}

		return
	}

	h.receive(ctx, p)
}

// eventfd wakes poll when a worker publishes its result. os.File keeps a late
// worker write safe if Run has already closed the descriptor during shutdown.
func resultWakeup() (*os.File, error) {
	fd, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		return nil, err
	}

	return os.NewFile(uintptr(fd), "HID result wakeup"), nil
}

// Run exposes a virtual FIDO HID device until cancellation or an I/O error.
func Run(ctx context.Context, handle func(context.Context, byte, []byte) (byte, []byte), logger *log.Logger) error {
	fd, err := unix.Open("/dev/uhid", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open /dev/uhid: %w", err)
	}

	f := os.NewFile(uintptr(fd), "/dev/uhid")
	defer func() { _ = f.Close() }() // Best-effort cleanup; preserve the operation result.

	event := make([]byte, uhidCreateDataOffset+len(reportDescriptor))
	binary.NativeEndian.PutUint32(event, uhidCreate2)
	copy(event[uhidEventTypeSize:uhidCreateNameEnd], "cv2-fido")
	binary.NativeEndian.PutUint16(event[uhidCreateRDSizeOffset:], uint16(len(reportDescriptor)))
	binary.NativeEndian.PutUint16(event[uhidCreateBusOffset:], unix.BUS_USB) // Virtual, not a physical USB token.
	// Deliberately unassigned IDs; access rules match the exact device name.
	binary.NativeEndian.PutUint32(event[uhidCreateVendorOffset:], 0)
	binary.NativeEndian.PutUint32(event[uhidCreateProductOffset:], 0)
	copy(event[uhidCreateDataOffset:], reportDescriptor)
	if err := writeUHID(f, event); err != nil {
		return err
	}

	// Closing the UHID fd destroys the device, including on error or SIGINT.
	h := newHID(func(report []byte) error {
		input := make([]byte, uhidInputDataOffset+len(report))
		binary.NativeEndian.PutUint32(input, uhidInput2)
		binary.NativeEndian.PutUint16(input[uhidEventTypeSize:], uint16(len(report)))
		copy(input[uhidInputDataOffset:], report)
		return writeUHID(f, input)
	}, handle)
	wakeup, err := resultWakeup()
	if err != nil {
		return err
	}

	defer func() { _ = wakeup.Close() }()
	h.wake = func() {
		var value [8]byte
		binary.NativeEndian.PutUint64(value[:], 1)
		_, _ = wakeup.Write(value[:]) // Shutdown may close it before the worker returns.
	}

	h.debug = logger
	defer func() {
		if h.job != nil {
			h.job.cancel()
		}
	}()

	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}, {Fd: int32(wakeup.Fd()), Events: unix.POLLIN}}
	lastTick := time.Now()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		n, err := unix.Poll(poll, int(pollInterval/time.Millisecond))
		if err != nil && !errors.Is(err, unix.EINTR) {
			return err
		}

		if n > 0 && poll[0].Revents != 0 {
			if poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
				return errors.New("UHID disconnected")
			}

			buf := make([]byte, uhidEventSize)
			n, err := unix.Read(fd, buf)
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}

			if err != nil {
				return err
			}

			if n < uhidEventTypeSize {
				return errors.New("short UHID event")
			}

			switch binary.NativeEndian.Uint32(buf) {
			case uhidOutput:
				h.receiveOutput(ctx, buf[uhidEventTypeSize:n])
			case uhidGetReport, uhidSetReport: // GET_REPORT/SET_REPORT: control transfers are unsupported.
				if n < uhidControlIDEnd {
					return errors.New("short UHID control request")
				}

				reply := make([]byte, uhidControlReplySize)
				kind := uint32(uhidGetReportReply)
				if binary.NativeEndian.Uint32(buf) == uhidSetReport {
					kind = uhidSetReportReply
				}

				binary.NativeEndian.PutUint32(reply, kind)
				copy(reply[uhidEventTypeSize:uhidControlIDEnd], buf[uhidEventTypeSize:uhidControlIDEnd])
				binary.NativeEndian.PutUint16(reply[uhidControlIDEnd:], uint16(unix.EIO))
				if err := writeUHID(f, reply); err != nil {
					return err
				}
			}
		}

		if n > 0 && poll[1].Revents&unix.POLLIN != 0 {
			var value [8]byte
			if _, err := wakeup.Read(value[:]); err != nil {
				return err
			}

			select {
			case result := <-h.results:
				h.finish(result)
			default: // A periodic tick may already have handled this result.
			}
		}

		if now := time.Now(); now.Sub(lastTick) >= pollInterval {
			h.tick(now)
			lastTick = now
		}

		if h.err != nil {
			return h.err
		}
	}
}
