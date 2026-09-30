package hid

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestResultWakeupPoll(t *testing.T) {
	wake, err := resultWakeup()
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = wake.Close() }()
	poll := []unix.PollFd{{Fd: int32(wake.Fd()), Events: unix.POLLIN}}
	ready := make(chan error, 1)
	go func() {
		var value [8]byte
		binary.NativeEndian.PutUint64(value[:], 1)
		_, err := wake.Write(value[:])
		ready <- err
	}()
	n, err := unix.Poll(poll, 1000)
	if err != nil || n != 1 || poll[0].Revents&unix.POLLIN == 0 {
		t.Fatalf("wakeup: n=%d err=%v", n, err)
	}

	if err := <-ready; err != nil {
		t.Fatal(err)
	}

	var value [8]byte
	if _, err := wake.Read(value[:]); err != nil {
		t.Fatal(err)
	}

	if n, err := unix.Poll(poll, 0); err != nil || n != 0 {
		t.Fatalf("wakeup not drained: n=%d err=%v", n, err)
	}

	if err := wake.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := wake.Write(value[:]); err == nil {
		t.Fatal("late write to closed wakeup succeeded")
	}
}

func TestCancelAfterWorkerCompletion(t *testing.T) {
	h, packets, cid := testHID(t)
	h.receive(context.Background(), hidPacket(cid, cmdCBOR, 1, []byte{4}))
	var result hidResult
	select {
	case result = <-h.results:
	case <-time.After(time.Second):
		t.Fatal("worker did not finish")
	}

	h.receive(context.Background(), hidPacket(cid, cmdCancel, 0, nil))
	h.finish(result)
	if len(*packets) != 1 || (*packets)[0][7] != 0x2d {
		t.Fatal("completed result bypassed cancellation")
	}
}
