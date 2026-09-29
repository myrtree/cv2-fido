// Package notification bridges the isolated service to desktop notifications.
// The desktop helper is not a trusted approval mechanism and never receives keys.
package notification

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const SocketPath = "/run/cv2-fido/notify.sock"

const (
	agentWait      = 2 * time.Second
	retryInterval  = 2 * time.Second
	maxRequestSize = 2048
)

type Request struct {
	RP     string
	Action string
}

// Text uses ASCII RP IDs without markup or control characters. This is a
// client-supplied RP ID, not an authenticated browser/process identity.
func (r Request) Text() (string, error) {
	if len(r.RP) == 0 || len(r.RP) > 253 {
		return "", errors.New("invalid RP ID")
	}

	for _, c := range r.RP {
		valid := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-'
		if !valid {
			return "", errors.New("RP ID must contain only ASCII hostname characters")
		}
	}

	switch r.Action {
	case "authenticate":
		return "Sign-in requested for " + r.RP + ".\nTouch the fingerprint reader only if you started this sign-in.", nil
	case "register":
		return "Security key registration requested for " + r.RP + ".\nTouch the fingerprint reader only if you started this registration.", nil
	default:
		return "", errors.New("invalid notification action")
	}
}

type Broker struct {
	listener *net.UnixListener
	waiting  chan *net.UnixConn
	done     chan struct{}
}

// Listen requires a private service-owned parent directory. The socket permits
// connections from desktop accounts; kernel peer credentials select the owner.
func Listen(path string, ownerUID uint32) (*Broker, error) {
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}

	if err := os.Chmod(path, 0666); err != nil {
		_ = listener.Close()
		return nil, err
	}

	b := &Broker{listener: listener, waiting: make(chan *net.UnixConn, 1), done: make(chan struct{})}
	go func() {
		defer close(b.done)
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}

			uid, err := peerUID(conn)
			if err != nil || uid != ownerUID {
				_ = conn.Close()
				continue
			}

			// A restarted helper replaces its old idle connection. Active requests
			// have already removed their connection from this queue.
			select {
			case old := <-b.waiting:
				_ = old.Close()
			default:
			}

			select {
			case b.waiting <- conn:
			default:
				_ = conn.Close()
			}
		}
	}()
	return b, nil
}

func (b *Broker) Close() {
	_ = b.listener.Close()
	<-b.done
	for {
		select {
		case conn := <-b.waiting:
			_ = conn.Close()
		default:
			return
		}
	}
}

// Show waits for notification delivery before allowing fingerprint verification.
// Close the returned function's connection when verification finishes or cancels.
func (b *Broker) Show(ctx context.Context, rp, action string) (func(), error) {
	r := Request{RP: rp, Action: action}
	if _, err := r.Text(); err != nil {
		return nil, err
	}

	timer := time.NewTimer(agentWait)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-b.done:
		return nil, errors.New("notification broker closed")
	case <-timer.C:
		return nil, errors.New("desktop notification agent is unavailable")
	case conn := <-b.waiting:
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		closeRequest := func() { stop(); _ = conn.Close() }
		if err := conn.SetDeadline(time.Now().Add(agentWait)); err != nil {
			closeRequest()
			return nil, err
		}

		if err := json.NewEncoder(conn).Encode(r); err != nil {
			closeRequest()
			return nil, err
		}

		var ack [1]byte
		if _, err := io.ReadFull(conn, ack[:]); err != nil || ack[0] != 1 {
			closeRequest()
			return nil, errors.New("desktop notification was not delivered")
		}

		if err := ctx.Err(); err != nil {
			closeRequest()
			return nil, err
		}

		return closeRequest, nil
	}
}

func peerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}

	var cred *unix.Ucred
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		cred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}

	if sockErr != nil {
		return 0, sockErr
	}

	return cred.Uid, nil
}

// ServeAgent reconnects after each request. Notification failures never produce
// an acknowledgement, so they cannot silently enable scanning.
func ServeAgent(ctx context.Context, path string, serviceUID uint32, show func(context.Context, Request) (func(), error)) error {
	for ctx.Err() == nil {
		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
		if err == nil {
			client := conn.(*net.UnixConn)
			uid, err := peerUID(client)
			if err == nil && uid == serviceUID {
				err = serveRequest(ctx, client, show)
				_ = client.Close()
				if err == nil {
					continue
				}
			}

			_ = client.Close()
		}

		timer := time.NewTimer(retryInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}

	return ctx.Err()
}

func serveRequest(ctx context.Context, conn net.Conn, show func(context.Context, Request) (func(), error)) error {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	var r Request
	dec := json.NewDecoder(io.LimitReader(conn, maxRequestSize))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return err
	}

	if _, err := r.Text(); err != nil {
		return err
	}

	requestCtx, cancel := context.WithCancel(ctx)
	ended := make(chan struct{})
	go func() {
		var end [1]byte
		_, _ = conn.Read(end[:])
		cancel() // EOF or any unexpected server data ends this request.
		close(ended)
	}()
	defer func() { _ = conn.Close(); cancel(); <-ended }()

	closeNotification, err := show(requestCtx, r)
	if err != nil {
		return err
	}

	defer closeNotification()

	if err := requestCtx.Err(); err != nil {
		return err
	}

	if _, err := conn.Write([]byte{1}); err != nil {
		return err
	}

	// No subsequent command is accepted on this connection, so an old
	// acknowledgement cannot approve a later request.
	<-ended
	return nil
}
