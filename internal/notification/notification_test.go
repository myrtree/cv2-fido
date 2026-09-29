package notification

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestRequestText(t *testing.T) {
	for _, rp := range []string{"example.com", "xn--e1afmkfd.xn--p1ai", "localhost"} {
		text, err := (Request{RP: rp, Action: "authenticate"}).Text()
		if err != nil || !strings.Contains(text, rp) {
			t.Fatal(text, err)
		}
	}

	for _, rp := range []string{"", "a\nb", "<b>example.com</b>", "example.com\u202e", "https://example.com", strings.Repeat("a", 254)} {
		if _, err := (Request{RP: rp, Action: "authenticate"}).Text(); err == nil {
			t.Fatal("accepted misleading RP", rp)
		}
	}

	if _, err := (Request{RP: "example.com", Action: "arbitrary"}).Text(); err == nil {
		t.Fatal("accepted unknown action")
	}
}

func TestNotificationLifecycle(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "delivered", true: "unavailable"}[fail], func(t *testing.T) {
			server, client := net.Pipe()
			defer func() { _ = server.Close(); _ = client.Close() }()

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			closed := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				done <- serveRequest(ctx, client, func(context.Context, Request) (func(), error) {
					if fail {
						return nil, errors.New("no notification daemon")
					}

					return func() { close(closed) }, nil
				})
				_ = client.Close()
			}()
			if err := json.NewEncoder(server).Encode(Request{RP: "example.com", Action: "authenticate"}); err != nil {
				t.Fatal(err)
			}

			var ack [1]byte
			_, err := io.ReadFull(server, ack[:])
			if fail {
				if err == nil {
					t.Fatal("failed notification acknowledged")
				}
			} else {
				if err != nil || ack[0] != 1 {
					t.Fatal("missing delivery acknowledgement", err)
				}

				_ = server.Close()
			}

			select {
			case err := <-done:
				if (err != nil) != fail {
					t.Fatal("unexpected lifecycle result", err)
				}
			case <-ctx.Done():
				t.Fatal("notification helper did not finish")
			}

			if !fail {
				select {
				case <-closed:
				default:
					t.Fatal("notification was not closed")
				}
			}
		})
	}
}
