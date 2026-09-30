package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/user"
	"testing"
)

func TestCLIUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"unknown"}, {"run", "--bogus"}, {"run", "unexpected"}} {
		var out bytes.Buffer
		if err := run(context.Background(), args, &out); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}

	var out bytes.Buffer
	if err := run(context.Background(), []string{"--help"}, &out); err != nil {
		t.Fatal(err)
	}

	if !bytes.Contains(out.Bytes(), []byte("doctor")) {
		t.Fatal("missing usage")
	}
}

func TestExitStatus(t *testing.T) {
	t.Setenv("CV2_FIDO_USER", "")
	err := run(context.Background(), []string{"run"}, &bytes.Buffer{})
	if got := exitStatus(err); got != 78 {
		t.Fatalf("empty owner: status=%d err=%v", got, err)
	}

	for _, tc := range []struct {
		err  error
		want int
	}{
		{nil, 0}, {context.Canceled, 0},
		{errors.New("temporary backend failure"), 1},
		{context.DeadlineExceeded, 1},
		{fmt.Errorf("wrapped: %w", err), 78},
		{validateIdentity(0, 990, 1000, true), 78},
	} {
		if got := exitStatus(tc.err); got != tc.want {
			t.Fatalf("error=%v status=%d want=%d", tc.err, got, tc.want)
		}
	}
}

func TestUnknownAccountIsConfigurationError(t *testing.T) {
	_, err := lookupAccount("cv2-fido-test-nonexistent-account-!invalid!")
	var unknown user.UnknownUserError
	if exitStatus(err) != exitConfig || !errors.As(err, &unknown) {
		t.Fatalf("unknown account: %v (status %d)", err, exitStatus(err))
	}
}
