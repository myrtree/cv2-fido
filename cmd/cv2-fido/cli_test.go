package main

import (
	"bytes"
	"context"
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
