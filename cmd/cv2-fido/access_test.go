package main

import (
	"os"
	"testing"
)

func TestDevicePermissions(t *testing.T) {
	for _, tt := range []struct {
		name     string
		uid, gid uint32
		mode     os.FileMode
		acl      bool
		want     bool
	}{
		{"private service device", 0, 990, os.ModeDevice | os.ModeCharDevice | 0660, false, true},
		{"old desktop ACL", 0, 990, os.ModeDevice | os.ModeCharDevice | 0660, true, false},
		{"world access", 0, 990, os.ModeDevice | os.ModeCharDevice | 0666, false, false},
		{"other group", 0, 1000, os.ModeDevice | os.ModeCharDevice | 0660, false, false},
		{"desktop owner", 1000, 990, os.ModeDevice | os.ModeCharDevice | 0660, false, false},
		{"regular file", 0, 990, 0660, false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := privateDevice(tt.uid, tt.gid, tt.mode, tt.acl, 990); got != tt.want {
				t.Fatalf("allowed=%v want=%v", got, tt.want)
			}
		})
	}
}

func TestRawTPMDevice(t *testing.T) {
	for _, tt := range []struct{ device, raw string }{
		{"/dev/tpmrm0", "/dev/tpm0"},
		{"/dev/tpmrm1", "/dev/tpm1"},
		{"/dev/tpm0", ""},
		{"/tmp/tpm.sock", ""},
		{"/dev/tpmrm../uhid", ""},
		{"/dev/tpmrm", ""},
	} {
		t.Run(tt.device, func(t *testing.T) {
			got, err := rawTPMDevice(tt.device)
			if got != tt.raw || (err == nil) != (tt.raw != "") {
				t.Fatalf("raw=%q err=%v", got, err)
			}
		})
	}
}

func TestServiceIdentity(t *testing.T) {
	for _, tt := range []struct {
		name                    string
		process, service, owner uint32
		member                  bool
		want                    bool
	}{
		{"service", 990, 990, 1000, true, true},
		{"desktop process", 1000, 990, 1000, true, false},
		{"root process", 0, 990, 1000, true, false},
		{"root service", 0, 0, 1000, true, false},
		{"root owner", 990, 990, 0, true, false},
		{"service owner", 990, 990, 990, true, false},
		{"unprotected owner", 990, 990, 1000, false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := validateIdentity(tt.process, tt.service, tt.owner, tt.member)
			if (err == nil) != tt.want {
				t.Fatalf("err=%v, want allowed=%v", err, tt.want)
			}
		})
	}
}
