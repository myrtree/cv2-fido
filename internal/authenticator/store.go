package authenticator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const (
	maxCredentials    = 64
	storeVersion      = 1
	maxStoreSize      = 1 << 20
	maxWrappedKeySize = 4096
)

type credential struct {
	ID       []byte `json:"id"`
	RP       string `json:"rp"`
	User     []byte `json:"user"`
	Key      []byte `json:"key"` // TPM-wrapped object, not a plaintext private key.
	Resident bool   `json:"resident"`
}

type store struct {
	dir         string
	lock        *os.File
	credentials []credential
	failed      error
}

type diskState struct {
	Version     int          `json:"version"`
	Credentials []credential `json:"credentials"`
}

func privateFile(path string, flags int) (*os.File, error) {
	fd, err := syscall.Open(path, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}

	f := os.NewFile(uintptr(fd), path)
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}

	owner, ok := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || !ok || owner.Uid != uint32(os.Getuid()) {
		_ = f.Close()
		return nil, fmt.Errorf("%s must be a private regular file owned by this user", path)
	}

	return f, nil
}

func openStore(dir string) (*store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}

	st, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}

	owner, ok := st.Sys().(*syscall.Stat_t)
	if !st.IsDir() || st.Mode().Perm()&0077 != 0 || !ok || owner.Uid != uint32(os.Getuid()) {
		return nil, fmt.Errorf("%s must be a private directory owned by this user", dir)
	}

	lock, err := privateFile(filepath.Join(dir, "lock"), syscall.O_RDWR|syscall.O_CREAT)
	if err != nil {
		return nil, err
	}

	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("store already in use: %w", err)
	}

	s := &store{dir: dir, lock: lock}
	f, err := privateFile(filepath.Join(dir, "credentials.json"), syscall.O_RDONLY)
	if errors.Is(err, os.ErrNotExist) {
		// A dangling symlink must not be treated as an empty store.
		if _, lerr := os.Lstat(filepath.Join(dir, "credentials.json")); errors.Is(lerr, os.ErrNotExist) {
			return s, nil
		}
	}

	if err != nil {
		_ = s.Close()
		return nil, err
	}

	defer func() { _ = f.Close() }() // Best-effort cleanup; preserve the operation result.

	var state diskState
	dec := json.NewDecoder(io.LimitReader(f, maxStoreSize))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&state); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("read credentials: %w", err)
	}

	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		_ = s.Close()
		return nil, errors.New("trailing credential data")
	}

	if state.Version != storeVersion || len(state.Credentials) > maxCredentials {
		_ = s.Close()
		return nil, errors.New("unsupported or oversized credential store")
	}

	ids := make(map[string]bool)
	residents := make(map[string]bool)
	for _, c := range state.Credentials {
		if len(c.ID) != credentialIDSize || c.RP == "" || len(c.User) == 0 || len(c.User) > maxUserIDSize || len(c.Key) == 0 || len(c.Key) > maxWrappedKeySize || ids[string(c.ID)] || (c.Resident && residents[c.RP]) {
			_ = s.Close()
			return nil, errors.New("invalid or duplicate credential")
		}

		ids[string(c.ID)] = true
		if c.Resident {
			residents[c.RP] = true
		}
	}

	s.credentials = state.Credentials
	return s, nil
}

func (s *store) Close() error { return s.lock.Close() }

func (s *store) find(rp string, id []byte) *credential {
	for i := range s.credentials {
		c := &s.credentials[i]
		if c.RP == rp && bytes.Equal(c.ID, id) {
			return c
		}
	}

	return nil
}

// save publishes only after the replacement and directory entry are durable.
// The process lock and serialized CTAP handler protect the in-memory snapshot.
func (s *store) save(c credential) error {
	return s.saveWithSync(c, (*os.File).Sync)
}

func (s *store) saveWithSync(c credential, syncDir func(*os.File) error) error {
	if s.failed != nil {
		return s.failed
	}

	next := append(append([]credential(nil), s.credentials...), c)
	data, err := json.Marshal(diskState{Version: storeVersion, Credentials: next})
	if err != nil {
		return err
	}

	f, err := os.CreateTemp(s.dir, ".credentials-*")
	if err != nil {
		return err
	}

	defer func() { _ = os.Remove(f.Name()) }() // Already renamed on success; remove the temporary file on failure.
	defer func() { _ = f.Close() }()           // Best-effort cleanup; preserve the operation result.

	if _, err = f.Write(data); err != nil {
		return err
	}

	if err = f.Sync(); err != nil {
		return err
	}

	if err = f.Close(); err != nil {
		return err
	}

	d, err := os.Open(s.dir)
	if err != nil {
		return err
	}

	defer func() { _ = d.Close() }() // Best-effort cleanup; preserve the operation result.

	if err = os.Rename(f.Name(), filepath.Join(s.dir, "credentials.json")); err != nil {
		return err
	}

	if err = syncDir(d); err != nil {
		s.failed = fmt.Errorf("credential commit uncertain; restart required: %w", err)
		return s.failed
	}

	s.credentials = next
	return nil
}
