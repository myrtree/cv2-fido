package notification

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// The socket is public, but only the service may create or replace its pathname.
// Root-owned sticky ancestors (e.g. /tmp in tests) protect owned descendants.
func socketDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("socket path must be absolute and clean: %s", path)
	}

	parent := filepath.Dir(path)
	for dir := parent; ; dir = filepath.Dir(dir) {
		st, err := os.Lstat(dir)
		if err != nil {
			return fmt.Errorf("socket directory: %w", err)
		}

		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || !st.IsDir() || (owner.Uid != 0 && owner.Uid != uint32(os.Geteuid())) {
			return fmt.Errorf("untrusted socket directory: %s", dir)
		}

		if dir == parent && owner.Uid != uint32(os.Geteuid()) {
			return fmt.Errorf("socket directory must belong to the service: %s", dir)
		}

		stickyAncestor := dir != parent && owner.Uid == 0 && st.Mode()&os.ModeSticky != 0
		if st.Mode().Perm()&0022 != 0 && !stickyAncestor {
			return fmt.Errorf("socket directory is writable by other users: %s", dir)
		}

		if dir == "/" {
			return nil
		}
	}
}
