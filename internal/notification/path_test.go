package notification

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSocketDirectory(t *testing.T) {
	for _, mode := range []string{"private", "readable", "writable", "symlink", "symlink ancestor"} {
		t.Run(mode, func(t *testing.T) {
			base := socketTestDirectory(t)
			dir := filepath.Join(base, "runtime")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}

			switch mode {
			case "readable":
				if err := os.Chmod(dir, 0755); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := os.Chmod(dir, 0777); err != nil {
					t.Fatal(err)
				}
			case "symlink", "symlink ancestor":
				link := filepath.Join(base, "link")
				if err := os.Symlink(dir, link); err != nil {
					t.Fatal(err)
				}

				dir = link
				if mode == "symlink ancestor" {
					dir = filepath.Join(link, "child")
					if err := os.Mkdir(dir, 0700); err != nil {
						t.Fatal(err)
					}
				}
			}

			err := socketDirectory(filepath.Join(dir, "notify.sock"))
			want := mode == "private" || mode == "readable"
			if (err == nil) != want {
				t.Fatalf("allowed=%v err=%v", want, err)
			}
		})
	}
}

// MkdirTemp creates a private directory even when the runner uses a permissive
// umask. Use one level so the test does not depend on testing's parent modes.
func socketTestDirectory(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cv2-fido-socket-")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return dir
}
