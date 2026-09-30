package main

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const serviceUser = "cv2-fido"
const ownerGroup = "cv2-fido-users"

func configuredOwner(name string) (uint32, error) {
	if name == "" {
		return 0, configurationError("set CV2_FIDO_USER in /etc/cv2-fido.conf; see README.md")
	}

	service, err := lookupAccount(serviceUser)
	if err != nil {
		return 0, fmt.Errorf("service account: %w", err)
	}

	owner, err := lookupAccount(name)
	if err != nil {
		return 0, fmt.Errorf("fingerprint owner: %w", err)
	}

	if owner.Username != name {
		return 0, configurationError("use the owner's canonical username")
	}

	serviceID, err := strconv.ParseUint(service.Uid, 10, 32)
	if err != nil {
		return 0, err
	}

	ownerID, err := strconv.ParseUint(owner.Uid, 10, 32)
	if err != nil {
		return 0, err
	}

	group, err := user.LookupGroup(ownerGroup)
	if err != nil {
		return 0, fmt.Errorf("protected owner group: %w", err)
	}

	groups, err := owner.GroupIds()
	if err != nil {
		return 0, err
	}

	if slices.Contains(groups, service.Gid) {
		return 0, configurationError("desktop owner must not belong to the private cv2-fido service group")
	}

	if err := validateIdentity(uint32(os.Geteuid()), uint32(serviceID), uint32(ownerID), slices.Contains(groups, group.Gid)); err != nil {
		return 0, err
	}

	return uint32(ownerID), nil
}

// Unknown accounts require configuration changes; lookup failures may be temporary.
func lookupAccount(name string) (*user.User, error) {
	account, err := user.Lookup(name)
	var unknown user.UnknownUserError
	if errors.As(err, &unknown) {
		return nil, fmt.Errorf("%w: %w", errConfiguration, err)
	}

	return account, err
}

// Old uaccess ACLs can survive a udev rule reload. Refuse to start until device
// isolation is effective; a reboot is still needed to revoke already-open FDs.
func checkDeviceIsolation(device string) error {
	raw, err := rawTPMDevice(device)
	if err != nil {
		return err
	}

	group, err := user.LookupGroup(serviceUser)
	if err != nil {
		return err
	}

	gid, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil {
		return err
	}

	for _, path := range []string{device, "/dev/uhid", raw} {
		st, err := os.Lstat(path)
		if path == raw && errors.Is(err, os.ErrNotExist) {
			continue
		}

		if err != nil {
			return err
		}

		size, err := unix.Getxattr(path, "system.posix_acl_access", nil)
		if err != nil && !errors.Is(err, unix.ENODATA) {
			return fmt.Errorf("device ACL %s: %w", path, err)
		}

		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("cannot inspect owner of %s", path)
		}

		allowed := privateDevice(owner.Uid, owner.Gid, st.Mode(), size > 0, uint32(gid))
		if path == raw {
			allowed = owner.Uid == 0 && st.Mode()&os.ModeCharDevice != 0 && st.Mode().Perm()&0077 == 0 && size <= 0
		}

		if !allowed {
			return fmt.Errorf("%w: %s is not isolated; check udev rules and reboot (see README.md)", errConfiguration, path)
		}
	}

	return nil
}

func rawTPMDevice(device string) (string, error) {
	index, ok := strings.CutPrefix(device, "/dev/tpmrm")
	if _, err := strconv.ParseUint(index, 10, 32); !ok || err != nil {
		return "", configurationError("TPM must be a /dev/tpmrmN resource-manager device")
	}

	return "/dev/tpm" + index, nil
}

func privateDevice(uid, gid uint32, mode os.FileMode, hasACL bool, serviceGID uint32) bool {
	return uid == 0 && gid == serviceGID && mode&os.ModeCharDevice != 0 && mode.Perm() == 0660 && !hasACL
}

func validateIdentity(process, service, owner uint32, protected bool) error {
	if process == 0 || service == 0 || process != service {
		return configurationError("run under the cv2-fido service account using the system service")
	}

	if owner == 0 || owner == service {
		return configurationError("fingerprint owner must be a separate non-root desktop user")
	}

	if !protected {
		return configurationError("fingerprint owner must belong to cv2-fido-users; see README.md")
	}

	return nil
}
