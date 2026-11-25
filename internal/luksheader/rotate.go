// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

//go:build ceph_luks_header_session

package luksheader

import (
	"bytes"
	"errors"
	"fmt"
	"syscall"

	"github.com/ceph/go-ceph/rbd"
	"github.com/ironcore-dev/ceph-provider/internal/cryptsetup"
)

// ErrSamePassphrase is returned by Rotate when the old and the new
// passphrase are equal.
var ErrSamePassphrase = errors.New("luksheader: old and new passphrase are the same")

// keyslotCost is the key derivation of the keyslot that Rotate adds. It is
// fixed, so the memory a rotation needs for it is the same on every host.
var keyslotCost = cryptsetup.PBKDF{
	Type:       cryptsetup.Argon2id,
	Iterations: 4,
	MemoryKiB:  64 * 1024,
	Threads:    4,
}

// Rotate replaces the passphrase of the image in two changes of its
// header. The first adds a keyslot for newPassphrase. The second checks
// newPassphrase on the header as the image has it now and removes the
// keyslot of oldPassphrase. Between the two both passphrases open the
// image.
//
// After an error Rotate can be called again with the same passphrases. It
// skips what the call before it has done. The note on img at Change holds
// here too.
func Rotate(img *rbd.Image, oldPassphrase, newPassphrase []byte) error {
	if bytes.Equal(oldPassphrase, newPassphrase) {
		return ErrSamePassphrase
	}

	added := -1
	err := Change(img, func(dev *cryptsetup.Device) error {
		var err error
		added, err = dev.CheckPassphrase(cryptsetup.AnyKeyslot, newPassphrase)
		if err == nil {
			// a call before this one added the keyslot
			return nil
		}
		if !errors.Is(err, syscall.EPERM) {
			return fmt.Errorf("check new passphrase: %w", err)
		}
		if err := dev.SetPBKDF(keyslotCost); err != nil {
			return fmt.Errorf("set key derivation: %w", err)
		}
		added, err = dev.AddKeyslot(cryptsetup.AnyKeyslot, oldPassphrase, newPassphrase)
		return err
	})
	if err != nil {
		return fmt.Errorf("add keyslot for new passphrase: %w", err)
	}

	err = Change(img, func(dev *cryptsetup.Device) error {
		if _, err := dev.CheckPassphrase(added, newPassphrase); err != nil {
			return fmt.Errorf("check new passphrase on keyslot %d: %w", added, err)
		}
		old, err := dev.CheckPassphrase(cryptsetup.AnyKeyslot, oldPassphrase)
		if errors.Is(err, syscall.EPERM) {
			// a call before this one removed the keyslot
			return nil
		}
		if err != nil {
			return fmt.Errorf("find keyslot of old passphrase: %w", err)
		}
		return dev.RemoveKeyslot(old)
	})
	if err != nil {
		return fmt.Errorf("remove keyslot of old passphrase: %w", err)
	}
	return nil
}
