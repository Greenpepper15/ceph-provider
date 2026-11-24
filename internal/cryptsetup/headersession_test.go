// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

//go:build ceph_luks_header_session

package cryptsetup_test

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ceph/go-ceph/rados"
	"github.com/ceph/go-ceph/rbd"
	"github.com/ironcore-dev/ceph-provider/internal/cryptsetup"
)

func luks2(passphrase []byte) rbd.EncryptionOptionsLUKS2 {
	return rbd.EncryptionOptionsLUKS2{
		Alg:        rbd.EncryptionAlgorithmAES256,
		Passphrase: passphrase,
	}
}

// loads reports whether librbd opens the encryption of the image with
// the passphrase.
func loads(t *testing.T, ioctx *rados.IOContext, name string, passphrase []byte) error {
	t.Helper()
	img, err := rbd.OpenImage(ioctx, name, rbd.NoSnapshot)
	if err != nil {
		t.Fatalf("open image: %v", err)
	}
	defer func() { _ = img.Close() }()
	return img.EncryptionLoad(luks2(passphrase))
}

// changeHeader stages the LUKS header of the image through librbd, lets
// change edit it with libcryptsetup and writes it back.
func changeHeader(t *testing.T, ioctx *rados.IOContext, name string, change func(dev *cryptsetup.Device)) {
	t.Helper()
	img, err := rbd.OpenImage(ioctx, name, rbd.NoSnapshot)
	if err != nil {
		t.Fatalf("open image: %v", err)
	}
	defer func() { _ = img.Close() }()

	hdr, err := img.EncryptionLUKSHeaderOpen()
	if err != nil {
		t.Fatalf("open header session: %v", err)
	}
	defer func() { _ = hdr.Close() }()

	dev, err := cryptsetup.Open(fmt.Sprintf("/proc/self/fd/%d", hdr.Fd()))
	if err != nil {
		t.Fatalf("load staged header: %v", err)
	}
	change(dev)
	// libcryptsetup lets go of the file before librbd reads it
	dev.Close()

	// no other client gets the lock between two writes of the header
	if err := img.LockAcquire(rbd.LockModeExclusiveTransient); err != nil {
		t.Fatalf("acquire lock: %v", err)
	}
	if err := hdr.Commit(); err != nil {
		t.Errorf("commit header: %v", err)
	}
	if err := img.LockRelease(); err != nil {
		t.Errorf("release lock: %v", err)
	}
}

// A passphrase is replaced on an RBD image in two commits: the new
// keyslot is added and checked, then the old one is removed. Needs a
// Ceph cluster whose librbd has the header session, named by
// CEPH_CONFIG_FILE.
func TestHeaderSession(t *testing.T) {
	conf := os.Getenv("CEPH_CONFIG_FILE")
	if conf == "" {
		t.Skip("CEPH_CONFIG_FILE is not set")
	}

	conn, err := rados.NewConn()
	if err != nil {
		t.Fatalf("new connection: %v", err)
	}
	if err := conn.ReadConfigFile(conf); err != nil {
		t.Fatalf("read %s: %v", conf, err)
	}
	if err := conn.Connect(); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Shutdown()

	pool := fmt.Sprintf("cryptsetup-test-%d", time.Now().UnixNano())
	if err := conn.MakePool(pool); err != nil {
		t.Fatalf("create pool: %v", err)
	}
	defer func() { _ = conn.DeletePool(pool) }()
	ioctx, err := conn.OpenIOContext(pool)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	defer ioctx.Destroy()

	const name = "volume"
	if err := rbd.CreateImage(ioctx, name, 64<<20, rbd.NewRbdImageOptions()); err != nil {
		t.Fatalf("create image: %v", err)
	}
	img, err := rbd.OpenImage(ioctx, name, rbd.NoSnapshot)
	if err != nil {
		t.Fatalf("open image: %v", err)
	}
	err = img.EncryptionFormat(luks2(oldPassphrase))
	_ = img.Close()
	if err != nil {
		t.Fatalf("format image: %v", err)
	}

	added := -1
	changeHeader(t, ioctx, name, func(dev *cryptsetup.Device) {
		if err := dev.SetPBKDF(fixedCost); err != nil {
			t.Fatalf("set PBKDF: %v", err)
		}
		added, err = dev.AddKeyslot(cryptsetup.AnyKeyslot, oldPassphrase, newPassphrase)
		if err != nil {
			t.Fatalf("add keyslot: %v", err)
		}
	})
	if err := loads(t, ioctx, name, newPassphrase); err != nil {
		t.Fatalf("new passphrase after add: %v", err)
	}
	if err := loads(t, ioctx, name, oldPassphrase); err != nil {
		t.Errorf("old passphrase after add: %v", err)
	}

	changeHeader(t, ioctx, name, func(dev *cryptsetup.Device) {
		// the header that came back from the image has the new keyslot
		keyslots, err := dev.Keyslots()
		if err != nil {
			t.Fatalf("list keyslots: %v", err)
		}
		if len(keyslots) != 2 || keyslots[1].ID != added || keyslots[1].PBKDF != fixedCost {
			t.Errorf("keyslots after add: got %+v, want keyslot %d with %+v", keyslots, added, fixedCost)
		}
		if slot, err := dev.CheckPassphrase(added, newPassphrase); err != nil || slot != added {
			t.Fatalf("new passphrase on keyslot %d: keyslot %d, err %v", added, slot, err)
		}
		old, err := dev.CheckPassphrase(cryptsetup.AnyKeyslot, oldPassphrase)
		if err != nil {
			t.Fatalf("find the old keyslot: %v", err)
		}
		if err := dev.RemoveKeyslot(old); err != nil {
			t.Fatalf("remove keyslot %d: %v", old, err)
		}
	})
	if err := loads(t, ioctx, name, newPassphrase); err != nil {
		t.Errorf("new passphrase after remove: %v", err)
	}
	if err := loads(t, ioctx, name, oldPassphrase); err == nil {
		t.Error("old passphrase after remove: image still loads")
	}
}
