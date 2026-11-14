package main

import (
	"errors"
	"os"
)

// fileStore keeps the device state in a file, replaced atomically.
type fileStore string

func (f fileStore) Load() ([]byte, error) {
	b, err := os.ReadFile(string(f))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

func (f fileStore) Save(b []byte) error {
	tmp := string(f) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, string(f))
}
