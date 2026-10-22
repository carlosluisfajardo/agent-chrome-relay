// Package relayauth authenticates every extension command against a public key pinned at setup.
package relayauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func Load(home string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(filepath.Join(home, "extension-signing-key"))
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid extension signing key; restore its setup backup")
	}
	return ed25519.PrivateKey(b), nil
}

// Provision never replaces an existing key. Only the public half goes in the extension directory.
func Provision(home string) (string, error) {
	key, err := Load(home)
	if errors.Is(err, os.ErrNotExist) {
		_, key, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return "", err
		}
		f, e := os.OpenFile(filepath.Join(home, "extension-signing-key"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return "", e
		}
		_, err = f.Write(key)
		closeErr := f.Close()
		if err == nil {
			err = closeErr
		}
	}
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), nil
}

func Envelope(key ed25519.PrivateKey, nonce string, sequence int, command any) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("extension authentication is not set up")
	}
	payload, err := json.Marshal(struct {
		Nonce    string `json:"nonce"`
		Sequence int    `json:"sequence"`
		Command  any    `json:"command"`
	}{nonce, sequence, command})
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]string{"payload": string(payload), "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, payload))})
}
