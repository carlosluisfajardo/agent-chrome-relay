package relayauth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedCommandsAndProvisioning(t *testing.T) {
	home := t.TempDir()
	public, err := Provision(home)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Provision(home)
	if err != nil || public != again {
		t.Fatal("provisioning replaced existing pin")
	}
	key, err := Load(home)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(filepath.Join(home, "extension-signing-key"))
	if st.Mode().Perm() != 0600 {
		t.Fatal("signing key not private")
	}
	b, err := Envelope(key, "nonce", 1, map[string]any{"op": "create"})
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]string
	json.Unmarshal(b, &envelope)
	signature, _ := base64.RawURLEncoding.DecodeString(envelope["signature"])
	pub, _ := base64.RawURLEncoding.DecodeString(public)
	if !ed25519.Verify(pub, []byte(envelope["payload"]), signature) {
		t.Fatal("server signature invalid")
	}
	if ed25519.Verify(pub, []byte(envelope["payload"]+" "), signature) {
		t.Fatal("tampered payload verified")
	}
	if _, err := Envelope(nil, "nonce", 1, nil); err == nil {
		t.Fatal("unpaired command accepted")
	}
	os.WriteFile(filepath.Join(home, "extension-signing-key"), []byte("corrupt fixture"), 0600)
	if _, err := Provision(home); err == nil {
		t.Fatal("corrupt key silently replaced")
	}
}
