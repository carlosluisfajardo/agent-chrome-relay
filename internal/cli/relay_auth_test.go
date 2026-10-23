package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
)

func TestUpdatePairsAndReloadsBeforeRestart(t *testing.T) {
	home := t.TempDir()
	ext := filepath.Join(home, "extension")
	os.Mkdir(ext, 0700)
	os.WriteFile(filepath.Join(home, "token"), []byte("dummy-test-token"), 0600)
	// This owned executable is the only launchctl on PATH; no service is touched.
	bin := filepath.Join(home, "bin")
	os.Mkdir(bin, 0700)
	started := filepath.Join(home, "started")
	os.WriteFile(filepath.Join(bin, "launchctl"), []byte("#!/bin/sh\nprintf started > '"+started+"'\n"), 0700)
	t.Setenv("PATH", bin)
	var orderError string
	var orderMu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/status" {
			fmt.Fprint(w, `{"profiles":["me@example.test"],"agents":[],"extensionAuth":"ed25519-v1"}`)
			return
		}
		if r.URL.Path == "/reload-extensions" {
			orderMu.Lock()
			defer orderMu.Unlock()
			if _, e := os.Stat(started); e == nil {
				orderError = "restart happened before old extension reload"
			}
			b, _ := os.ReadFile(filepath.Join(ext, "relay.json"))
			var config map[string]any
			json.Unmarshal(b, &config)
			if config["publicKey"] == nil {
				orderError = "reload happened before public-key provisioning"
			}
			fmt.Fprint(w, `{"reloading":["me@example.test"]}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	var output bytes.Buffer
	c := &cli{instance: instance{Home: home, Ext: ext, Port: port, Name: "fixture", Label: "fixture", Plist: filepath.Join(home, "absent.plist")}, args: []string{"fixture", "update"}, out: &output, errw: &output}
	if err := c.update(); err != nil {
		t.Fatal(err)
	}
	orderMu.Lock()
	defer orderMu.Unlock()
	if orderError != "" {
		t.Fatal(orderError)
	}
	if _, err := os.Stat(started); err != nil {
		t.Fatal("restart not requested")
	}
}

func TestPasskeyOffOnChangesRevocationEpoch(t *testing.T) {
	home := t.TempDir()
	var out bytes.Buffer
	c := &cli{instance: instance{Home: home, Name: "fixture"}, args: []string{"fixture", "passkeys", "off"}, out: &out, errw: &out}
	if err := c.passkeys(); err != nil {
		t.Fatal(err)
	}
	first := c.config().obj("passkeys").get("epoch")
	c.args[2] = "on"
	if err := c.passkeys(); err != nil {
		t.Fatal(err)
	}
	second := c.config().obj("passkeys").get("epoch")
	if first == nil || second == nil || first == second {
		t.Fatal("off/on did not revoke the old passkey epoch")
	}
}
