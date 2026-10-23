package relay

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	op "github.com/1password/onepassword-sdk-go"
	"github.com/aindeev/agent-chrome-relay/internal/vault"
)

func TestAuditCookieNetworkBoundary(t *testing.T) {
	h := newHarness(t)
	f := h.extension("me@example.com")
	a := h.agent("me@example.com")
	sid, tab := openTab(a, 1)
	const secret = "dummy-http-only-session"
	for i, tc := range []struct {
		name, method string
		params       any
	}{
		{"interception", "Fetch.enable", map[string]any{}},
		{"response array", "Fetch.fulfillRequest", map[string]any{"requestId": "r", "responseCode": 200, "responseHeaders": []any{map[string]any{"name": "sEt-CoOkIe", "value": "SID=" + secret + "; HttpOnly"}}}},
		{"response binary", "Fetch.fulfillRequest", map[string]any{"requestId": "r", "responseCode": 200, "binaryResponseHeaders": base64.StdEncoding.EncodeToString([]byte("Set-Cookie: SID=" + secret + "; HttpOnly\x00"))}},
		{"continue response", "Fetch.continueResponse", map[string]any{"requestId": "r", "responseCode": 200, "responseHeaders": []any{map[string]any{"name": "Set-Cookie", "value": "SID=; Max-Age=0; HttpOnly"}}}},
		{"continue binary", "Fetch.continueResponse", map[string]any{"requestId": "r", "responseCode": 200, "binaryResponseHeaders": base64.StdEncoding.EncodeToString([]byte("Set-Cookie: SID=" + secret + "\x00"))}},
		{"request override", "Fetch.continueRequest", map[string]any{"requestId": "r", "headers": []any{map[string]any{"name": "Cookie", "value": "SID=" + secret}}}},
		{"extra headers", "Network.setExtraHTTPHeaders", map[string]any{"headers": map[string]any{"Cookie": "SID=" + secret}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := float64(i + 10)
			a.send(map[string]any{"id": n, "sessionId": sid, "method": tc.method, "params": tc.params})
			if errMsg(a.next(id(n))) == "" {
				t.Error("cookie-capable override accepted")
			}
			if len(f.all(method(tc.method))) != 0 {
				t.Error("cookie-capable override reached Chrome")
			}
		})
	}
	a.send(map[string]any{"id": 90, "sessionId": sid, "method": "Network.enable"})
	if errMsg(a.next(id(90))) != "" {
		t.Fatal("ordinary network monitoring refused")
	}
	// Keep the documented body result, but don't grant an unreviewed response field.
	f.peer.mu.Lock()
	answer := f.peer.answer
	f.peer.answer = func(m map[string]any) (any, string) {
		if m["method"] == "Network.getResponseBody" {
			return map[string]any{"body": "ordinary response body", "base64Encoded": false, "headers": map[string]any{"Set-Cookie": secret}}, ""
		}
		return answer(m)
	}
	f.peer.mu.Unlock()
	a.send(map[string]any{"id": 91, "sessionId": sid, "method": "Network.getResponseBody", "params": map[string]any{"requestId": "r"}})
	body := a.next(id(91))["result"].(map[string]any)
	if body["body"] != "ordinary response body" || body["base64Encoded"] != false {
		t.Error("ordinary response body lost")
	}
	if body["headers"] != nil {
		t.Error("unreviewed Network response header field escaped")
	}
	headers := map[string]any{"Cookie": "SID=" + secret, "Set-Cookie": "SID=" + secret + "; HttpOnly", "Content-Type": "text/plain"}
	response := map[string]any{"url": "https://unrelated.test/image", "status": 200, "statusText": "OK", "mimeType": "image/png", "headers": headers, "headersText": "Set-Cookie: SID=" + secret, "requestHeaders": headers, "requestHeadersText": "Cookie: SID=" + secret}
	request := map[string]any{"url": "https://unrelated.test/image", "method": "GET", "headers": headers}
	for _, tc := range []struct {
		method string
		params any
	}{
		{"Network.requestWillBeSentExtraInfo", map[string]any{"requestId": "r", "associatedCookies": []any{map[string]any{"cookie": map[string]any{"value": secret, "httpOnly": true}}}, "headers": headers}},
		{"Network.responseReceivedExtraInfo", map[string]any{"requestId": "r", "blockedCookies": []any{map[string]any{"cookieLine": secret}}, "exemptedCookies": []any{map[string]any{"cookie": map[string]any{"value": secret}}}, "headers": headers, "headersText": secret}},
		{"Network.requestWillBeSent", map[string]any{"requestId": "r", "request": request, "redirectResponse": response, "redirectHasExtraInfo": true, "type": "Image"}},
		{"Network.responseReceived", map[string]any{"requestId": "r", "response": response, "hasExtraInfo": true, "type": "Image"}},
		{"Network.webSocketWillSendHandshakeRequest", map[string]any{"requestId": "ws", "request": map[string]any{"headers": headers}}},
		{"Network.webSocketHandshakeResponseReceived", map[string]any{"requestId": "ws", "response": response}},
		{"Network.responseReceivedEarlyHints", map[string]any{"requestId": "r", "headers": headers}},
		{"Fetch.requestPaused", map[string]any{"requestId": "r", "request": request, "responseHeaders": []any{map[string]any{"name": "Set-Cookie", "value": secret}}}},
		{"Fetch.authRequired", map[string]any{"requestId": "r", "request": request}},
		{"Network.futureCookieEvent", map[string]any{"value": secret}},
	} {
		f.event(tab, tc.method, tc.params)
	}
	f.event(tab, "Network.loadingFinished", map[string]any{"requestId": "r", "encodedDataLength": 12})
	f.event(tab, "Runtime.consoleAPICalled", map[string]any{"type": "debug", "args": []any{}})
	a.next(method("Runtime.consoleAPICalled")) // same-socket ordering barrier
	for _, m := range a.all(func(m map[string]any) bool {
		return strings.HasPrefix(fmt.Sprint(m["method"]), "Network.") || strings.HasPrefix(fmt.Sprint(m["method"]), "Fetch.")
	}) {
		b, _ := json.Marshal(m)
		if strings.Contains(string(b), secret) {
			t.Errorf("cookie data escaped via %s", m["method"])
		}
	}
	for _, name := range []string{"Network.requestWillBeSentExtraInfo", "Network.responseReceivedExtraInfo", "Fetch.requestPaused", "Fetch.authRequired", "Network.futureCookieEvent"} {
		if len(a.all(method(name))) != 0 {
			t.Errorf("unsupported cookie-capable event forwarded: %s", name)
		}
	}
	r := a.next(method("Network.responseReceived"))["params"].(map[string]any)
	if r["hasExtraInfo"] != false {
		t.Error("response still promises suppressed extra info")
	}
	if r["response"].(map[string]any)["status"] != float64(200) {
		t.Error("response status lost")
	}
	q := a.next(method("Network.requestWillBeSent"))["params"].(map[string]any)
	if q["redirectHasExtraInfo"] != false || q["request"].(map[string]any)["url"] != "https://unrelated.test/image" {
		t.Error("request URL or extra-info contract lost")
	}
	if a.next(method("Network.loadingFinished"))["params"].(map[string]any)["encodedDataLength"] != float64(12) {
		t.Error("completion telemetry lost")
	}
}

func TestAuditDuplicateProfileClosesBeforeAuthentication(t *testing.T) {
	h := newHarness(t)
	h.extension("me@example.com")
	h.as(Caller{PID: 99}, true)
	p := h.dial("/extension?profile=me@example.com&client=second-install", http.Header{"Origin": {"chrome-extension://" + extID}})
	if code, _ := p.closedWith(); code != 4009 {
		t.Fatalf("duplicate profile close code %d", code)
	}
	if len(p.all(func(map[string]any) bool { return true })) != 0 {
		t.Fatal("refusal unexpectedly authenticated first")
	}
}

func TestAuditSharedStorageBoundary(t *testing.T) {
	h := newHarness(t)
	f := h.extension("me@example.com")
	a := h.agent("me@example.com")
	sid, _ := openTab(a, 1)
	for i, method := range []string{"Network.getAllCookies", "Network.getCookies", "Network.setCookie", "Network.deleteCookies", "Network.clearBrowserCookies", "Network.clearBrowserCache", "Storage.getCookies", "Storage.setCookies", "Storage.clearDataForOrigin", "DOMStorage.getDOMStorageItems", "IndexedDB.deleteDatabase", "CacheStorage.deleteCache", "ServiceWorker.unregister", "Target.sendMessageToTarget", "Target.attachToTarget", "Target.setDiscoverTargets", "Future.readAllProfileData"} {
		t.Run(method, func(t *testing.T) {
			n := float64(i + 10)
			a.send(map[string]any{"id": n, "sessionId": sid, "method": method, "params": map[string]any{"origin": "https://unrelated.test", "urls": []string{"https://unrelated.test"}}})
			if errMsg(a.next(id(n))) == "" {
				t.Errorf("shared-profile method %s was accepted", method)
			}
			if len(f.all(func(m map[string]any) bool { return m["method"] == method })) != 0 {
				t.Errorf("shared-profile method %s reached Chrome", method)
			}
		})
	}
	a.send(map[string]any{"id": 99, "sessionId": sid, "method": "Runtime.evaluate", "params": map[string]any{"expression": "1 + 1"}})
	if a.next(id(99))["result"] == nil {
		t.Fatal("ordinary page evaluation refused")
	}
}

func auditNavigate(t *testing.T, f *fakeChrome, a *peer, tab int, unique string) {
	t.Helper()
	f.event(tab, "Page.frameNavigated", map[string]any{"frame": map[string]any{"id": "TOP", "loaderId": unique, "url": "https://github.com/login"}})
	f.event(tab, "Runtime.executionContextCreated", map[string]any{"context": map[string]any{"id": 1, "uniqueId": unique, "origin": "https://github.com", "auxData": map[string]any{"frameId": "TOP", "isDefault": true}}})
	a.next(func(m map[string]any) bool { return m["method"] == "Runtime.executionContextCreated" })
}

func TestAuditProtectedFillsAndJSON(t *testing.T) {
	for _, field := range []string{"password", "otp"} {
		t.Run(field, func(t *testing.T) {
			h := newHarness(t)
			f := h.extension("me@example.com")
			a := h.agent("me@example.com")
			sid, tab := openTab(a, 1)
			auditNavigate(t, f, a, tab, "doc-a")
			a.send(map[string]any{"id": 2, "sessionId": sid, "method": "Input.insertText", "params": map[string]any{"text": "op://Agents/GitHub/" + field}})
			if !strings.Contains(errMsg(a.next(id(2))), "protected") {
				t.Error("protected vault fill was not refused")
			}
			if len(f.all(func(m map[string]any) bool { return m["method"] == "Input.insertText" })) != 0 {
				t.Error("protected value reached script-readable page")
			}
		})
	}
	t.Run("JSON booleans", func(t *testing.T) {
		h := newHarness(t)
		h.store.items[0].Fields[1].Value = "true"
		f := h.extension("me@example.com")
		a := h.agent("me@example.com")
		sid, tab := openTab(a, 1)
		auditNavigate(t, f, a, tab, "doc-a")
		a.send(map[string]any{"id": 2, "sessionId": sid, "method": "Input.insertText", "params": map[string]any{"text": "op://Agents/GitHub/password"}})
		a.next(id(2))
		h.s.mu.Lock()
		for internal := range h.s.agents {
			internal.ok(message{ID: json.RawMessage("99")}, map[string]any{"boolean": true, "text": "true"})
		}
		h.s.mu.Unlock()
		r := a.next(func(m map[string]any) bool { return m["id"] == float64(99) || m == nil })
		if r == nil {
			t.Fatal("masking corrupted JSON reply")
		}
		v, _ := r["result"].(map[string]any)
		if v["boolean"] != true || v["text"] != "true" {
			t.Fatalf("masking changed typed JSON: %v", r)
		}
	})
}

func TestAuditPopupCallerContext(t *testing.T) {
	h := newHarness(t)
	f := h.extension("me@example.com")
	a := h.agent("me@example.com")
	_, tab := openTab(a, 1)
	auditNavigate(t, f, a, tab, "doc-a")
	h.s.mu.Lock()
	var agent *Agent
	for x := range h.s.agents {
		agent = x
	}
	agent.openerOf[tab] = popupOpener{tabID: tab, id: 1, from: callFrom{contextID: 1, uniqueID: "doc-a"}}
	agent.contexts[tab][2] = ctxInfo{frameID: "IFRAME", isDefault: true}
	agent.onPageCall(tab, `{"op":"toOpener","data":"forged","targetOrigin":"*"}`, callFrom{contextID: 2})
	agent.onPageCall(tab, `{"op":"open","id":2,"url":"https://unrelated.test"}`, callFrom{contextID: 2})
	h.s.mu.Unlock()
	// A synchronous extension ping is an ordering barrier, not a timing guess.
	h.s.mu.Lock()
	agent.cdp(agent.p(), tab, "Runtime.evaluate", map[string]any{"expression": "audit-barrier"})
	h.s.mu.Unlock()
	if len(f.all(func(m map[string]any) bool { return strings.Contains(expr(m), "forged") })) != 0 {
		t.Error("iframe forged top-origin popup message")
	}
	if len(f.all(method("create"))) != 1 {
		t.Error("iframe created a popup through the top-only binding")
	}
	h.s.mu.Lock()
	agent.onPageCall(tab, `{"op":"toOpener","data":"valid-message","targetOrigin":"https://github.com"}`, callFrom{contextID: 1, uniqueID: "doc-a"})
	agent.cdp(agent.p(), tab, "Runtime.evaluate", map[string]any{"expression": "positive-barrier"})
	h.s.mu.Unlock()
	valid := f.all(func(m map[string]any) bool { return strings.Contains(expr(m), "valid-message") })
	if len(valid) != 1 || valid[0]["params"].(map[string]any)["uniqueContextId"] != "doc-a" {
		t.Fatal("valid top-document popup message was not delivered to its context")
	}
	h.s.mu.Lock()
	agent.onPageCall(tab, `{"op":"toOpener","data":"stale-message","targetOrigin":"*"}`, callFrom{contextID: 1, uniqueID: "old-context"})
	agent.cdp(agent.p(), tab, "Runtime.evaluate", map[string]any{"expression": "stale-barrier"})
	h.s.mu.Unlock()
	if len(f.all(func(m map[string]any) bool { return strings.Contains(expr(m), "stale-message") })) != 0 {
		t.Fatal("queued stale-context popup call was accepted")
	}
}

type auditBlockingChip struct {
	*softChip
	entered, release chan struct{}
}

func (c *auditBlockingChip) Sign(h, data []byte, reason, scope string, reuse time.Duration) ([]byte, error) {
	close(c.entered)
	<-c.release
	return c.softChip.Sign(h, data, reason, scope, reuse)
}

func auditKey(h *harness) {
	handle, pub, _ := h.chip.Create()
	sec := "s"
	f := func(k, v string) op.ItemField { return op.ItemField{Title: k, SectionID: &sec, Value: v} }
	h.store.items = append(h.store.items, op.Item{ID: "pk", Title: "Bot", Category: op.ItemCategoryLogin, Websites: []op.Website{{URL: "https://github.com"}}, Sections: []op.ItemSection{{ID: sec, Title: vault.PasskeySection}}, Fields: []op.ItemField{
		f("rp id", "github.com"), f("credential id", "Y3JlZA"), f("user name", "bot"), f("public key", base64.RawURLEncoding.EncodeToString(pub)), f("secure enclave key", base64.RawURLEncoding.EncodeToString(handle)),
	}})
}
func auditAsk(f *fakeChrome, tab, id int) {
	f.event(tab, "Runtime.bindingCalled", map[string]any{"name": binding, "executionContextId": 1, "payload": fmt.Sprintf(`{"op":"webauthn","kind":"get","id":%d,"publicKey":{"challenge":{"$b":"AAAA"},"rpId":"github.com"}}`, id)})
}
func auditOff(t *testing.T, h *harness) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(h.home, "config.json"), []byte(`{"extensionIds":["`+extID+`"],"onepassword":{"vault":"Agents"},"passkeys":{"enabled":false,"epoch":"revoked"}}`), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestAuditPasskeyCompletion(t *testing.T) {
	for _, change := range []string{"none", "same numeric context replacement", "passkeys off", "passkeys off without epoch", "off then on"} {
		t.Run(change, func(t *testing.T) {
			h := newHarness(t)
			auditKey(h)
			chip := &auditBlockingChip{h.chip, make(chan struct{}), make(chan struct{})}
			release := sync.OnceFunc(func() { close(chip.release) })
			defer release() // Fatal/Goexit must unblock the signer before harness cleanup joins it.
			h.s.chip = chip
			f := h.extension("me@example.com")
			a := h.agent("me@example.com")
			_, tab := openTab(a, 1)
			auditNavigate(t, f, a, tab, "doc-a")
			auditAsk(f, tab, 1)
			select {
			case <-chip.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("signing did not start")
			}
			if change == "same numeric context replacement" {
				auditNavigate(t, f, a, tab, "doc-b")
			}
			if change == "passkeys off" || change == "passkeys off without epoch" || change == "off then on" {
				auditOff(t, h)
			}
			if change == "passkeys off without epoch" {
				b, _ := os.ReadFile(filepath.Join(h.home, "config.json"))
				os.WriteFile(filepath.Join(h.home, "config.json"), []byte(strings.Replace(string(b), `"epoch":"revoked"`, `"epoch":""`, 1)), 0600)
			}
			if change == "off then on" {
				b, _ := os.ReadFile(filepath.Join(h.home, "config.json"))
				os.WriteFile(filepath.Join(h.home, "config.json"), []byte(strings.Replace(string(b), `"enabled":false`, `"enabled":true`, 1)), 0600)
			}
			release()
			// Wait for the handler's audited terminal outcome before examining replies.
			deadline := time.Now().Add(5 * time.Second)
			terminal := false
			for time.Now().Before(deadline) {
				b, _ := os.ReadFile(filepath.Join(h.home, "audit", time.Now().UTC().Format("2006-01-02")+".jsonl"))
				if strings.Contains(string(b), `"event":"passkey sign-in"`) || strings.Contains(string(b), `"event":"passkey cancelled"`) {
					terminal = true
					break
				}
				time.Sleep(time.Millisecond * 5)
			}
			if !terminal {
				t.Fatal("passkey handler did not reach a terminal outcome")
			}
			answers := f.all(func(m map[string]any) bool {
				return strings.Contains(expr(m), "__agentBridgeDone(1,") && strings.Contains(expr(m), `"credential"`)
			})
			if change != "none" && len(answers) != 0 {
				t.Fatalf("stale or revoked assertion delivered after %s", change)
			}
			if change == "none" {
				if len(answers) != 1 {
					t.Fatalf("live request received %d credentials", len(answers))
				}
				if answers[0]["params"].(map[string]any)["uniqueContextId"] != "doc-a" {
					t.Fatal("completion is not bound to unique originating context")
				}
			}
		})
	}
}

func TestAuditPasskeysOffPreparedTab(t *testing.T) {
	h := newHarness(t)
	auditKey(h)
	f := h.extension("me@example.com")
	a := h.agent("me@example.com")
	_, tab := openTab(a, 1)
	auditNavigate(t, f, a, tab, "doc-a")
	auditOff(t, h)
	h.s.mu.Lock()
	for agent := range h.s.agents {
		agent.onWebAuthn(tab, 7, map[string]any{"kind": "get", "publicKey": map[string]any{"challenge": map[string]string{"$b": "AAAA"}, "rpId": "github.com"}}, callFrom{contextID: 1, uniqueID: "doc-a"})
		agent.cdp(agent.p(), tab, "Runtime.evaluate", map[string]any{"expression": "off-barrier"})
	}
	h.s.mu.Unlock()
	h.person.mu.Lock()
	prompts := len(h.person.prompts)
	h.person.mu.Unlock()
	if prompts != 0 {
		t.Error("disabled prepared tab entered vault custody")
	}
	answers := f.all(func(m map[string]any) bool { return strings.Contains(expr(m), "__agentBridgeDone(7,") })
	if len(answers) != 1 {
		t.Fatalf("disabled prepared tab received %d explicit refusals", len(answers))
	}
	m := answers[0]
	if strings.Contains(expr(m), `"credential"`) || !strings.Contains(expr(m), "disabled") {
		t.Error("prepared tab retained passkey capability after off")
	}
	h.chip.mu.Lock()
	defer h.chip.mu.Unlock()
	if len(h.chip.reasons) != 0 {
		t.Error("disabled request entered signing")
	}
}
