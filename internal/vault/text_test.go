package vault

import (
	"context"
	"strings"
	"testing"

	op "github.com/1password/onepassword-sdk-go"
)

func TestResolveTextRefusesProtectedFieldsBeforeValueWork(t *testing.T) {
	for _, field := range []string{"password", "passwd", "otp", "otp1", "one-time password"} {
		t.Run(field, func(t *testing.T) {
			v, store, _, _ := fixture()
			// If the protected-field guard is bypassed, this TOTP reaches its known
			// invalid digit computation. The text-only path must never compute it.
			store.items[0].Fields[3].Value = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=32"
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("protected OTP computation reached: %v", p)
				}
			}()
			value, err := v.ResolveText(context.Background(), "op://Shared with Chrome Relay/GitHub/"+field, "https://github.com/login", claude)
			if err == nil || !strings.Contains(err.Error(), "protected") || value.Value != "" {
				t.Errorf("protected chosen value escaped custody via %s", field)
			}
		})
	}
	v, store, _, _ := fixture()
	store.items[0].Fields = append(store.items[0].Fields,
		op.ItemField{ID: "unknown", Title: "unknown", Value: "unclassified fixture"},
		op.ItemField{ID: "note", Title: "note", FieldType: op.ItemFieldTypeText, Value: "public fixture"})
	if value, err := v.ResolveText(context.Background(), "op://Shared with Chrome Relay/GitHub/unknown", "https://github.com/login", claude); err == nil || value.Value != "" {
		t.Fatal("unclassified field escaped text-only custody")
	}
	for field, want := range map[string]string{"username": "agent-bot", "note": "public fixture"} {
		value, err := v.ResolveText(context.Background(), "op://Shared with Chrome Relay/GitHub/"+field, "https://github.com/login", claude)
		if err != nil || value.Value != want {
			t.Errorf("public text %s failed: %v", field, err)
		}
	}
}
