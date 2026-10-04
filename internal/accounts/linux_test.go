package accounts

import (
	"strings"
	"testing"
)

func TestValidUsername(t *testing.T) {
	for _, name := range []string{"abc123", "a12345", "user01"} {
		if !ValidUsername(name) {
			t.Fatalf("geçerli olmalı: %q", name)
		}
	}
	for _, name := range []string{"", "Abc123", "1abcde", "ab", "abc-12", "abc_12", "türkçe"} {
		if ValidUsername(name) {
			t.Fatalf("geçersiz olmalı: %q", name)
		}
	}
}

func TestRandomCredentials(t *testing.T) {
	name, err := RandomUsername()
	if err != nil {
		t.Fatal(err)
	}
	if !ValidUsername(name) || len(name) != 6 {
		t.Fatalf("geçersiz kullanıcı adı: %q", name)
	}
	password, err := RandomPassword()
	if err != nil {
		t.Fatal(err)
	}
	if len(password) != 8 {
		t.Fatalf("geçersiz şifre uzunluğu: %d", len(password))
	}
}

func TestPayloads(t *testing.T) {
	get, connect := Payloads("can.vps-mosto.site", "127.0.0.1:109", "Backend: elsanor")
	if !strings.Contains(get, "Host: can.vps-mosto.site") || !strings.Contains(get, "Sec-WebSocket-Key:") {
		t.Fatalf("GET payload eksik: %s", get)
	}
	if !strings.Contains(connect, "X-Real-Host: 127.0.0.1:109") || !strings.Contains(connect, "X-Split: 1") {
		t.Fatalf("CONNECT payload eksik: %s", connect)
	}
	if !strings.Contains(get, "Backend: elsanor[crlf]") {
		t.Fatalf("ek header eksik: %s", get)
	}
}
