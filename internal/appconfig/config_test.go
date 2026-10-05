package appconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func isolateMenuConf(t *testing.T) {
	t.Helper()
	previous := MenuConfPath
	MenuConfPath = filepath.Join(t.TempDir(), "menu.conf")
	t.Cleanup(func() { MenuConfPath = previous })
}

func TestEnvFallsBackOnBlank(t *testing.T) {
	t.Setenv("VPNSTACK_TEST_ENV", "   ")
	if got := Env("VPNSTACK_TEST_ENV", "fallback"); got != "fallback" {
		t.Fatalf("Env() = %q, want %q", got, "fallback")
	}
	t.Setenv("VPNSTACK_TEST_ENV", "value")
	if got := Env("VPNSTACK_TEST_ENV", "fallback"); got != "value" {
		t.Fatalf("Env() = %q, want %q", got, "value")
	}
}

func TestPublicHostFallsBackToDefault(t *testing.T) {
	isolateMenuConf(t)
	t.Setenv("SSH_PUBLIC_HOST", "")
	t.Setenv("FAKE_HOST", "")
	if got := PublicHost(); got != DefaultPublicHost {
		t.Fatalf("PublicHost() = %q, want %q", got, DefaultPublicHost)
	}
}

func TestPublicHostFallsBackToMenuConf(t *testing.T) {
	isolateMenuConf(t)
	t.Setenv("SSH_PUBLIC_HOST", "")
	t.Setenv("FAKE_HOST", "")
	if err := os.WriteFile(MenuConfPath, []byte("FAKE_HOST=menu.example.com\n"), 0o600); err != nil {
		t.Fatalf("menu.conf yazılamadı: %v", err)
	}
	if got := PublicHost(); got != "menu.example.com" {
		t.Fatalf("PublicHost() = %q, want %q", got, "menu.example.com")
	}
}

func TestPublicHostPrefersEnvironment(t *testing.T) {
	isolateMenuConf(t)
	t.Setenv("SSH_PUBLIC_HOST", "")
	t.Setenv("FAKE_HOST", "vpn.example.com")
	if got := PublicHost(); got != "vpn.example.com" {
		t.Fatalf("PublicHost() = %q, want %q", got, "vpn.example.com")
	}
	t.Setenv("SSH_PUBLIC_HOST", "public.example.com")
	if got := PublicHost(); got != "public.example.com" {
		t.Fatalf("PublicHost() = %q, want %q", got, "public.example.com")
	}
}

func TestEnvInt(t *testing.T) {
	t.Setenv("VPNSTACK_TEST_INT", "")
	if got := EnvInt("VPNSTACK_TEST_INT", 10015); got != 10015 {
		t.Fatalf("EnvInt() = %d, want %d", got, 10015)
	}
	t.Setenv("VPNSTACK_TEST_INT", "notanumber")
	if got := EnvInt("VPNSTACK_TEST_INT", 10015); got != 10015 {
		t.Fatalf("EnvInt() = %d, want %d", got, 10015)
	}
	t.Setenv("VPNSTACK_TEST_INT", " 8080 ")
	if got := EnvInt("VPNSTACK_TEST_INT", 10015); got != 8080 {
		t.Fatalf("EnvInt() = %d, want %d", got, 8080)
	}
}
