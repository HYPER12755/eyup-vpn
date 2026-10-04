package appconfig

import "testing"

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
	t.Setenv("SSH_PUBLIC_HOST", "")
	t.Setenv("FAKE_HOST", "")
	if got := PublicHost(); got != DefaultPublicHost {
		t.Fatalf("PublicHost() = %q, want %q", got, DefaultPublicHost)
	}
}

func TestPublicHostPrefersEnvironment(t *testing.T) {
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
