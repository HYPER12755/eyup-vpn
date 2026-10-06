package singbox

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const sampleConfig = `{
  "log": {},
  "inbounds": [{
    "type": "vless", "tag": "test-in", "listen": "127.0.0.1", "listen_port": 1443,
    "users": [{"name": "user1", "uuid": "11111111-1111-1111-1111-111111111111", "flow": "xtls-rprx-vision"}],
    "tls": {"enabled": true, "server_name": "whatsapp.net", "reality": {"enabled": true, "private_key": "YHzFvH1VKwnZWhBy_9faBTqdIxesaP5IU-G8GijFWUU", "short_id": ["abcd1234"]}}
  }],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {"final": "direct"}
}`

func withTempConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(sampleConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	oldPath, oldReload, oldValidate := ConfigFile, Reload, Validate
	ConfigFile = path
	Reload = func() error { return nil }
	Validate = func(string) error { return nil }
	t.Cleanup(func() { ConfigFile, Reload, Validate = oldPath, oldReload, oldValidate })
	return path
}

func TestDerivePublicKeyMatchesSingbox(t *testing.T) {
	if _, err := exec.LookPath(Binary); err != nil {
		t.Skip("sing-box binary yok")
	}
	output, err := exec.Command(Binary, "generate", "reality-keypair").Output()
	if err != nil {
		t.Fatal(err)
	}
	privateKey, publicKey := "", ""
	for _, line := range strings.Split(string(output), "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		switch strings.TrimSpace(key) {
		case "PrivateKey":
			privateKey = strings.TrimSpace(value)
		case "PublicKey":
			publicKey = strings.TrimSpace(value)
		}
	}
	if derived := DerivePublicKey(privateKey); derived != publicKey {
		t.Fatalf("türetilen anahtar yanlış: got %q want %q", derived, publicKey)
	}
}

func TestRealityKeys(t *testing.T) {
	withTempConfig(t)
	keys := RealityKeys()
	if len(keys) != 1 || keys[0].Tag != "test-in" || len(keys[0].PublicKey) < 40 {
		t.Fatalf("beklenmeyen anahtarlar: %+v", keys)
	}
}

func TestBuildLinkReality(t *testing.T) {
	withTempConfig(t)
	t.Setenv("SSH_REALITY_HOST", "203.0.113.10")

	config, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	inbound := Inbounds(config)[0]
	link := BuildLink(inbound, Users(inbound)[0])
	if !strings.HasPrefix(link, "vless://11111111-1111-1111-1111-111111111111@203.0.113.10:443?") {
		t.Fatalf("beklenmeyen link: %s", link)
	}
	if !strings.Contains(link, "security=reality") || !strings.Contains(link, "flow=xtls-rprx-vision") {
		t.Fatalf("eksik parametre: %s", link)
	}
}

func TestAddAndRemoveUser(t *testing.T) {
	path := withTempConfig(t)
	account, link, err := AddUser(0, 30)
	if err != nil {
		t.Fatal(err)
	}
	if account.UUID == "" || account.Expires == "" || !strings.Contains(link, "vless://") {
		t.Fatalf("beklenmeyen hesap: %+v %s", account, link)
	}

	data, _ := os.ReadFile(path)
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if len(Users(Inbounds(config)[0])) != 2 {
		t.Fatalf("kullanıcı eklenmedi")
	}

	name, err := RemoveUser(0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if name != account.Name {
		t.Fatalf("yanlış kullanıcı silindi: %q", name)
	}
	data, _ = os.ReadFile(path)
	_ = json.Unmarshal(data, &config)
	if len(Users(Inbounds(config)[0])) != 1 {
		t.Fatalf("kullanıcı silinmedi")
	}
}

func TestBuildLinkRealityCarriesParameters(t *testing.T) {
	config := parseConfig(t, sampleConfig)
	inbound := Inbounds(config)[0]
	link := BuildLink(inbound, Users(inbound)[0])

	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatalf("link is not parseable: %v", err)
	}
	query := parsed.Query()
	for key, want := range map[string]string{
		"type": "tcp", "security": "reality", "sni": "whatsapp.net",
		"fp": "chrome", "sid": "abcd1234", "flow": "xtls-rprx-vision",
	} {
		if got := query.Get(key); got != want {
			t.Errorf("query %s = %q, want %q", key, got, want)
		}
	}
	if query.Get("pbk") == "" {
		t.Error("pbk must be present for a REALITY inbound")
	}
	if parsed.Port() != "443" {
		t.Errorf("loopback REALITY must publish on 443, got %q", parsed.Port())
	}
}

func TestBuildLinkEscapesValues(t *testing.T) {
	const tricky = `{
	  "inbounds": [{
	    "type": "vless", "tag": "my node/1", "listen": "127.0.0.1", "listen_port": 1443,
	    "users": [{"name": "user1", "uuid": "11111111-1111-1111-1111-111111111111"}],
	    "transport": {"type": "ws", "path": "/p?a=1&b=2"},
	    "tls": {"enabled": true, "server_name": "a.example.com"}
	  }],
	  "outbounds": [], "route": {"final": "direct"}
	}`
	config := parseConfig(t, tricky)
	inbound := Inbounds(config)[0]
	link := BuildLink(inbound, Users(inbound)[0])

	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatalf("link is not parseable: %v", err)
	}
	// The embedded '?' and '&' in the path must stay inside the path value.
	if got := parsed.Query().Get("path"); got != "/p?a=1&b=2" {
		t.Errorf("path = %q, want %q", got, "/p?a=1&b=2")
	}
	if parsed.Fragment != "my node/1" {
		t.Errorf("fragment = %q, want %q", parsed.Fragment, "my node/1")
	}
}

func parseConfig(t *testing.T, raw string) map[string]any {
	t.Helper()
	var config map[string]any
	if err := json.Unmarshal([]byte(raw), &config); err != nil {
		t.Fatal(err)
	}
	return config
}

func TestBuildLinkTrojan(t *testing.T) {
	const raw = `{
	  "inbounds": [{
	    "type": "trojan", "tag": "tr-node", "listen": "127.0.0.1", "listen_port": 1444,
	    "users": [{"name": "u1", "password": "s3cret-pass"}],
	    "tls": {"enabled": true, "server_name": "tr.example.com"}
	  }], "outbounds": [], "route": {"final": "direct"}
	}`
	config := parseConfig(t, raw)
	inbound := Inbounds(config)[0]
	link := BuildLink(inbound, Users(inbound)[0])

	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatalf("link is not parseable: %v", err)
	}
	if parsed.Scheme != "trojan" {
		t.Fatalf("scheme = %q, want trojan", parsed.Scheme)
	}
	if parsed.User == nil || parsed.User.Username() != "s3cret-pass" {
		t.Fatalf("trojan password not in userinfo: %v", parsed.User)
	}
	if got := parsed.Query().Get("sni"); got != "tr.example.com" {
		t.Errorf("sni = %q, want tr.example.com", got)
	}
	if parsed.Port() != "1444" {
		t.Errorf("port = %q, want 1444", parsed.Port())
	}
}

func TestBuildLinkVMess(t *testing.T) {
	const raw = `{
	  "inbounds": [{
	    "type": "vmess", "tag": "vm-node", "listen": "127.0.0.1", "listen_port": 10002,
	    "users": [{"name": "u1", "uuid": "11111111-1111-1111-1111-111111111111"}],
	    "transport": {"type": "ws", "path": "/ws"},
	    "tls": {"enabled": true, "server_name": "vm.example.com"}
	  }], "outbounds": [], "route": {"final": "direct"}
	}`
	config := parseConfig(t, raw)
	inbound := Inbounds(config)[0]
	link := BuildLink(inbound, Users(inbound)[0])

	if !strings.HasPrefix(link, "vmess://") {
		t.Fatalf("link must be vmess://, got %q", link)
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(link, "vmess://"))
	if err != nil {
		t.Fatalf("vmess payload not base64: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("vmess payload not JSON: %v", err)
	}
	if payload["id"] != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("id = %v", payload["id"])
	}
	if payload["net"] != "ws" || payload["path"] != "/ws" {
		t.Errorf("transport not preserved: %v", payload)
	}
	if payload["tls"] != "tls" || payload["sni"] != "vm.example.com" {
		t.Errorf("tls not preserved: %v", payload)
	}
}

func TestBuildLinkHysteria2(t *testing.T) {
	const raw = `{
	  "inbounds": [{
	    "type": "hysteria2", "tag": "hy-node", "listen": "127.0.0.1", "listen_port": 1445,
	    "users": [{"name": "u1", "password": "hy-pass"}],
	    "tls": {"enabled": true, "server_name": "hy.example.com"}
	  }], "outbounds": [], "route": {"final": "direct"}
	}`
	config := parseConfig(t, raw)
	inbound := Inbounds(config)[0]
	link := BuildLink(inbound, Users(inbound)[0])

	if !strings.HasPrefix(link, "hysteria2://hy-pass@") {
		t.Fatalf("unexpected hysteria2 link: %q", link)
	}
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatalf("link is not parseable: %v", err)
	}
	if got := parsed.Query().Get("sni"); got != "hy.example.com" {
		t.Errorf("sni = %q, want hy.example.com", got)
	}
}

func TestBuildLinkTuic(t *testing.T) {
	const raw = `{
	  "inbounds": [{
	    "type": "tuic", "tag": "tuic-node", "listen": "127.0.0.1", "listen_port": 1446,
	    "users": [{"name": "u1", "uuid": "22222222-2222-2222-2222-222222222222", "password": "tuic-pass"}],
	    "tls": {"enabled": true, "server_name": "tuic.example.com"}
	  }], "outbounds": [], "route": {"final": "direct"}
	}`
	config := parseConfig(t, raw)
	inbound := Inbounds(config)[0]
	link := BuildLink(inbound, Users(inbound)[0])

	if !strings.HasPrefix(link, "tuic://22222222-2222-2222-2222-222222222222:tuic-pass@") {
		t.Fatalf("unexpected tuic link: %q", link)
	}
	if !strings.Contains(link, "sni=tuic.example.com") {
		t.Errorf("sni missing: %q", link)
	}
}
