package limit

import (
	"strings"
	"testing"
	"time"
)

var sampleLines = []string{
	`          {`,
	`            "id": "${uuid}"`,
	`            #vless`,
	`#& baba `,
	`},{"id": "ab3b957f-6503-4ea0-8e79-1918e9480e33","email": "baba"`,
	`          }`,
	`            "id": "${uuid}"`,
	`            #vlessgrpc`,
	`#& nazmi 2026-10-13`,
	`},{"id": "faecbac4-0784-429f-bd1e-1e3d7b06d6c8","email": "nazmi"`,
	`### abdo 2027-08-02`,
	`},{"id": "3c706eb3-c6d4-4013-ab92-7166f63bc197","alterId": 0,"email": "abdo"`,
	`#! trojanci 2026-11-05`,
	`},{"password": "656496fd-221a-4398-9fce-0e32e5a1bd4f","email": "trojanci"`,
}

func TestParseUsersVless(t *testing.T) {
	users := Protos[0].ParseUsers(sampleLines)
	if len(users) != 2 {
		t.Fatalf("kullanıcı sayısı = %d, want 2", len(users))
	}
	if users[0].Name != "baba" || users[0].Expiry != "" {
		t.Fatalf("baba yanlış ayrıştırıldı: %+v", users[0])
	}
	if !strings.HasPrefix(users[0].Secret, "ab3b957f") {
		t.Fatalf("baba uuid = %q", users[0].Secret)
	}
	if users[1].Name != "nazmi" || users[1].Expiry != "2026-10-13" {
		t.Fatalf("nazmi yanlış ayrıştırıldı: %+v", users[1])
	}
}

func TestParseUsersOtherProtocols(t *testing.T) {
	vmess := Protos[1].ParseUsers(sampleLines)
	if len(vmess) != 1 || vmess[0].Name != "abdo" || vmess[0].Expiry != "2027-08-02" {
		t.Fatalf("vmess ayrıştırma hatalı: %+v", vmess)
	}
	trojan := Protos[2].ParseUsers(sampleLines)
	if len(trojan) != 1 || trojan[0].Name != "trojanci" {
		t.Fatalf("trojan ayrıştırma hatalı: %+v", trojan)
	}
	if !strings.HasPrefix(trojan[0].Secret, "656496fd") {
		t.Fatalf("trojan şifresi = %q", trojan[0].Secret)
	}
}

func TestParseUsersDeduplicates(t *testing.T) {
	lines := append(append([]string{}, sampleLines...), `#& baba `, `},{"id": "ab3b957f-6503-4ea0-8e79-1918e9480e33","email": "baba"`)
	users := Protos[0].ParseUsers(lines)
	count := 0
	for _, user := range users {
		if user.Name == "baba" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("baba %d kez listelendi, want 1", count)
	}
}

func TestRemoveUser(t *testing.T) {
	out, removed := RemoveUser(sampleLines, "#&", "nazmi")
	if removed != 1 {
		t.Fatalf("silinen = %d, want 1", removed)
	}
	if len(out) != len(sampleLines)-2 {
		t.Fatalf("satır sayısı = %d, want %d", len(out), len(sampleLines)-2)
	}
	joined := strings.Join(out, "\n")
	if strings.Contains(joined, "nazmi") || strings.Contains(joined, "faecbac4") {
		t.Fatalf("nazmi kaydı kaldı:\n%s", joined)
	}
	if !strings.Contains(joined, "baba") {
		t.Fatalf("baba kaydı yanlışlıkla silindi")
	}
}

func TestRemoveDBUser(t *testing.T) {
	lines := []string{"& plughin Account", "### baba  ab3b 0 ", "### abdo 2027-08-02 3c7 0 "}
	out := RemoveDBUser(lines, "###", "baba")
	if len(out) != 2 {
		t.Fatalf("satır sayısı = %d, want 2", len(out))
	}
	if strings.Contains(strings.Join(out, "\n"), "baba") {
		t.Fatalf("baba db satırı kaldı")
	}
}

func TestFormatBytes(t *testing.T) {
	cases := map[uint64]string{
		500:            "500B",
		2048:           "2KB",
		5 * 1048576:    "5MB",
		3 * 1073741824: "3GB",
		// Eski con() scriptiyle birebir: 1GB'ın bir eksiği hâlâ MB sayılır.
		1073741823: "1024MB",
		1048575:    "1024KB",
	}
	for input, want := range cases {
		if got := FormatBytes(input); got != want {
			t.Fatalf("FormatBytes(%d) = %q, want %q", input, got, want)
		}
	}
}

func TestExpired(t *testing.T) {
	today := time.Date(2026, 10, 6, 15, 0, 0, 0, time.UTC)
	if Expired("", today) {
		t.Fatal("boş tarih süresiz sayılmalı")
	}
	if !Expired("2026-10-05", today) {
		t.Fatal("dünkü tarih süresi dolmuş sayılmalı")
	}
	if Expired("2026-10-06", today) {
		t.Fatal("bugünün tarihi dolmamış sayılmalı")
	}
	if Expired("2026-10-07", today) {
		t.Fatal("gelecek tarih dolmamış sayılmalı")
	}
	if Expired("bozuk", today) {
		t.Fatal("geçersiz tarih silme sebebi olmamalı")
	}
}

func TestParseStatsValue(t *testing.T) {
	if value, ok := ParseStatsValue("stat: user>>>baba>>>traffic>>>downlink\n  value: 1234\n"); !ok || value != 1234 {
		t.Fatalf("value: biçimi okunamadı: %d %v", value, ok)
	}
	if value, ok := ParseStatsValue("stat user>>>baba>>>traffic>>>downlink: 42"); !ok || value != 42 {
		t.Fatalf("eski biçim okunamadı: %d %v", value, ok)
	}
	if _, ok := ParseStatsValue("failed to get stats"); ok {
		t.Fatal("failed çıktısı okunmuş sayılmamalı")
	}
	if _, ok := ParseStatsValue(""); ok {
		t.Fatal("boş çıktı okunmuş sayılmamalı")
	}
}

func TestExceeded(t *testing.T) {
	if Exceeded(5000, 0) {
		t.Fatal("kota 0 sınırsız olmalı")
	}
	if Exceeded(1000, 1000) {
		t.Fatal("tam kotada aşım olmamalı")
	}
	if !Exceeded(1001, 1000) {
		t.Fatal("kota aşımı yakalanmadı")
	}
}
