package accounts

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var usernamePattern = regexp.MustCompile(`^[a-z][a-z0-9]{2,31}$`)

type Config struct {
	Group string
	Shell string
}

func ValidUsername(username string) bool {
	return usernamePattern.MatchString(username)
}

func UserExists(username string) bool {
	return exec.Command("id", "-u", username).Run() == nil
}

func EnsureGroup(group string) error {
	if exec.Command("getent", "group", group).Run() == nil {
		return nil
	}
	return exec.Command("groupadd", "-f", group).Run()
}

// ListUsers returns the members of group. A missing group and a failing
// getent are reported as errors so callers can tell them apart from a group
// that simply has no members yet.
func ListUsers(group string) ([]string, error) {
	output, err := exec.Command("getent", "group", group).Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 2 {
			return nil, fmt.Errorf("grup yok: %s", group)
		}
		return nil, fmt.Errorf("getent group %s: %w", group, err)
	}
	parts := strings.Split(strings.TrimSpace(string(output)), ":")
	if len(parts) < 4 {
		return nil, fmt.Errorf("getent group %s: beklenmeyen çıktı", group)
	}
	if parts[3] == "" {
		return []string{}, nil
	}
	return strings.Split(parts[3], ","), nil
}

func CreateUser(username, password string, cfg Config, days int) (string, error) {
	if !ValidUsername(username) {
		return "", errors.New("geçersiz kullanıcı adı")
	}
	if password == "" || strings.ContainsAny(password, ":\n\r") {
		return "", errors.New("geçersiz şifre")
	}
	if cfg.Group == "" {
		cfg.Group = "sshvpn"
	}
	if cfg.Shell == "" {
		cfg.Shell = "/bin/false"
	}
	if err := EnsureGroup(cfg.Group); err != nil {
		return "", fmt.Errorf("grup oluşturulamadı: %w", err)
	}

	if output, err := exec.Command("useradd", "-M", "-s", cfg.Shell, "-G", cfg.Group, username).CombinedOutput(); err != nil {
		return "", fmt.Errorf("useradd: %s", strings.TrimSpace(string(output)))
	}

	chpasswd := exec.Command("chpasswd")
	chpasswd.Stdin = strings.NewReader(username + ":" + password + "\n")
	if output, err := chpasswd.CombinedOutput(); err != nil {
		_ = exec.Command("userdel", username).Run()
		return "", fmt.Errorf("chpasswd: %s", strings.TrimSpace(string(output)))
	}

	expires := "-1"
	expiresText := "Süresiz"
	if days > 0 {
		expires = time.Now().AddDate(0, 0, days).Format("2006-01-02")
		expiresText = expires
	}
	if output, err := exec.Command("chage", "-E", expires, "-M", "99999", username).CombinedOutput(); err != nil {
		_ = exec.Command("userdel", username).Run()
		return "", fmt.Errorf("chage: %s", strings.TrimSpace(string(output)))
	}

	return expiresText, nil
}

func DeleteUser(username string) error {
	if !ValidUsername(username) {
		return errors.New("geçersiz kullanıcı adı")
	}
	if !UserExists(username) {
		return nil
	}
	if output, err := exec.Command("userdel", username).CombinedOutput(); err != nil {
		return fmt.Errorf("userdel: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

func Expiry(username string) string {
	output, err := exec.Command("chage", "-l", username).Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(output), "\n") {
		key, value, found := strings.Cut(line, ":")
		if found && strings.Contains(key, "Account expires") {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func RandomUsername() (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	name := make([]byte, 6)
	first, err := randInt(26)
	if err != nil {
		return "", err
	}
	name[0] = "abcdefghijklmnopqrstuvwxyz"[first]
	for i := 1; i < len(name); i++ {
		index, err := randInt(len(alphabet))
		if err != nil {
			return "", err
		}
		name[i] = alphabet[index]
	}
	return string(name), nil
}

func RandomPassword() (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	password := make([]byte, 8)
	for i := range password {
		index, err := randInt(len(alphabet))
		if err != nil {
			return "", err
		}
		password[i] = alphabet[index]
	}
	return string(password), nil
}

func Payloads(host, target, extraHeader string) (string, string) {
	extra := ""
	if extraHeader != "" {
		extra = extraHeader + "[crlf]"
	}
	get := fmt.Sprintf("GET / HTTP/1.1[crlf]Host: %s[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==[crlf]Sec-WebSocket-Version: 13[crlf]%s[crlf]", host, extra)
	connect := fmt.Sprintf("CONNECT %s HTTP/1.1[crlf]Host: %s[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==[crlf]Sec-WebSocket-Version: 13[crlf]X-Real-Host: %s[crlf]X-Split: 1[crlf]%s[crlf]", target, host, target, extra)
	return get, connect
}

func randInt(max int) (int, error) {
	value, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(value.Int64()), nil
}
