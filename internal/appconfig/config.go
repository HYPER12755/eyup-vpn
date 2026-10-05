package appconfig

import (
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

const (
	SingboxConfigPath = "/usr/local/etc/sing-box/config.json"
	SingboxClientPath = "/usr/local/etc/sing-box/phone_client.json"
	SingboxBinary     = "/usr/local/bin/sing-box"
	DefaultPublicHost = "can.vps-mosto.site"
	DefaultSSHTarget  = "127.0.0.1:109"
	DefaultSSHGroup   = "sshvpn"
	DefaultSSHShell   = "/bin/false"
)

// MenuConfPath is a variable, not a constant: on an installed server the file
// exists and takes precedence over the default host, so tests must be able to
// point it at a temp path to stay independent of the host they run on.
var MenuConfPath = "/etc/sshvpn/menu.conf"

func Env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func EnvInt(key string, fallback int) int {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return fallback
}

func MenuConfValues() (string, string) {
	host, header := "", ""
	data, err := os.ReadFile(MenuConfPath)
	if err != nil {
		return host, header
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if !found {
			continue
		}
		switch key {
		case "FAKE_HOST":
			host = strings.TrimSpace(value)
		case "EXTRA_HEADER":
			header = strings.TrimSpace(value)
		}
	}
	return host, header
}

func PublicHost() string {
	menuHost, _ := MenuConfValues()
	if host := Env("SSH_PUBLIC_HOST", Env("FAKE_HOST", menuHost)); host != "" {
		return host
	}
	return DefaultPublicHost
}

var (
	realityHostOnce  sync.Once
	realityHostValue string
)

func RealityHost() string {
	realityHostOnce.Do(func() {
		if value := strings.TrimSpace(os.Getenv("SSH_REALITY_HOST")); value != "" {
			realityHostValue = value
			return
		}
		if conn, err := net.Dial("udp", "8.8.8.8:80"); err == nil {
			if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr.IP != nil {
				realityHostValue = addr.IP.String()
			}
			_ = conn.Close()
		}
		if realityHostValue == "" {
			if host, _ := MenuConfValues(); host != "" {
				realityHostValue = host
			} else {
				realityHostValue = DefaultPublicHost
			}
		}
	})
	return realityHostValue
}
