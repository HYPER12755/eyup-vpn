// Package limit ports the legacy limit.vless/vmess/trojan shell daemons: it
// parses the marker-based Xray config, accumulates per-user downlink usage and
// decides which accounts to remove when their quota or expiry is reached.
package limit

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Proto describes one protocol's files and markers. The values mirror the
// legacy scripts and xraycfg.py, so both toolchains stay interoperable.
type Proto struct {
	Name     string // vless
	Prefix   string // "#&" (config marker prefix)
	DBPath   string // "/etc/vless/.vless.db"
	DBPrefix string // "###" (line prefix inside the db)
	Root     string // "/etc/vless" -> quota files: root/<user>
	UsageDir string // "/etc/limit/vless" -> usage files: usageDir/<user>
}

var Protos = []Proto{
	{Name: "vless", Prefix: "#&", DBPath: "/etc/vless/.vless.db", DBPrefix: "###", Root: "/etc/vless", UsageDir: "/etc/limit/vless"},
	{Name: "vmess", Prefix: "###", DBPath: "/etc/vmess/.vmess.db", DBPrefix: "###", Root: "/etc/vmess", UsageDir: "/etc/limit/vmess"},
	{Name: "trojan", Prefix: "#!", DBPath: "/etc/trojan/.trojan.db", DBPrefix: "#!", Root: "/etc/trojan", UsageDir: "/etc/limit/trojan"},
}

// User is one account found in the config markers.
type User struct {
	Proto  string
	Name   string
	Expiry string // "2026-10-13" or "" (unlimited)
	Secret string // uuid / password from the injected line
}

// ParseUsers extracts every marker user of the protocol from config lines.
// A user occupies two lines: "<prefix> <name> <expiry>" followed by the
// injected line holding "id"/"password".
func (p Proto) ParseUsers(lines []string) []User {
	users := make([]User, 0)
	seen := map[string]bool{}
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, p.Prefix+" ") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}
		name := fields[1]
		if seen[name] {
			continue
		}
		expiry := ""
		if len(fields) > 2 {
			expiry = fields[2]
		}
		secret := ""
		if index+1 < len(lines) {
			secret = secretFromLine(lines[index+1])
		}
		seen[name] = true
		users = append(users, User{Proto: p.Name, Name: name, Expiry: expiry, Secret: secret})
	}
	return users
}

var secretPattern = regexp.MustCompile(`"(?:id|password)": "([^"]+)"`)

func secretFromLine(line string) string {
	match := secretPattern.FindStringSubmatch(line)
	if len(match) == 2 {
		return match[1]
	}
	return ""
}

// RemoveUser deletes every pair of lines belonging to the user (the marker
// line plus the injected "},{" line that follows it) and reports how many
// pairs were removed.
func RemoveUser(lines []string, prefix, user string) ([]string, int) {
	out := make([]string, 0, len(lines))
	removed := 0
	for index := 0; index < len(lines); index++ {
		if !lineMatchesUser(lines[index], prefix, user) {
			out = append(out, lines[index])
			continue
		}
		removed++
		if index+1 < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[index+1]), "},{") {
			index++
		}
	}
	return out, removed
}

func lineMatchesUser(line, prefix, user string) bool {
	trimmed := strings.TrimSpace(line)
	return trimmed == prefix+" "+user || strings.HasPrefix(trimmed, prefix+" "+user+" ")
}

// RemoveDBUser removes the user's line from a database file's lines.
func RemoveDBUser(lines []string, dbPrefix, user string) []string {
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == dbPrefix+" "+user || strings.HasPrefix(trimmed, dbPrefix+" "+user+" ") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// FormatBytes mirrors the legacy "con" shell helper.
func FormatBytes(bytes uint64) string {
	switch {
	case bytes < 1024:
		return fmt.Sprintf("%dB", bytes)
	case bytes < 1048576:
		return fmt.Sprintf("%dKB", (bytes+1023)/1024)
	case bytes < 1073741824:
		return fmt.Sprintf("%dMB", (bytes+1048575)/1048576)
	default:
		return fmt.Sprintf("%dGB", (bytes+1073741823)/1073741824)
	}
}

// Expired reports whether an ISO expiry date ("2026-10-13") is before today.
func Expired(expiry string, today time.Time) bool {
	if expiry == "" {
		return false
	}
	parsed, err := time.Parse("2006-01-02", expiry)
	if err != nil {
		return false
	}
	return parsed.Before(today.Truncate(24 * time.Hour))
}

var valuePattern = regexp.MustCompile(`value:\s*"?(\d+)"?`)
var statPattern = regexp.MustCompile(`^stat[^:]*:\s*"?(\d+)"?`)

// ParseStatsValue extracts the counter from `xray api stats` output. The tool
// prints "value: N" on newer versions and "stat <name>: N" on older ones.
func ParseStatsValue(output string) (uint64, bool) {
	for _, line := range strings.Split(output, "\n") {
		if match := valuePattern.FindStringSubmatch(line); len(match) == 2 {
			value, err := strconv.ParseUint(match[1], 10, 64)
			if err == nil {
				return value, true
			}
		}
	}
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if match := statPattern.FindStringSubmatch(trimmed); len(match) == 2 {
			value, err := strconv.ParseUint(match[1], 10, 64)
			if err == nil {
				return value, true
			}
		}
	}
	if strings.Contains(output, "failed") {
		return 0, false
	}
	return 0, false
}

// Exceeded reports whether accumulated usage passed the quota. A quota of zero
// (or a missing file, handled by the caller) means unlimited.
func Exceeded(usage, quota uint64) bool {
	return quota > 0 && usage > quota
}
