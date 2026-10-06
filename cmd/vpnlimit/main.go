// vpnlimit ports the legacy limit.vless/vmess/trojan shell daemons to Go.
// Every pass it reads per-user downlink counters through the Xray stats API,
// accumulates them in /etc/limit/<proto>/<user> and removes accounts whose
// quota (see /etc/<proto>/<user>) or expiry (config marker) is reached.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"vpnstack/internal/limit"
	"vpnstack/internal/version"
)

const (
	defaultConfigPath = "/etc/xray/config.json"
	defaultXrayBin    = "/usr/local/bin/xray"
	defaultStatsAddr  = "127.0.0.1:10000"
	defaultBotDB      = "/etc/bot/.bot.db"
	defaultWwwRoot    = "/var/www/html"
	statsTimeout      = 10 * time.Second
)

type app struct {
	configPath string
	xrayBin    string
	statsAddr  string
	botDB      string
	wwwRoot    string
	dryRun     bool
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func main() {
	once := flag.Bool("once", false, "tek tur çalış ve çık")
	interval := flag.Duration("interval", 5*time.Second, "tur aralığı")
	dryRun := flag.Bool("dry-run", false, "hiçbir şey yazma/silme, yalnızca raporla")
	showVersion := flag.Bool("version", false, "sürümü yaz ve çık")
	flag.Parse()

	if *showVersion {
		fmt.Printf("vpnlimit %s\n", version.Full())
		return
	}

	log.SetFlags(log.LstdFlags)
	application := &app{
		configPath: envOr("XRAY_CONFIG", defaultConfigPath),
		xrayBin:    envOr("XRAY_BIN", defaultXrayBin),
		statsAddr:  envOr("XRAY_STATS_ADDR", defaultStatsAddr),
		botDB:      envOr("VPNSTACK_BOT_DB", defaultBotDB),
		wwwRoot:    envOr("VPNSTACK_WWW_ROOT", defaultWwwRoot),
		dryRun:     *dryRun,
	}

	if _, err := os.Stat(application.configPath); err != nil {
		log.Printf("config bulunamadı (%s); izleyici boş bekleyecek", application.configPath)
	}
	for {
		if err := application.runOnce(time.Now()); err != nil {
			log.Printf("tur hatası: %v", err)
		}
		if *once {
			return
		}
		time.Sleep(*interval)
	}
}

type removal struct {
	proto  limit.Proto
	user   limit.User
	reason string
	usage  uint64
	quota  uint64
}

func (a *app) runOnce(now time.Time) error {
	lines, err := readLines(a.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var removals []removal
	changed := false
	for _, proto := range limit.Protos {
		for _, user := range proto.ParseUsers(lines) {
			delta, ok := a.statsDownlink(user.Name)
			if !ok {
				continue
			}
			usage := readUint(proto.UsageDir+"/"+user.Name) + delta
			if a.dryRun {
				if delta > 0 {
					log.Printf("dry-run: %s/%s +%s (toplam %s)", proto.Name, user.Name, limit.FormatBytes(delta), limit.FormatBytes(usage))
				}
			} else if err := writeUint(proto.UsageDir+"/"+user.Name, usage); err != nil {
				log.Printf("kullanım yazılamadı (%s): %v", user.Name, err)
				continue
			}
			quota := readUint(proto.Root + "/" + user.Name)
			switch {
			case limit.Exceeded(usage, quota):
				removals = append(removals, removal{proto: proto, user: user, reason: "kota", usage: usage, quota: quota})
			case limit.Expired(user.Expiry, now):
				removals = append(removals, removal{proto: proto, user: user, reason: "süre", usage: usage, quota: quota})
			}
		}
	}

	if len(removals) == 0 {
		return nil
	}

	for _, item := range removals {
		text := fmt.Sprintf("%s kaldırılıyor: %s (%s) — kullanım %s", item.proto.Name, item.user.Name, item.reason, limit.FormatBytes(item.usage))
		if item.quota > 0 {
			text += fmt.Sprintf(" / kota %s", limit.FormatBytes(item.quota))
		}
		log.Print(text)
		if a.dryRun {
			continue
		}
		var removed int
		lines, removed = limit.RemoveUser(lines, item.proto.Prefix, item.user.Name)
		if removed > 0 {
			changed = true
		}
		a.removeDBEntry(item.proto, item.user.Name)
		a.cleanupFiles(item.proto, item.user.Name)
		a.notify(fmt.Sprintf("⚠️ %s limit aşıldı\nKullanıcı: %s\nNeden: %s\nKullanım: %s", strings.ToUpper(item.proto.Name), item.user.Name, item.reason, limit.FormatBytes(item.usage)))
	}

	if a.dryRun || !changed {
		return nil
	}
	if err := a.writeConfig(lines); err != nil {
		return err
	}
	if err := exec.Command("systemctl", "restart", "xray").Run(); err != nil {
		log.Printf("xray yeniden başlatılamadı: %v", err)
	}
	return nil
}

// statsDownlink reads the user's downlink counter. It resets the counter only
// when we are going to record the delta; a dry run must not steal traffic from
// the running limiter.
func (a *app) statsDownlink(user string) (uint64, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), statsTimeout)
	defer cancel()
	name := fmt.Sprintf("user>>>%s>>>traffic>>>downlink", user)
	args := []string{"api", "stats", "--server=" + a.statsAddr, "-name", name}
	if !a.dryRun {
		args = append(args, "-reset")
	}
	out, err := exec.CommandContext(ctx, a.xrayBin, args...).CombinedOutput()
	if err != nil && len(out) == 0 {
		return 0, false
	}
	return limit.ParseStatsValue(string(out))
}

func (a *app) writeConfig(lines []string) error {
	if data, err := os.ReadFile(a.configPath); err == nil {
		_ = os.WriteFile(a.configPath+".limit.bak", data, 0o644)
	}
	return os.WriteFile(a.configPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func (a *app) removeDBEntry(proto limit.Proto, user string) {
	lines, err := readLines(proto.DBPath)
	if err != nil {
		return
	}
	kept := limit.RemoveDBUser(lines, proto.DBPrefix, user)
	if len(kept) == len(lines) {
		return
	}
	if err := os.WriteFile(proto.DBPath, []byte(strings.Join(kept, "\n")+"\n"), 0o644); err != nil {
		log.Printf("db güncellenemedi (%s): %v", proto.DBPath, err)
	}
}

// cleanupFiles removes the legacy per-user bookkeeping files, mirroring the
// paths the shell daemons deleted after expiring an account.
func (a *app) cleanupFiles(proto limit.Proto, user string) {
	paths := []string{
		fmt.Sprintf("/etc/funny/limit/%s/ip/%s", proto.Name, user),
		proto.Root + "/" + user,
		proto.UsageDir + "/" + user,
		proto.UsageDir + "/quota/" + user,
		fmt.Sprintf("%s/%s-%s.txt", a.wwwRoot, proto.Name, user),
	}
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			log.Printf("temizlenemedi %s: %v", path, err)
		}
	}
}

// notify sends a Telegram message when /etc/bot/.bot.db holds "#bot# <key> <chat>".
func (a *app) notify(text string) {
	lines, err := readLines(a.botDB)
	if err != nil {
		return
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "#bot# ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		api := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", fields[1])
		response, err := http.PostForm(api, url.Values{
			"chat_id":    {fields[2]},
			"text":       {text},
			"parse_mode": {"HTML"},
		})
		if err != nil {
			log.Printf("telegram bildirimi gönderilemedi: %v", err)
			return
		}
		_ = response.Body.Close()
		return
	}
}

func readLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n"), nil
}

func readUint(path string) uint64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var value uint64
	_, _ = fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &value)
	return value
}

func writeUint(path string, value uint64) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(fmt.Sprintf("%d\n", value)), 0o644)
}
