package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"vpnstack/internal/accounts"
	"vpnstack/internal/appconfig"
	"vpnstack/internal/singbox"
	"vpnstack/internal/version"
)

const (
	colorGreen = "\033[0;32m"
	colorRed   = "\033[0;31m"
	colorCyAN  = "\033[0;36m"
	colorReset = "\033[0m"
)

type check struct {
	name   string
	ok     bool
	detail string
}

func runCheck(name string, fn func() (bool, string)) check {
	ok, detail := fn()
	return check{name: name, ok: ok, detail: detail}
}

func serviceActive(name string) bool {
	return exec.Command("systemctl", "is-active", "--quiet", name).Run() == nil
}

func portOpen(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// portListener reports the process name listening on a local TCP port, or an
// empty string when the port is closed or the name cannot be determined.
// A port being open says nothing about which program holds it, and on servers
// that also run the legacy Python bridge that difference matters.
func portListener(port int) string {
	out, err := exec.Command("ss", "-ltnpH", fmt.Sprintf("sport = :%d", port)).Output()
	if err != nil {
		return ""
	}
	const marker = "users:(("
	text := string(out)
	index := strings.Index(text, marker)
	if index == -1 {
		return ""
	}
	rest := text[index+len(marker):]
	open := strings.Index(rest, "\"")
	if open == -1 {
		return ""
	}
	rest = rest[open+1:]
	if end := strings.Index(rest, "\""); end != -1 {
		return rest[:end]
	}
	return ""
}

func printChecks(checks []check) int {
	failed := 0
	for _, item := range checks {
		if item.ok {
			fmt.Printf("%s[+]%s %-26s %s\n", colorGreen, colorReset, item.name, item.detail)
			continue
		}
		failed++
		fmt.Printf("%s[x]%s %-26s %s\n", colorRed, colorReset, item.name, item.detail)
	}
	return failed
}

func cmdStatus() int {
	config, err := singbox.Load()
	inboundCount, userCount := 0, 0
	if err == nil {
		for _, inbound := range singbox.Inbounds(config) {
			inboundCount++
			userCount += len(singbox.Users(inbound))
		}
	}
	group := appconfig.Env("SSH_ACCOUNT_GROUP", appconfig.DefaultSSHGroup)
	sshUsers, sshErr := accounts.ListUsers(group)

	fmt.Printf("vpnstack %s\n", version.Full())
	fmt.Printf("Servisler : sing-box=%s ws=%s ws-ovpn=%s haproxy=%s\n",
		state(singboxService()), state(serviceActive("ws")), state(serviceActive("ws-ovpn")), state(serviceActive("haproxy")))
	fmt.Printf("Inbound   : %d düğüm, %d sing-box kullanıcısı\n", inboundCount, userCount)
	fmt.Printf("SSH       : %d hesap (%s grubu)%s\n", len(sshUsers), group, sshNote(sshErr))
	fmt.Printf("Public    : %s · REALITY: %s:443\n", appconfig.PublicHost(), appconfig.RealityHost())
	if err != nil {
		fmt.Printf("%sconfig okunamadı:%s %v\n", colorRed, colorReset, err)
		return 1
	}
	return 0
}

func singboxService() bool { return serviceActive("sing-box") }

func sshNote(err error) string {
	if err == nil {
		return ""
	}
	return " · " + colorRed + err.Error() + colorReset
}

func state(active bool) string {
	if active {
		return colorGreen + "aktif" + colorReset
	}
	return colorRed + "kapalı" + colorReset
}

func cmdDoctor() int {
	checks := []check{
		runCheck("sing-box servisi", func() (bool, string) {
			return singboxService(), "systemctl is-active sing-box"
		}),
		runCheck("ws servisi (10015)", func() (bool, string) {
			return serviceActive("ws"), "systemctl is-active ws"
		}),
		runCheck("ws-ovpn servisi (10012)", func() (bool, string) {
			return serviceActive("ws-ovpn"), "systemctl is-active ws-ovpn"
		}),
		runCheck("haproxy servisi", func() (bool, string) {
			return serviceActive("haproxy"), "80/443 ön uç"
		}),
		runCheck("fail2ban servisi", func() (bool, string) {
			if !serviceActive("fail2ban") {
				return false, "kapalı"
			}
			return true, "sshd/dropbear jails"
		}),
		runCheck("ssh servisleri", func() (bool, string) {
			dropbear := serviceActive("dropbear") || serviceActive("dropbear-vpnstack")
			sshd := serviceActive("ssh") || serviceActive("sshd")
			if !dropbear && !sshd {
				return false, "ne dropbear ne sshd"
			}
			return true, fmt.Sprintf("dropbear=%v sshd=%v", dropbear, sshd)
		}),
		// The SSH tunnel path needs dropbear on both ports: 109 is sshproxy's
		// default target, 143 is where haproxy sends raw SSH. The unit check
		// above says nothing about the ports actually being held.
		runCheck("dropbear :109", func() (bool, string) {
			if portOpen(109) {
				return true, "sshproxy hedefi"
			}
			return false, "kapalı"
		}),
		runCheck("dropbear :143", func() (bool, string) {
			if portOpen(143) {
				return true, "haproxy ham SSH arka ucu"
			}
			return false, "kapalı"
		}),
		runCheck("port 80", func() (bool, string) {
			if portOpen(80) {
				return true, "dinleniyor"
			}
			return false, "kapalı"
		}),
		runCheck("port 443", func() (bool, string) {
			if portOpen(443) {
				return true, "dinleniyor"
			}
			return false, "kapalı"
		}),
		runCheck("port 10015", func() (bool, string) {
			if !portOpen(10015) {
				return false, "kapalı"
			}
			if name := portListener(10015); name != "" && !strings.Contains(name, "sshproxy") {
				return false, fmt.Sprintf("%s dinliyor (sshproxy değil)", name)
			}
			return true, "sshproxy"
		}),
		runCheck("menu.conf", func() (bool, string) {
			if _, err := os.Stat(appconfig.MenuConfPath); err == nil {
				host, _ := appconfig.MenuConfValues()
				return true, "host: " + host
			}
			return false, appconfig.MenuConfPath + " yok"
		}),
		runCheck("sing-box config", func() (bool, string) {
			if err := singbox.Validate(singbox.ConfigFile); err != nil {
				return false, err.Error()
			}
			return true, singbox.ConfigFile
		}),
		runCheck("port çakışması", func() (bool, string) {
			config, err := singbox.Load()
			if err != nil {
				return false, err.Error()
			}
			seen := map[string]string{}
			for _, inbound := range singbox.Inbounds(config) {
				key := fmt.Sprintf("%s:%d", singbox.Listen(inbound), singbox.Port(inbound))
				if other, exists := seen[key]; exists {
					return false, fmt.Sprintf("%s ile %s aynı portta", other, singbox.Tag(inbound))
				}
				seen[key] = singbox.Tag(inbound)
			}
			return true, fmt.Sprintf("%d düğüm tekil", len(seen))
		}),
		runCheck("REALITY anahtarları", func() (bool, string) {
			config, err := singbox.Load()
			if err != nil {
				return false, err.Error()
			}
			inbounds := singbox.Inbounds(config)
			// A deployment with only TLS inbounds has no keys to show; that is
			// a valid configuration, not a fault.
			wantsReality := false
			for _, inbound := range inbounds {
				if singbox.BoolField(singbox.Reality(inbound), "enabled") {
					wantsReality = true
					break
				}
			}
			keys := singbox.RealityKeys()
			if !wantsReality {
				if len(keys) > 0 {
					return true, fmt.Sprintf("%d anahtar (REALITY inbound yok)", len(keys))
				}
				return true, "REALITY inbound yok"
			}
			if len(keys) == 0 {
				return false, "REALITY inbound var ancak anahtar türetilemiyor"
			}
			return true, fmt.Sprintf("%d anahtar", len(keys))
		}),
		runCheck("sshvpn grubu", func() (bool, string) {
			users, err := accounts.ListUsers(appconfig.Env("SSH_ACCOUNT_GROUP", appconfig.DefaultSSHGroup))
			if err != nil {
				return false, err.Error()
			}
			return true, fmt.Sprintf("%d hesap", len(users))
		}),
	}

	failed := printChecks(checks)
	if failed > 0 {
		fmt.Printf("\n%s%d kontrol başarısız.%s\n", colorRed, failed, colorReset)
		return 1
	}
	fmt.Printf("\n%sTüm kontroller başarılı.%s\n", colorGreen, colorReset)
	return 0
}

func cmdLinks(args []string) int {
	filter := ""
	if len(args) > 0 {
		filter = args[0]
	}
	config, err := singbox.Load()
	if err != nil {
		fmt.Println("config okunamadı:", err)
		return 1
	}
	found := false
	for _, inbound := range singbox.Inbounds(config) {
		tag := singbox.Tag(inbound)
		if filter != "" && filter != tag {
			continue
		}
		for _, user := range singbox.Users(inbound) {
			link := singbox.BuildLink(inbound, user)
			name := singbox.StringField(user, "name")
			if name == "" {
				name = "-"
			}
			if link == "" {
				fmt.Printf("%s (%s, %s): link desteklenmiyor\n", tag, singbox.Type(inbound), name)
			} else {
				fmt.Printf("%s (%s, %s):\n%s%s%s\n", tag, singbox.Type(inbound), name, colorCyAN, link, colorReset)
			}
			found = true
		}
	}
	if !found {
		fmt.Println("Kayıt bulunamadı.")
		return 1
	}
	return 0
}

func cmdUsers() int {
	group := appconfig.Env("SSH_ACCOUNT_GROUP", appconfig.DefaultSSHGroup)
	sshUsers, sshErr := accounts.ListUsers(group)
	sort.Strings(sshUsers)
	if sshErr != nil {
		fmt.Printf("SSH hesapları (%s): okunamadı — %v\n", group, sshErr)
	} else {
		fmt.Printf("SSH hesapları (%s): %d\n", group, len(sshUsers))
	}
	for _, user := range sshUsers {
		fmt.Printf("  %-12s %s\n", user, accounts.Expiry(user))
	}

	config, err := singbox.Load()
	if err != nil {
		fmt.Println("sing-box config okunamadı:", err)
		return 1
	}
	fmt.Println("sing-box kullanıcıları:")
	for _, inbound := range singbox.Inbounds(config) {
		users := singbox.Users(inbound)
		fmt.Printf("  %-14s %-10s :%d — %d kullanıcı\n", singbox.Tag(inbound), singbox.Type(inbound), singbox.Port(inbound), len(users))
	}
	return 0
}

func cmdBackup(args []string) int {
	dir := "/root/vpnstack-backup"
	if len(args) > 0 {
		dir = args[0]
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Println("dizin oluşturulamadı:", err)
		return 1
	}

	name := filepath.Join(dir, "vpnstack-"+time.Now().Format("20060102-150405")+".tar.gz")
	file, err := os.Create(name)
	if err != nil {
		fmt.Println("yedeK oluşturulamadı:", err)
		return 1
	}
	defer file.Close()

	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)

	files := []struct {
		source string
		target string
	}{
		{singbox.ConfigFile, "sing-box/config.json"},
		{singbox.ClientFile, "sing-box/phone_client.json"},
		{appconfig.MenuConfPath, "sshvpn/menu.conf"},
	}
	for _, item := range files {
		if err := addFile(tarWriter, item.source, item.target); err != nil && !os.IsNotExist(err) {
			fmt.Printf("uyarı: %s: %v\n", item.source, err)
		}
	}

	if users, err := accounts.ListUsers(appconfig.Env("SSH_ACCOUNT_GROUP", appconfig.DefaultSSHGroup)); err != nil {
		fmt.Printf("uyarı: SSH kullanıcı listesi alınamadı: %v\n", err)
	} else {
		content := strings.Join(users, "\n") + "\n"
		_ = tarWriter.WriteHeader(&tar.Header{Name: "sshvpn/users.txt", Mode: 0o600, Size: int64(len(content)), ModTime: time.Now()})
		_, _ = tarWriter.Write([]byte(content))
	}

	meta := fmt.Sprintf("version=%s\ndate=%s\n", version.Full(), time.Now().Format(time.RFC3339))
	_ = tarWriter.WriteHeader(&tar.Header{Name: "meta.txt", Mode: 0o600, Size: int64(len(meta)), ModTime: time.Now()})
	_, _ = tarWriter.Write([]byte(meta))

	if err := tarWriter.Close(); err != nil {
		fmt.Println("arşiv kapatılamadı:", err)
		return 1
	}
	if err := gzipWriter.Close(); err != nil {
		fmt.Println("arşiv kapatılamadı:", err)
		return 1
	}
	fmt.Printf("%sYedek alındı:%s %s\n", colorGreen, colorReset, name)
	return 0
}

func addFile(tarWriter *tar.Writer, source, target string) error {
	info, err := os.Stat(source)
	if err != nil {
		return err
	}
	file, err := os.Open(source)
	if err != nil {
		return err
	}
	defer file.Close()
	header := &tar.Header{Name: target, Mode: int64(info.Mode().Perm()), Size: info.Size(), ModTime: info.ModTime()}
	if err := tarWriter.WriteHeader(header); err != nil {
		return err
	}
	_, err = io.Copy(tarWriter, file)
	return err
}

func cmdRestore(args []string) int {
	if len(args) == 0 {
		fmt.Println("Kullanım: vpnctl restore <yedek.tar.gz> [--yes]")
		return 2
	}
	source := args[0]
	assumeYes := false
	for _, arg := range args[1:] {
		if arg == "--yes" || arg == "-y" {
			assumeYes = true
		}
	}

	if !assumeYes {
		fmt.Printf("%s, %s ve %s geri yüklenecek. Devam? (e/H): ", singbox.ConfigFile, singbox.ClientFile, appconfig.MenuConfPath)
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(answer)), "e") {
			fmt.Println("İptal edildi.")
			return 0
		}
	}

	file, err := os.Open(source)
	if err != nil {
		fmt.Println("yedek açılamadı:", err)
		return 1
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		fmt.Println("gzip hatası:", err)
		return 1
	}
	defer gzipReader.Close()

	restored := 0
	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Println("arşiv hatası:", err)
			return 1
		}
		var target string
		switch header.Name {
		case "sing-box/config.json":
			target = singbox.ConfigFile
		case "sing-box/phone_client.json":
			target = singbox.ClientFile
		case "sshvpn/menu.conf":
			target = appconfig.MenuConfPath
		default:
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			fmt.Printf("dizin hatası %s: %v\n", target, err)
			return 1
		}
		tmp := target + ".restore.tmp"
		out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			fmt.Printf("yazma hatası %s: %v\n", target, err)
			return 1
		}
		if _, err := io.Copy(out, tarReader); err != nil {
			_ = out.Close()
			_ = os.Remove(tmp)
			fmt.Printf("kopyalama hatası %s: %v\n", target, err)
			return 1
		}
		_ = out.Close()
		if target == singbox.ConfigFile {
			if err := singbox.Validate(tmp); err != nil {
				_ = os.Remove(tmp)
				fmt.Println("yedek config geçersiz:", err)
				return 1
			}
		}
		if err := os.Rename(tmp, target); err != nil {
			fmt.Printf("değiştirme hatası %s: %v\n", target, err)
			return 1
		}
		fmt.Printf("%s[+]%s %s geri yüklendi\n", colorGreen, colorReset, target)
		restored++
	}

	if restored == 0 {
		fmt.Println("Yedekte bilinen dosya yok.")
		return 1
	}
	if err := singbox.Reload(); err != nil {
		fmt.Println("sing-box yeniden başlatılamadı:", err)
		return 1
	}
	fmt.Printf("%sGeri yükleme tamam (%d dosya).%s\n", colorGreen, restored, colorReset)
	return 0
}
