package singbox

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/curve25519"

	"vpnstack/internal/appconfig"
)

var (
	ConfigFile = appconfig.SingboxConfigPath
	ClientFile = appconfig.SingboxClientPath
	Binary     = appconfig.SingboxBinary

	Reload = func() error {
		if output, err := exec.Command("systemctl", "restart", "sing-box").CombinedOutput(); err != nil {
			return fmt.Errorf("sing-box yeniden başlatılamadı: %s", strings.TrimSpace(string(output)))
		}
		return nil
	}
	Validate = func(path string) error {
		if _, err := os.Stat(Binary); err != nil {
			return nil
		}
		if output, err := exec.Command(Binary, "check", "-c", path).CombinedOutput(); err != nil {
			return fmt.Errorf("config doğrulaması başarısız: %s", strings.TrimSpace(string(output)))
		}
		return nil
	}
)

type UserAccount struct {
	Inbound   string `json:"inbound"`
	Type      string `json:"type"`
	Name      string `json:"name"`
	UUID      string `json:"uuid,omitempty"`
	Password  string `json:"password,omitempty"`
	Expires   string `json:"expires"`
	CreatedAt string `json:"created_at"`
}

func Load() (map[string]any, error) {
	data, err := os.ReadFile(ConfigFile)
	if err != nil {
		return nil, err
	}
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	return config, nil
}

func Save(config map[string]any) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(ConfigFile)
	tmp, err := os.CreateTemp(dir, ".singbox-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	discard := func() {
		_ = tmp.Close()
		_ = os.Remove(name)
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		discard()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		discard()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := Validate(name); err != nil {
		_ = os.Remove(name)
		return err
	}
	return os.Rename(name, ConfigFile)
}

func Inbounds(config map[string]any) []map[string]any {
	raw, ok := config["inbounds"].([]any)
	if !ok {
		return nil
	}
	result := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		if inbound, ok := item.(map[string]any); ok {
			result = append(result, inbound)
		}
	}
	return result
}

func Users(inbound map[string]any) []map[string]any {
	raw, ok := inbound["users"].([]any)
	if !ok {
		return nil
	}
	result := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		if user, ok := item.(map[string]any); ok {
			result = append(result, user)
		}
	}
	return result
}

func Tag(inbound map[string]any) string  { return StringField(inbound, "tag") }
func Type(inbound map[string]any) string { return StringField(inbound, "type") }

func Listen(inbound map[string]any) string { return StringField(inbound, "listen") }

func Port(inbound map[string]any) int {
	if value, ok := inbound["listen_port"].(float64); ok {
		return int(value)
	}
	return 0
}

func Transport(inbound map[string]any) map[string]any {
	value, _ := inbound["transport"].(map[string]any)
	return value
}

func TLS(inbound map[string]any) map[string]any {
	value, _ := inbound["tls"].(map[string]any)
	return value
}

func Reality(inbound map[string]any) map[string]any {
	value, _ := TLS(inbound)["reality"].(map[string]any)
	return value
}

func StringField(values map[string]any, key string) string {
	if values == nil {
		return ""
	}
	value, _ := values[key].(string)
	return value
}

func BoolField(values map[string]any, key string) bool {
	if values == nil {
		return false
	}
	value, _ := values[key].(bool)
	return value
}

func DerivePublicKey(privateKey string) string {
	priv, err := base64.RawURLEncoding.DecodeString(privateKey)
	if err != nil || len(priv) != 32 {
		return ""
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(pub)
}

type RealityKey struct {
	Tag       string
	PublicKey string
}

func RealityKeys() []RealityKey {
	config, err := Load()
	if err != nil {
		return nil
	}
	keys := make([]RealityKey, 0, 4)
	for _, inbound := range Inbounds(config) {
		reality := Reality(inbound)
		if !BoolField(reality, "enabled") {
			continue
		}
		if publicKey := DerivePublicKey(StringField(reality, "private_key")); publicKey != "" {
			keys = append(keys, RealityKey{Tag: Tag(inbound), PublicKey: publicKey})
		}
	}
	return keys
}

func IsLoopback(inbound map[string]any) bool {
	listen := Listen(inbound)
	return strings.HasPrefix(listen, "127.") || listen == "::1" || listen == "localhost"
}

func buildQuery(inbound map[string]any, user map[string]any) string {
	network := "tcp"
	if transport := Transport(inbound); transport != nil {
		if value := StringField(transport, "type"); value != "" {
			network = value
		}
	}

	tls := TLS(inbound)
	reality := Reality(inbound)
	sni := StringField(tls, "server_name")

	query := "type=" + network + "&security=none"
	if BoolField(tls, "enabled") {
		query = "type=" + network + "&security=tls&sni=" + sni
	}
	if BoolField(reality, "enabled") {
		query = fmt.Sprintf("type=%s&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s",
			network, sni, DerivePublicKey(StringField(reality, "private_key")), firstShortID(reality))
	}
	if flow := StringField(user, "flow"); flow != "" {
		query += "&flow=" + flow
	}
	if transport := Transport(inbound); transport != nil {
		if path := StringField(transport, "path"); path != "" {
			query += "&path=" + path
		}
	}
	return query
}

func BuildLink(inbound map[string]any, user map[string]any) string {
	host := appconfig.PublicHost()
	port := Port(inbound)

	tls := TLS(inbound)
	reality := Reality(inbound)
	if BoolField(reality, "enabled") && IsLoopback(inbound) {
		host = appconfig.RealityHost()
		port = 443
	}

	tag := Tag(inbound)
	sni := StringField(tls, "server_name")

	switch Type(inbound) {
	case "vless":
		return fmt.Sprintf("vless://%s@%s:%d?%s#%s", StringField(user, "uuid"), host, port, buildQuery(inbound, user), tag)
	case "vmess":
		network := "tcp"
		if transport := Transport(inbound); transport != nil {
			if value := StringField(transport, "type"); value != "" {
				network = value
			}
		}
		payload := map[string]string{
			"v": "2", "ps": tag + "-" + StringField(user, "name"), "add": host,
			"port": strconv.Itoa(port), "id": StringField(user, "uuid"), "aid": "0",
			"scy": "auto", "net": network, "type": "none", "host": sni, "tls": "tls",
		}
		data, _ := json.Marshal(payload)
		return "vmess://" + base64.StdEncoding.EncodeToString(data)
	case "trojan":
		return fmt.Sprintf("trojan://%s@%s:%d?security=tls&sni=%s#%s", StringField(user, "password"), host, port, sni, tag)
	case "tuic":
		return fmt.Sprintf("tuic://%s:%s@%s:%d?congestion_control=bbr&alpn=h3&sni=%s#%s",
			StringField(user, "uuid"), StringField(user, "password"), host, port, sni, tag)
	case "hysteria2":
		return fmt.Sprintf("hysteria2://%s@%s:%d/?sni=%s#%s", StringField(user, "password"), host, port, sni, tag)
	default:
		return ""
	}
}

func AddUser(inboundIndex int, days int) (UserAccount, string, error) {
	config, err := Load()
	if err != nil {
		return UserAccount{}, "", err
	}
	inbounds := Inbounds(config)
	if inboundIndex < 0 || inboundIndex >= len(inbounds) {
		return UserAccount{}, "", errors.New("geçersiz inbound")
	}
	inbound := inbounds[inboundIndex]

	name, err := randomUserName()
	if err != nil {
		return UserAccount{}, "", err
	}

	user, err := newUser(inbound, name)
	if err != nil {
		return UserAccount{}, "", err
	}
	if Type(inbound) == "vless" {
		if users := Users(inbound); len(users) > 0 {
			if flow := StringField(users[0], "flow"); flow != "" {
				user["flow"] = flow
			}
		}
	}

	if raw, ok := inbound["users"].([]any); ok {
		inbound["users"] = append(raw, user)
	} else {
		inbound["users"] = []any{user}
	}

	if err := Save(config); err != nil {
		return UserAccount{}, "", err
	}
	if err := Reload(); err != nil {
		return UserAccount{}, "", err
	}

	expires := "Süresiz"
	if days > 0 {
		expires = time.Now().AddDate(0, 0, days).Format("2006-01-02")
	}

	account := UserAccount{
		Inbound:   Tag(inbound),
		Type:      Type(inbound),
		Name:      name,
		UUID:      StringField(user, "uuid"),
		Password:  StringField(user, "password"),
		Expires:   expires,
		CreatedAt: time.Now().Format(time.RFC3339),
	}
	return account, BuildLink(inbound, user), nil
}

func RemoveUser(inboundIndex int, userIndex int) (string, error) {
	config, err := Load()
	if err != nil {
		return "", err
	}
	inbounds := Inbounds(config)
	if inboundIndex < 0 || inboundIndex >= len(inbounds) {
		return "", errors.New("geçersiz inbound")
	}
	inbound := inbounds[inboundIndex]
	raw, ok := inbound["users"].([]any)
	if !ok || userIndex < 0 || userIndex >= len(raw) {
		return "", errors.New("geçersiz kullanıcı")
	}
	user, _ := raw[userIndex].(map[string]any)
	name := StringField(user, "name")

	filtered := make([]any, 0, len(raw)-1)
	for i, item := range raw {
		if i == userIndex {
			continue
		}
		filtered = append(filtered, item)
	}
	inbound["users"] = filtered

	if err := Save(config); err != nil {
		return "", err
	}
	if err := Reload(); err != nil {
		return "", err
	}
	return name, nil
}

func RemoveUserByName(name string) (bool, error) {
	config, err := Load()
	if err != nil {
		return false, err
	}
	removed := false
	for _, inbound := range Inbounds(config) {
		raw, ok := inbound["users"].([]any)
		if !ok {
			continue
		}
		filtered := make([]any, 0, len(raw))
		for _, item := range raw {
			user, _ := item.(map[string]any)
			if StringField(user, "name") == name {
				removed = true
				continue
			}
			filtered = append(filtered, item)
		}
		if len(filtered) != len(raw) {
			inbound["users"] = filtered
		}
	}
	if !removed {
		return false, nil
	}
	if err := Save(config); err != nil {
		return false, err
	}
	if err := Reload(); err != nil {
		return false, err
	}
	return true, nil
}

func newUser(inbound map[string]any, name string) (map[string]any, error) {
	switch Type(inbound) {
	case "vless", "vmess":
		return map[string]any{"name": name, "uuid": uuid.NewString()}, nil
	case "hysteria2", "trojan", "shadowtls", "shadowsocks", "anytls", "snell":
		password, err := randomPassword()
		if err != nil {
			return nil, err
		}
		return map[string]any{"name": name, "password": password}, nil
	case "tuic":
		password, err := randomPassword()
		if err != nil {
			return nil, err
		}
		return map[string]any{"name": name, "uuid": uuid.NewString(), "password": password}, nil
	default:
		return nil, fmt.Errorf("bu protokol için kullanıcı ekleme desteklenmiyor: %s", Type(inbound))
	}
}

func randomUserName() (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	buf := make([]byte, 5)
	for i := range buf {
		index, err := randInt(len(alphabet))
		if err != nil {
			return "", err
		}
		buf[i] = alphabet[index]
	}
	return "tg" + string(buf), nil
}

func randomPassword() (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	buf := make([]byte, 8)
	for i := range buf {
		index, err := randInt(len(alphabet))
		if err != nil {
			return "", err
		}
		buf[i] = alphabet[index]
	}
	return string(buf), nil
}

func randInt(max int) (int, error) {
	value, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(value.Int64()), nil
}

func firstShortID(reality map[string]any) string {
	if reality == nil {
		return ""
	}
	ids, ok := reality["short_id"].([]any)
	if !ok || len(ids) == 0 {
		return ""
	}
	value, _ := ids[0].(string)
	return value
}
