package main

import (
	"fmt"
	"os"

	"vpnstack/internal/version"
)

const usageText = `vpnctl — VPN stack yönetim aracı

Kullanım:
  vpnctl status            Servis ve düğüm özeti
  vpnctl doctor            Sağlık kontrolü (sorun varsa çıkış kodu 1)
  vpnctl links [tag]       Inbound kullanıcı bağlantı linkleri
  vpnctl users             SSH ve sing-box kullanıcıları
  vpnctl backup [dizin]    Yapılandırma yedeği (varsayılan /root/vpnstack-backup)
  vpnctl restore <dosya>   Yedeği geri yükle (--yes ile onaysız)
  vpnctl version           Sürüm bilgisi
`

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Print(usageText)
		os.Exit(2)
	}

	switch args[0] {
	case "version", "--version", "-v":
		fmt.Printf("vpnctl %s\n", version.Full())
	case "status":
		os.Exit(cmdStatus())
	case "doctor":
		os.Exit(cmdDoctor())
	case "links":
		os.Exit(cmdLinks(args[1:]))
	case "users":
		os.Exit(cmdUsers())
	case "backup":
		os.Exit(cmdBackup(args[1:]))
	case "restore":
		os.Exit(cmdRestore(args[1:]))
	case "help", "--help", "-h":
		fmt.Print(usageText)
	default:
		fmt.Print(usageText)
		os.Exit(2)
	}
}
