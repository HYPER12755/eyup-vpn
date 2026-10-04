package main

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"vpnstack/internal/version"
)

const (
	bufLen        = 4096 * 4
	selectTimeout = 3 * time.Second
	idleTicks     = 60
	defaultHost   = "127.0.0.1:109"
	pass          = ""
)

func buildResponse(head string) []byte {
	accept := "foo"
	if key := findHeader(head, "Sec-WebSocket-Key"); key != "" {
		accept = websocketAccept(key)
	}
	return []byte("HTTP/1.1 101 <font color=\"green\">SCRIPT BY PUSAT BLITAR</b></font>\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n")
}

func main() {
	listenAddr := "127.0.0.1"
	listenPort := 10015

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-h":
			printUsage()
			return
		case "-v", "--version", "version":
			fmt.Printf("sshproxy %s\n", version.Full())
			return
		case "-b", "--bind":
			if i+1 < len(args) {
				i++
				listenAddr = args[i]
			}
		case "-p", "--port":
			if i+1 < len(args) {
				i++
				if parsed, err := strconv.Atoi(args[i]); err == nil {
					listenPort = parsed
				}
			}
		default:
			if parsed, err := strconv.Atoi(args[i]); err == nil {
				listenPort = parsed
			}
		}
	}

	listener, err := net.Listen("tcp", net.JoinHostPort(listenAddr, strconv.Itoa(listenPort)))
	if err != nil {
		slog.Error("sshproxy: listen failed", "addr", listenAddr, "port", listenPort, "err", err)
		os.Exit(1)
	}

	slog.Info("sshproxy started", "version", version.Full(), "addr", listenAddr, "port", listenPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleConn(conn, listenPort)
	}
}

func printUsage() {
	fmt.Println("Usage: sshproxy [port]")
	fmt.Println("       sshproxy -p <port>")
	fmt.Println("       sshproxy -b <bindAddr> -p <port>")
	fmt.Println("       sshproxy -b 0.0.0.0 -p 80")
}

func handleConn(client net.Conn, listenPort int) {
	clientBuffer := make([]byte, bufLen)
	n, err := client.Read(clientBuffer)
	if err != nil {
		_ = client.Close()
		return
	}
	head := string(clientBuffer[:n])

	hostPort := findHeader(head, "X-Real-Host")
	if hostPort == "" {
		hostPort = defaultHost
	}

	if findHeader(head, "X-Split") != "" {
		extra := make([]byte, bufLen)
		_, _ = client.Read(extra)
	}

	if hostPort == "" {
		_, _ = client.Write([]byte("HTTP/1.1 400 NoXRealHost!\r\n\r\n"))
		_ = client.Close()
		return
	}

	password := findHeader(head, "X-Pass")
	if pass != "" && password == pass {
		// password mode: any target allowed
	} else if pass != "" && password != pass {
		_, _ = client.Write([]byte("HTTP/1.1 400 WrongPass!\r\n\r\n"))
		_ = client.Close()
		return
	} else if !isLocalHost(hostPort) {
		_, _ = client.Write([]byte("HTTP/1.1 403 Forbidden!\r\n\r\n"))
		_ = client.Close()
		return
	}

	targetAddr := targetAddress(hostPort, listenPort)
	target, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		slog.Warn("sshproxy: dial target failed", "client", client.RemoteAddr().String(), "target", hostPort, "err", err)
		_ = client.Close()
		return
	}
	defer target.Close()
	defer client.Close()

	slog.Info("sshproxy: connection", "client", client.RemoteAddr().String(), "target", hostPort)

	if _, err := client.Write(buildResponse(head)); err != nil {
		return
	}

	reader := bufio.NewReader(client)
	if findHeader(head, "Sec-WebSocket-Key") != "" {
		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, peekErr := reader.Peek(1)
		_ = client.SetReadDeadline(time.Time{})
		if peekErr == nil && !detectWebSocket(reader) {
			proxy(client, reader, target)
			return
		}
		proxyWebSocket(client, reader, target)
		return
	}
	proxy(client, reader, target)
}

func isLocalHost(hostPort string) bool {
	return strings.HasPrefix(hostPort, "127.0.0.1") || strings.HasPrefix(hostPort, "localhost")
}

func targetAddress(hostPort string, listenPort int) string {
	index := strings.Index(hostPort, ":")
	if index == -1 {
		return net.JoinHostPort(hostPort, strconv.Itoa(443))
	}
	host := hostPort[:index]
	port, err := strconv.Atoi(hostPort[index+1:])
	if err != nil || port < 1 || port > 65535 {
		return net.JoinHostPort(host, strconv.Itoa(listenPort))
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func findHeader(head, header string) string {
	aux := strings.Index(head, header+": ")
	if aux == -1 {
		return ""
	}
	offset := strings.Index(head[aux:], ":")
	if offset == -1 {
		return ""
	}
	aux += offset
	head = head[aux+2:]
	aux = strings.Index(head, "\r\n")
	if aux == -1 {
		return ""
	}
	return head[:aux]
}

func proxy(client net.Conn, clientReader io.Reader, target net.Conn) {
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())

	done := make(chan struct{}, 2)
	go copyStream(client, target, &lastActivity, done)
	go copyStream(target, clientReader, &lastActivity, done)

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		ticker := time.NewTicker(selectTimeout)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				last := time.Unix(0, lastActivity.Load())
				if time.Since(last) > selectTimeout*idleTicks {
					_ = client.Close()
					_ = target.Close()
					return
				}
			}
		}
	}()

	<-done
	_ = client.Close()
	_ = target.Close()
	<-done
}

func copyStream(dst net.Conn, src io.Reader, lastActivity *atomic.Int64, done chan<- struct{}) {
	defer func() { done <- struct{}{} }()

	buffer := make([]byte, bufLen)
	for {
		n, err := src.Read(buffer)
		if n > 0 {
			lastActivity.Store(time.Now().UnixNano())
			if _, writeErr := dst.Write(buffer[:n]); writeErr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}
