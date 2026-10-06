package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"vpnstack/internal/version"
)

const (
	bufLen          = 4096 * 4
	maxHeadLen      = 64 * 1024
	headerTimeout   = 10 * time.Second
	splitTimeout    = 2 * time.Second
	selectTimeout   = 3 * time.Second
	idleTicks       = 60
	defaultHost     = "127.0.0.1:109"
	pass            = ""
	keepAlivePeriod = 60 * time.Second
	shutdownGrace   = 10 * time.Second
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
	maxConns := 0

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
		case "--maxconns":
			if i+1 < len(args) {
				i++
				if parsed, err := strconv.Atoi(args[i]); err == nil {
					maxConns = parsed
				}
			}
		default:
			if parsed, err := strconv.Atoi(args[i]); err == nil {
				listenPort = parsed
			}
		}
	}
	if maxConns == 0 {
		maxConns = envInt("SSHPROXY_MAX_CONNS", 0)
	}

	listener, err := net.Listen("tcp", net.JoinHostPort(listenAddr, strconv.Itoa(listenPort)))
	if err != nil {
		slog.Error("sshproxy: listen failed", "addr", listenAddr, "port", listenPort, "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	slog.Info("sshproxy started", "version", version.Full(), "addr", listenAddr, "port", listenPort, "maxconns", maxConns)

	serve(ctx, listener, listenPort, maxConns)
}

// serve accepts and relays connections until ctx is cancelled, then lets
// in-flight tunnels drain for up to shutdownGrace before the process exits.
func serve(ctx context.Context, listener net.Listener, listenPort, maxConns int) {
	limiter := newLimiter(maxConns)

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	var wg sync.WaitGroup
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			slog.Error("sshproxy: accept failed", "err", err)
			break
		}
		if !limiter.acquire(ctx) {
			_ = conn.Close()
			continue
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer limiter.release()
			handleConn(c, listenPort)
		}(conn)
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		slog.Info("sshproxy: stopped")
	case <-time.After(shutdownGrace):
		slog.Warn("sshproxy: shutdown deadline reached, dropping active connections")
	}
}

// connLimiter caps concurrent connections with a counting semaphore. A nil
// limiter means no cap.
type connLimiter chan struct{}

func newLimiter(max int) connLimiter {
	if max <= 0 {
		return nil
	}
	return make(connLimiter, max)
}

func (l connLimiter) acquire(ctx context.Context) bool {
	if l == nil {
		return true
	}
	select {
	case l <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (l connLimiter) release() {
	if l != nil {
		<-l
	}
}

func envInt(key string, fallback int) int {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return fallback
}

func printUsage() {
	fmt.Println("Usage: sshproxy [port]")
	fmt.Println("       sshproxy -p <port>")
	fmt.Println("       sshproxy -b <bindAddr> -p <port>")
	fmt.Println("       sshproxy --maxconns <n>     (0 = unlimited, default)")
	fmt.Println("       sshproxy -b 0.0.0.0 -p 80")
}

// readHead reads the request head up to the blank line and leaves anything the
// client pipelined behind it in the reader, so the forwarding loop still sees
// the first payload bytes.
func readHead(reader *bufio.Reader, conn net.Conn) (string, error) {
	_ = conn.SetReadDeadline(time.Now().Add(headerTimeout))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	var head strings.Builder
	for head.Len() < maxHeadLen {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		head.WriteString(line)
		if line == "\r\n" || line == "\n" {
			return head.String(), nil
		}
	}
	return "", errors.New("sshproxy: request head too large")
}

func handleConn(client net.Conn, listenPort int) {
	setKeepAlive(client)
	reader := bufio.NewReader(client)

	head, err := readHead(reader, client)
	if err != nil {
		_ = client.Close()
		return
	}

	hostPort := findHeader(head, "X-Real-Host")
	if hostPort == "" {
		hostPort = defaultHost
	}

	if findHeader(head, "X-Split") != "" {
		// X-Split means the client's first data packet arrives separately. The
		// wait is bounded so a client that blocks on our 101 cannot deadlock.
		_ = client.SetReadDeadline(time.Now().Add(splitTimeout))
		_, _ = reader.Read(make([]byte, bufLen))
		_ = client.SetReadDeadline(time.Time{})
	}

	if pass != "" {
		if findHeader(head, "X-Pass") != pass {
			_, _ = client.Write([]byte("HTTP/1.1 400 WrongPass!\r\n\r\n"))
			_ = client.Close()
			return
		}
	} else if !isLocalHost(hostPort) {
		_, _ = client.Write([]byte("HTTP/1.1 403 Forbidden!\r\n\r\n"))
		_ = client.Close()
		return
	}

	targetAddr, err := targetAddress(hostPort)
	if err != nil {
		_, _ = client.Write([]byte("HTTP/1.1 400 BadTarget!\r\n\r\n"))
		_ = client.Close()
		return
	}

	target, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		slog.Warn("sshproxy: dial target failed", "client", client.RemoteAddr().String(), "target", hostPort, "err", err)
		_ = client.Close()
		return
	}
	setKeepAlive(target)
	defer target.Close()
	defer client.Close()

	slog.Info("sshproxy: connection", "client", client.RemoteAddr().String(), "target", hostPort)

	if _, err := client.Write(buildResponse(head)); err != nil {
		return
	}

	if findHeader(head, "Sec-WebSocket-Key") != "" {
		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, peekErr := reader.Peek(1)
		_ = client.SetReadDeadline(time.Time{})
		if peekErr != nil || !detectWebSocket(reader) {
			proxy(client, reader, target)
			return
		}
		proxyWebSocket(client, reader, target)
		return
	}
	proxy(client, reader, target)
}

// isLocalHost reports whether hostPort points at the loopback interface. It
// compares parsed addresses rather than prefixes, so names such as
// "localhost.attacker.example" are not accepted.
func isLocalHost(hostPort string) bool {
	host, _, _ := splitHostPort(hostPort)
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// splitHostPort separates host and port, accepting the bracketed IPv6 form
// ("[::1]:109"). net.SplitHostPort is deliberately not used: it rejects a
// missing port, but X-Real-Host may legitimately omit it. hasPort reports
// whether a separator was present at all, so "host:" stays an error rather
// than being silently completed to the default port.
func splitHostPort(hostPort string) (host, port string, hasPort bool) {
	if strings.HasPrefix(hostPort, "[") {
		if end := strings.Index(hostPort, "]"); end != -1 {
			host = hostPort[1:end]
			rest := hostPort[end+1:]
			if strings.HasPrefix(rest, ":") {
				return host, rest[1:], true
			}
			return host, "", false
		}
	}
	index := strings.Index(hostPort, ":")
	if index == -1 {
		return hostPort, "", false
	}
	return hostPort[:index], hostPort[index+1:], true
}

func targetAddress(hostPort string) (string, error) {
	host, port, hasPort := splitHostPort(hostPort)
	if host == "" {
		return "", fmt.Errorf("sshproxy: geçersiz hedef %q", hostPort)
	}
	if !hasPort {
		return net.JoinHostPort(host, strconv.Itoa(443)), nil
	}
	parsed, err := strconv.Atoi(port)
	if err != nil || parsed < 1 || parsed > 65535 {
		return "", fmt.Errorf("sshproxy: geçersiz hedef %q", hostPort)
	}
	return net.JoinHostPort(host, strconv.Itoa(parsed)), nil
}

// findHeader returns the value of a request header. Header names are matched
// case-insensitively (HTTP/2 requires lowercase, and clients differ) and only
// against a line's own name field, so a value that merely mentions the header
// (Referer: http://host/X-Real-Host: evil) is not mistaken for the real thing.
func findHeader(head, header string) string {
	want := strings.ToLower(header)
	for head != "" {
		var line string
		if index := strings.Index(head, "\n"); index != -1 {
			line, head = head[:index+1], head[index+1:]
		} else {
			line, head = head, ""
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return ""
		}
		name, value, found := strings.Cut(line, ":")
		if !found || strings.ToLower(strings.TrimSpace(name)) != want {
			continue
		}
		return strings.TrimSpace(value)
	}
	return ""
}

func proxy(client net.Conn, clientReader io.Reader, target net.Conn) {
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())

	done := make(chan struct{}, 2)
	go copyStream(client, target, &lastActivity, done)
	go copyStream(target, clientReader, &lastActivity, done)

	stop := make(chan struct{})
	defer close(stop)
	startIdleReaper(&lastActivity, stop, func() {
		_ = client.Close()
		_ = target.Close()
	})

	<-done
	_ = client.Close()
	_ = target.Close()
	<-done
}

// startIdleReaper closes both ends of a relay once no byte has moved for
// selectTimeout*idleTicks. It gives the WebSocket path the same idle bound the
// raw path always had, so an idle tunnel cannot pin a goroutine forever when
// haproxy's tunnel timeout is absent (e.g. direct :10015 use).
func startIdleReaper(lastActivity *atomic.Int64, stop <-chan struct{}, closeAll func()) {
	go func() {
		ticker := time.NewTicker(selectTimeout)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if time.Since(time.Unix(0, lastActivity.Load())) > selectTimeout*idleTicks {
					closeAll()
					return
				}
			}
		}
	}()
}

func setKeepAlive(conn net.Conn) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tcp.SetKeepAlive(true)
	_ = tcp.SetKeepAlivePeriod(keepAlivePeriod)
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
