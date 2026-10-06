package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestFindHeader(t *testing.T) {
	head := "CONNECT / HTTP/1.1\r\nX-Real-Host: 127.0.0.1:109\r\nX-Split: 1\r\nX-Pass: abc\r\n\r\n"
	if got := findHeader(head, "X-Real-Host"); got != "127.0.0.1:109" {
		t.Fatalf("unexpected X-Real-Host: %q", got)
	}
	if got := findHeader(head, "X-Split"); got != "1" {
		t.Fatalf("unexpected X-Split: %q", got)
	}
	if got := findHeader(head, "X-Pass"); got != "abc" {
		t.Fatalf("unexpected X-Pass: %q", got)
	}
	if got := findHeader(head, "X-Missing"); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestTargetAddress(t *testing.T) {
	if got, err := targetAddress("127.0.0.1:109"); err != nil || got != "127.0.0.1:109" {
		t.Fatalf("unexpected target: %q (%v)", got, err)
	}
	if got, err := targetAddress("localhost:22"); err != nil || got != "localhost:22" {
		t.Fatalf("unexpected target: %q (%v)", got, err)
	}
	if got, err := targetAddress("127.0.0.1"); err != nil || got != "127.0.0.1:443" {
		t.Fatalf("unexpected target: %q (%v)", got, err)
	}
	// The bracketed IPv6 form must be parsed, not mistaken for a host with an
	// unparsable port.
	if got, err := targetAddress("[::1]:109"); err != nil || got != "[::1]:109" {
		t.Fatalf("unexpected IPv6 target: %q (%v)", got, err)
	}
	if got, err := targetAddress("[::1]"); err != nil || got != "[::1]:443" {
		t.Fatalf("unexpected IPv6 target without port: %q (%v)", got, err)
	}
	if _, err := targetAddress("[]:109"); err == nil {
		t.Fatal("empty IPv6 host must be rejected")
	}
	// An unparsable port must be rejected, never silently redirected to the
	// proxy's own listener.
	for _, bad := range []string{"127.0.0.1:notaport", "127.0.0.1:", "127.0.0.1:0", "127.0.0.1:99999"} {
		if _, err := targetAddress(bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}

func TestIsLocalHost(t *testing.T) {
	if !isLocalHost("127.0.0.1:109") || !isLocalHost("localhost:22") {
		t.Fatal("local hosts must be allowed")
	}
	// Loopback in its bracketed IPv6 form must be recognised, otherwise a
	// legitimate [::1] target is refused as remote.
	if !isLocalHost("[::1]:109") {
		t.Fatal("IPv6 loopback must be allowed")
	}
	if isLocalHost("example.com:22") || isLocalHost("8.8.8.8:443") {
		t.Fatal("remote hosts must be rejected without password")
	}
	// Prefix matching must not be mistaken for a loopback address.
	for _, spoofed := range []string{
		"localhost.attacker.example:22",
		"127.0.0.1.attacker.example:22",
		"127.0.0.10.evil:22",
		"notlocalhost:22",
	} {
		if isLocalHost(spoofed) {
			t.Fatalf("spoofed host accepted: %q", spoofed)
		}
	}
}

// HTTP/2 mandates lowercase header names, and clients are inconsistent, so
// name matching must not be case-sensitive.
func TestFindHeaderIsCaseInsensitive(t *testing.T) {
	head := "CONNECT / HTTP/1.1\r\nx-real-host: 127.0.0.1:109\r\nX-split: 1\r\nx-PASS: abc\r\n\r\n"
	if got := findHeader(head, "X-Real-Host"); got != "127.0.0.1:109" {
		t.Fatalf("unexpected X-Real-Host: %q", got)
	}
	if got := findHeader(head, "X-Split"); got != "1" {
		t.Fatalf("unexpected X-Split: %q", got)
	}
	if got := findHeader(head, "X-Pass"); got != "abc" {
		t.Fatalf("unexpected X-Pass: %q", got)
	}
}

// A header name appearing inside another header's value must not be read as a
// real header: "Referer: .../X-Real-Host: 8.8.8.8:53" would otherwise inject a
// target and bypass the loopback guard.
func TestFindHeaderIgnoresInjectionInValue(t *testing.T) {
	head := "GET / HTTP/1.1\r\nHost: proxy\r\nReferer: http://proxy/X-Real-Host: 8.8.8.8:53\r\nX-Real-Host: 127.0.0.1:109\r\n\r\n"
	if got := findHeader(head, "X-Real-Host"); got != "127.0.0.1:109" {
		t.Fatalf("header read out of another header's value: %q", got)
	}
	// With no genuine header present, the injected one must not be found at all.
	head = "GET / HTTP/1.1\r\nHost: proxy\r\nReferer: http://proxy/X-Real-Host: 8.8.8.8:53\r\n\r\n"
	if got := findHeader(head, "X-Real-Host"); got != "" {
		t.Fatalf("injected header accepted: %q", got)
	}
}

// The request head may arrive in several TCP segments; the proxy must still
// see the headers.
func TestHandleConnSplitRequest(t *testing.T) {
	echo := startEchoServer(t)
	bridge := startBridgeServer(t)

	client, err := net.DialTimeout("tcp", bridge.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	request := fmt.Sprintf("GET / HTTP/1.1\r\nHost: x\r\nX-Real-Host: 127.0.0.1:%d\r\n\r\n", echoPort(t, echo))
	// Split inside the X-Real-Host header value.
	for _, chunk := range []string{request[:40], request[40:]} {
		if _, err := client.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	reader := bufio.NewReader(client)
	readSwitch(t, reader)

	payload := []byte("SSH-2.0-split\r\n")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	assertEcho(t, reader, payload)
}

// Bytes sent in the same segment as the request head must survive: the header
// read stops at the blank line and leaves the rest buffered for forwarding.
func TestHandleConnPreservesPipelinedData(t *testing.T) {
	echo := startEchoServer(t)
	bridge := startBridgeServer(t)

	client, err := net.DialTimeout("tcp", bridge.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	request := fmt.Sprintf("GET / HTTP/1.1\r\nHost: x\r\nX-Real-Host: 127.0.0.1:%d\r\n\r\n", echoPort(t, echo))
	payload := []byte("SSH-2.0-bannerr")
	if _, err := client.Write(append([]byte(request), payload...)); err != nil {
		t.Fatal(err)
	}

	reader := bufio.NewReader(client)
	readSwitch(t, reader)
	assertEcho(t, reader, payload)
}

// Only the first request is inspected. A client that spreads its handshake
// across several pipelined requests gets the extra ones forwarded to the SSH
// server as payload, which sees them as an invalid banner and drops the
// connection. Pinning this so the single-request requirement stays documented
// behaviour rather than a surprise.
func TestOnlyFirstRequestIsParsed(t *testing.T) {
	echo := startEchoServer(t)
	bridge := startBridgeServer(t)

	client, err := net.DialTimeout("tcp", bridge.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	head := fmt.Sprintf("GET / HTTP/1.1\r\nHost: example.com\r\nX-Real-Host: 127.0.0.1:%d\r\n\r\n", echoPort(t, echo))
	// A second request carrying the upgrade headers, as a misconfigured client
	// would send it.
	second := "GET / HTTP/1.1\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
	if _, err := client.Write([]byte(head + second)); err != nil {
		t.Fatal(err)
	}

	reader := bufio.NewReader(client)

	// Consume the 101 status line and header block ourselves so the accept token
	// can be inspected; readSwitch() discards them.
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "HTTP/1.1 101") {
		t.Fatalf("unexpected status: %q", status)
	}
	var headers []byte
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		headers = append(headers, line...)
		if line == "\r\n" {
			break
		}
	}

	// No Sec-WebSocket-Key in the first request, so framing stays off and the
	// accept token is the placeholder rather than the RFC 6455 digest.
	if !strings.Contains(string(headers), "Sec-WebSocket-Accept: foo") {
		t.Fatalf("expected raw relay with placeholder accept token, got %q", headers)
	}
	if strings.Contains(string(headers), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") {
		t.Fatal("framing must not be enabled by a later request")
	}
	// The second request is relayed verbatim as payload.
	assertEcho(t, reader, []byte(second))
}

func TestHandleConnRejectsBadTarget(t *testing.T) {
	bridge := startBridgeServer(t)

	client, err := net.DialTimeout("tcp", bridge.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nX-Real-Host: 127.0.0.1:notaport\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(client).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains([]byte(line), []byte("400")) {
		t.Fatalf("expected 400, got %q", line)
	}
}

// readHead must stop at the blank line: anything the client sent behind the
// headers has to stay buffered, or the first SSH bytes are lost.
func TestReadHeadLeavesPipelinedBytes(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	const tail = "PAYLOAD-AFTER-HEAD"
	raw := "GET / HTTP/1.1\r\nHost: x\r\nX-Real-Host: 127.0.0.1:109\r\n\r\n" + tail
	go func() { _, _ = client.Write([]byte(raw)) }()

	reader := bufio.NewReader(server)
	head, err := readHead(reader, server)
	if err != nil {
		t.Fatal(err)
	}
	if got := findHeader(head, "X-Real-Host"); got != "127.0.0.1:109" {
		t.Fatalf("unexpected X-Real-Host: %q", got)
	}
	rest := make([]byte, len(tail))
	if _, err := io.ReadFull(reader, rest); err != nil {
		t.Fatal(err)
	}
	if string(rest) != tail {
		t.Fatalf("pipelined payload lost: got %q want %q", rest, tail)
	}
}

// An unparsable X-Real-Host port must not be redirected at the proxy itself.
func TestTargetAddressNeverFallsBackToListenPort(t *testing.T) {
	if _, err := targetAddress("127.0.0.1:notaport"); err == nil {
		t.Fatal("unparsable port must be rejected")
	}
}

func echoPort(t *testing.T, l net.Listener) int {
	t.Helper()
	return l.Addr().(*net.TCPAddr).Port
}

func TestConnLimiter(t *testing.T) {
	ctx := context.Background()

	if !newLimiter(0).acquire(ctx) {
		t.Fatal("nil limiter must always acquire")
	}
	newLimiter(0).release() // must not panic

	limiter := newLimiter(2)
	if !limiter.acquire(ctx) || !limiter.acquire(ctx) {
		t.Fatal("first two acquires must succeed")
	}
	// The third acquire must not succeed while the two slots are held.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if limiter.acquire(cancelled) {
		t.Fatal("acquire with cancelled context must fail")
	}
	limiter.release()
	if !limiter.acquire(ctx) {
		t.Fatal("acquire after release must succeed")
	}
}

// readSwitch consumes the 101 status line and its header block.
func readSwitch(t *testing.T, reader *bufio.Reader) {
	t.Helper()
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains([]byte(status), []byte("HTTP/1.1 101")) {
		t.Fatalf("unexpected status: %q", status)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			return
		}
	}
}

func assertEcho(t *testing.T, reader io.Reader, payload []byte) {
	t.Helper()
	buffer := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, buffer); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buffer, payload) {
		t.Fatalf("echo mismatch: got %q want %q", buffer, payload)
	}
}

func startEchoServer(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return listener
}

func startBridgeServer(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleConn(conn, listener.Addr().(*net.TCPAddr).Port)
		}
	}()
	return listener
}

func TestHandleConnForwarding(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	echoPort := echo.Addr().(*net.TCPAddr).Port

	bridge, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	go func() {
		for {
			conn, err := bridge.Accept()
			if err != nil {
				return
			}
			go handleConn(conn, bridge.Addr().(*net.TCPAddr).Port)
		}
	}()

	client, err := net.DialTimeout("tcp", bridge.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	request := fmt.Sprintf("CONNECT / HTTP/1.1\r\nX-Real-Host: 127.0.0.1:%d\r\nX-Split: 1\r\n\r\n", echoPort)
	if _, err := client.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := client.Write([]byte("JUNK")); err != nil {
		t.Fatal(err)
	}

	reader := bufio.NewReader(client)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains([]byte(status), []byte("HTTP/1.1 101")) {
		t.Fatalf("unexpected status: %q", status)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}

	payload := []byte("ssh-go-port")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, buffer); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buffer, payload) {
		t.Fatalf("echo mismatch: %q", buffer)
	}
}

func TestHandleConnRejectsRemoteHost(t *testing.T) {
	bridge, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	go func() {
		for {
			conn, err := bridge.Accept()
			if err != nil {
				return
			}
			go handleConn(conn, bridge.Addr().(*net.TCPAddr).Port)
		}
	}()

	client, err := net.DialTimeout("tcp", bridge.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := client.Write([]byte("CONNECT / HTTP/1.1\r\nX-Real-Host: example.com:22\r\n\r\n")); err != nil {
		t.Fatal(err)
	}

	line, err := bufio.NewReader(client).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains([]byte(line), []byte("403")) {
		t.Fatalf("expected 403, got %q", line)
	}
}
