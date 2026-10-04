package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
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
	if got := targetAddress("127.0.0.1:109", 10015); got != "127.0.0.1:109" {
		t.Fatalf("unexpected target: %q", got)
	}
	if got := targetAddress("localhost:22", 10015); got != "localhost:22" {
		t.Fatalf("unexpected target: %q", got)
	}
	if got := targetAddress("127.0.0.1", 10015); got != "127.0.0.1:443" {
		t.Fatalf("unexpected target: %q", got)
	}
}

func TestIsLocalHost(t *testing.T) {
	if !isLocalHost("127.0.0.1:109") || !isLocalHost("localhost:22") {
		t.Fatal("local hosts must be allowed")
	}
	if isLocalHost("example.com:22") || isLocalHost("8.8.8.8:443") {
		t.Fatal("remote hosts must be rejected without password")
	}
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
