package main

import (
	"bufio"
	"bytes"
	"testing"
)

func TestWebsocketAccept(t *testing.T) {
	got := websocketAccept("dGhlIHNhbXBsZSBub25jZQ==")
	want := "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
	if got != want {
		t.Fatalf("accept mismatch: got %q want %q", got, want)
	}
}

func TestFrameRoundTrip(t *testing.T) {
	payload := []byte("SSH-2.0-test\r\n")
	var masked bytes.Buffer
	masked.WriteByte(0x82)
	masked.WriteByte(0x80 | byte(len(payload)))
	mask := []byte{1, 2, 3, 4}
	masked.Write(mask)
	for i, b := range payload {
		masked.WriteByte(b ^ mask[i%4])
	}

	opcode, decoded, err := readFrame(bufio.NewReader(&masked))
	if err != nil {
		t.Fatal(err)
	}
	if opcode != 0x2 || !bytes.Equal(decoded, payload) {
		t.Fatalf("unexpected frame: opcode=%x payload=%q", opcode, decoded)
	}

	var out bytes.Buffer
	if err := writeFrame(&out, 0x2, payload); err != nil {
		t.Fatal(err)
	}
	if out.Bytes()[0] != 0x82 {
		t.Fatalf("unexpected header: %x", out.Bytes()[0])
	}
}

func TestDetectWebSocket(t *testing.T) {
	raw := bufio.NewReader(bytes.NewReader([]byte("SSH-2.0-OpenSSH\r\n")))
	if detectWebSocket(raw) {
		t.Fatal("raw SSH must not be detected as websocket")
	}
	frame := bufio.NewReader(bytes.NewReader([]byte{0x82, 0x80, 0x00, 0x00, 0x00, 0x00}))
	if !detectWebSocket(frame) {
		t.Fatal("masked binary frame must be detected")
	}
}
