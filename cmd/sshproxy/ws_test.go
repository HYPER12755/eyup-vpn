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

func TestClosePayload(t *testing.T) {
	if got := closePayload(nil); got != nil {
		t.Fatalf("empty close must echo nil, got %x", got)
	}
	if got := closePayload([]byte{0x03}); got != nil {
		t.Fatalf("short close payload must echo nil, got %x", got)
	}
	// A close carrying status 1000 (normal closure) echoes just the code.
	if got := closePayload([]byte{0x03, 0xe8, 'b', 'y', 'e'}); !bytes.Equal(got, []byte{0x03, 0xe8}) {
		t.Fatalf("close status not echoed: %x", got)
	}
}

// writeFrame must select the 126 (16-bit) and 127 (64-bit) length encodings
// correctly; only the <126 branch was exercised by TestFrameRoundTrip.
func TestWriteFrameExtendedLengths(t *testing.T) {
	for _, size := range []int{126, 65535, 65536, 1 << 20} {
		payload := make([]byte, size)
		for i := range payload {
			payload[i] = byte(i)
		}
		var out bytes.Buffer
		if err := writeFrame(&out, 0x2, payload); err != nil {
			t.Fatalf("writeFrame(%d): %v", size, err)
		}
		opcode, decoded, err := readFrame(bufio.NewReader(&out))
		if err != nil {
			t.Fatalf("readFrame(%d): %v", size, err)
		}
		if opcode != 0x2 || !bytes.Equal(decoded, payload) {
			t.Fatalf("round trip mismatch at %d bytes: opcode=%x len=%d", size, opcode, len(decoded))
		}
	}
}
