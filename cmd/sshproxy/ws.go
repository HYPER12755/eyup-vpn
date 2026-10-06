package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	// RFC 6455 §5.5: control frames carry at most 125 bytes of payload.
	maxControlPayload = 125
)

func websocketAccept(key string) string {
	hash := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(hash[:])
}

func readFrame(reader *bufio.Reader) (byte, []byte, error) {
	first, err := reader.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	opcode := first & 0x0f

	second, err := reader.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	masked := second&0x80 != 0
	length := int64(second & 0x7f)

	switch length {
	case 126:
		var extended [2]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return 0, nil, err
		}
		length = int64(binary.BigEndian.Uint16(extended[:]))
	case 127:
		var extended [8]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return 0, nil, err
		}
		length = int64(binary.BigEndian.Uint64(extended[:]))
	}

	if length < 0 || length > 1<<20 {
		return 0, nil, errors.New("ws: frame too large")
	}

	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(reader, mask[:]); err != nil {
			return 0, nil, err
		}
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return opcode, payload, nil
}

func writeFrame(writer io.Writer, opcode byte, payload []byte) error {
	header := make([]byte, 0, 10)
	header = append(header, 0x80|opcode)
	switch {
	case len(payload) < 126:
		header = append(header, byte(len(payload)))
	case len(payload) <= 65535:
		header = append(header, 126, byte(len(payload)>>8), byte(len(payload)))
	default:
		header = append(header, 127, 0, 0, 0, 0,
			byte(len(payload)>>24), byte(len(payload)>>16), byte(len(payload)>>8), byte(len(payload)))
	}
	if _, err := writer.Write(header); err != nil {
		return err
	}
	_, err := writer.Write(payload)
	return err
}

// frameWriter serialises writes to the client socket. Both the forwarding and
// the control-frame goroutines emit frames, and writeFrame issues two writes
// per frame, so without this a PONG can splice itself into a data frame.
type frameWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (f *frameWriter) write(opcode byte, payload []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return writeFrame(f.w, opcode, payload)
}

func proxyWebSocket(client net.Conn, reader *bufio.Reader, target net.Conn) {
	done := make(chan struct{}, 2)
	frames := &frameWriter{w: client}

	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())

	stop := make(chan struct{})
	defer close(stop)
	startIdleReaper(&lastActivity, stop, func() {
		_ = client.Close()
		_ = target.Close()
	})

	go func() {
		defer func() { done <- struct{}{} }()
		buffer := make([]byte, bufLen)
		for {
			n, err := target.Read(buffer)
			if n > 0 {
				lastActivity.Store(time.Now().UnixNano())
				if writeErr := frames.write(0x2, buffer[:n]); writeErr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		for {
			opcode, payload, err := readFrame(reader)
			if err != nil {
				return
			}
			lastActivity.Store(time.Now().UnixNano())
			switch opcode {
			case 0x8:
				_ = frames.write(0x8, closePayload(payload))
				return
			case 0x9:
				if len(payload) > maxControlPayload {
					return
				}
				if err := frames.write(0xA, payload); err != nil {
					return
				}
			case 0xA:
			default:
				if len(payload) > 0 {
					if _, err := target.Write(payload); err != nil {
						return
					}
				}
			}
		}
	}()

	<-done
	_ = client.Close()
	_ = target.Close()
	<-done
}

// closePayload builds the close frame echoed back when the peer initiates a
// close. RFC 6455 §5.5.1: a close frame may carry a two-byte status code;
// echoing it yields a well-formed close instead of an empty one.
func closePayload(received []byte) []byte {
	if len(received) >= 2 {
		return received[:2]
	}
	return nil
}

func detectWebSocket(reader *bufio.Reader) bool {
	first, err := reader.Peek(1)
	if err != nil {
		return false
	}
	return isWebSocketOpcode(first[0])
}

func isWebSocketOpcode(first byte) bool {
	if first&0x80 == 0 {
		return false
	}
	switch first & 0x0f {
	case 0x0, 0x1, 0x2, 0x8, 0x9, 0xA:
		return true
	}
	return false
}
