package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

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

func proxyWebSocket(client net.Conn, reader *bufio.Reader, target net.Conn) {
	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		buffer := make([]byte, bufLen)
		for {
			n, err := target.Read(buffer)
			if n > 0 {
				if writeErr := writeFrame(client, 0x2, buffer[:n]); writeErr != nil {
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
			switch opcode {
			case 0x8:
				_ = writeFrame(client, 0x8, nil)
				return
			case 0x9:
				if err := writeFrame(client, 0xA, payload); err != nil {
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
