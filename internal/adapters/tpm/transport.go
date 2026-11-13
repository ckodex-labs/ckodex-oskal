package tpm

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const maxTPMMessage = 4096

// socketTransport speaks raw TPM command framing to swtpm. Each command owns
// its connection, so cancellation closes real I/O without a blocked worker.
// The provider serializes commands; this transport has no internal retry loop.
type socketTransport struct {
	ctx     context.Context
	network string
	address string
}

func (s *socketTransport) Send(command []byte) ([]byte, error) {
	if len(command) < 10 || len(command) > maxTPMMessage || int(binary.BigEndian.Uint32(command[2:6])) != len(command) {
		return nil, fmt.Errorf("TPM command framing exceeds bounds")
	}
	deadline, ok := s.ctx.Deadline()
	if !ok {
		return nil, fmt.Errorf("TPM command requires a deadline")
	}
	conn, err := (&net.Dialer{}).DialContext(s.ctx, s.network, s.address)
	if err != nil {
		return nil, fmt.Errorf("connect to TPM: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set TPM deadline: %w", err)
	}
	stop := context.AfterFunc(s.ctx, func() { _ = conn.Close() })
	defer stop()
	response, err := exchange(conn, command)
	if s.ctx.Err() != nil {
		return nil, s.ctx.Err()
	}
	return response, err
}

func exchange(conn net.Conn, command []byte) ([]byte, error) {
	for len(command) > 0 {
		n, err := conn.Write(command)
		if err != nil {
			return nil, fmt.Errorf("write TPM command: %w", err)
		}
		if n == 0 {
			return nil, io.ErrShortWrite
		}
		command = command[n:]
	}
	header := make([]byte, 10)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("read TPM response header: %w", err)
	}
	size := binary.BigEndian.Uint32(header[2:6])
	if size < 10 || size > maxTPMMessage {
		return nil, fmt.Errorf("TPM response length %d exceeds bounds", size)
	}
	response := make([]byte, size)
	copy(response, header)
	if _, err := io.ReadFull(conn, response[10:]); err != nil {
		return nil, fmt.Errorf("read TPM response body: %w", err)
	}
	return response, nil
}
