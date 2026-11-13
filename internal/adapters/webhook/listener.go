package webhook

import (
	"net"
	"sync"
)

// MaxWebhookConnections bounds native hosting before TLS handshakes and HTTP
// parsing. Handler-only hosts own their listener's connection bound.
const MaxWebhookConnections = 64

type connectionListener struct {
	net.Listener
	tokens chan struct{}
	closed chan struct{}
	once   sync.Once
}

func newConnectionListener(listener net.Listener, limit int) *connectionListener {
	return &connectionListener{Listener: listener, tokens: make(chan struct{}, limit), closed: make(chan struct{})}
}
func (l *connectionListener) Accept() (net.Conn, error) {
	select {
	case l.tokens <- struct{}{}:
	case <-l.closed:
		return nil, net.ErrClosed
	}
	connection, err := l.Listener.Accept()
	if err != nil {
		<-l.tokens
		return nil, err
	}
	return &limitedConnection{Conn: connection, release: func() { <-l.tokens }}, nil
}
func (l *connectionListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return l.Listener.Close()
}

type limitedConnection struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *limitedConnection) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
