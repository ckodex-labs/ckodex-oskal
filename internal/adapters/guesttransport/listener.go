package guesttransport

import (
	"net"
	"sync"
)

// connectionListener applies capacity before gRPC/TLS starts a handshake.
type connectionListener struct {
	net.Listener
	slots  chan struct{}
	closed chan struct{}
	once   sync.Once
}

func newConnectionListener(listener net.Listener, limit int) *connectionListener {
	return &connectionListener{Listener: listener, slots: make(chan struct{}, limit), closed: make(chan struct{})}
}
func (l *connectionListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.closed:
		return nil, net.ErrClosed
	}
	connection, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &countedConnection{Conn: connection, release: func() { <-l.slots }}, nil
}
func (l *connectionListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return l.Listener.Close()
}

type countedConnection struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *countedConnection) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
