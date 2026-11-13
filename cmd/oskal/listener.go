package main

import (
	"net"
	"sync"
)

// limitedListener bounds accepted connections before TLS or Workload API work.
type limitedListener struct {
	net.Listener
	tokens chan struct{}
	closed chan struct{}
	once   sync.Once
}

func newLimitedListener(listener net.Listener, limit int) *limitedListener {
	return &limitedListener{Listener: listener, tokens: make(chan struct{}, limit), closed: make(chan struct{})}
}
func (l *limitedListener) Accept() (net.Conn, error) {
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
func (l *limitedListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return l.Listener.Close()
}

type limitedConnection struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *limitedConnection) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
