// Package guestproducer runs the real, explicitly enrolled demo source. It does
// not provision a TPM, mint a read grant, or enroll its own signing authority.
package guestproducer

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/guesttransport"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/tetragonhealth"
	"github.com/ckodex-labs/ckodex-oskal/internal/application/guest"
	"github.com/ckodex-labs/ckodex-oskal/internal/signedrecords"
)

type TLSFiles struct {
	CA          string `json:"ca"`
	Certificate string `json:"certificate"`
	Key         string `json:"key"`
	ServerName  string `json:"serverName"`
}

type Config struct {
	Target           string                    `json:"target"`
	BrokerTarget     string                    `json:"brokerTarget"`
	TransportTLS     TLSFiles                  `json:"transportTLS"`
	BrokerTLS        TLSFiles                  `json:"brokerTLS"`
	ExportKeyFile    string                    `json:"exportKeyFile"`
	EnrollmentID     string                    `json:"enrollmentID"`
	Enrollment       guest.Enrollment          `json:"enrollment"`
	ReceiptKey       string                    `json:"receiptKey"`
	ReceiptAuthority assurance.AuthorityRef    `json:"receiptAuthority"`
	Subject          assurance.SubjectRef      `json:"subject"`
	Control          assurance.ControlRef      `json:"control"`
	Epoch            assurance.AssuranceEpoch  `json:"epoch"`
	Native           tetragonhealth.Enrollment `json:"native"`
	GrantFile        string                    `json:"grantFile"`
	GrantKey         string                    `json:"grantKey"`
	TetragonSocket   string                    `json:"tetragonSocket"`
	SocketOwnerUID   uint32                    `json:"socketOwnerUID"`
	SocketOwnerGID   uint32                    `json:"socketOwnerGID"`
	MetricsEndpoint  string                    `json:"metricsEndpoint"`
	Namespace        string                    `json:"namespace"`
	ReadTimeout      time.Duration             `json:"readTimeout"`
	TransportLimits  guesttransport.Limits     `json:"transportLimits"`
}

func Load(path string) (Config, error) {
	var config Config
	raw, err := readRegular(path, 256<<10, true)
	if err != nil {
		return config, err
	}
	if err := signedrecords.DecodeJSON(raw, &config, 256<<10); err != nil {
		return config, fmt.Errorf("decode outside-owned source configuration: %w", err)
	}
	if err := config.Validate(); err != nil {
		return config, err
	}
	return config, nil
}

func (c Config) Validate() error {
	if c.Target == "" || len(c.Target) > 2048 || c.BrokerTarget == "" || len(c.BrokerTarget) > 2048 || c.EnrollmentID == "" || c.Namespace == "" {
		return fmt.Errorf("explicit verifier, quote broker, enrollment ID and namespace are required")
	}
	if err := c.Enrollment.Validate(); err != nil {
		return err
	}
	if err := c.Native.Validate(); err != nil {
		return err
	}
	for _, path := range []string{c.ExportKeyFile, c.GrantFile, c.TetragonSocket, c.TransportTLS.CA, c.TransportTLS.Certificate, c.TransportTLS.Key, c.BrokerTLS.CA, c.BrokerTLS.Certificate, c.BrokerTLS.Key} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
			return fmt.Errorf("source credentials, grants and sockets require clean absolute paths")
		}
	}
	if c.TransportTLS.ServerName == "" || c.BrokerTLS.ServerName == "" {
		return fmt.Errorf("both remote TLS server names must be explicitly pinned")
	}
	if _, err := publicKey(c.ReceiptKey); err != nil {
		return fmt.Errorf("receipt key: %w", err)
	}
	if _, err := publicKey(c.GrantKey); err != nil {
		return fmt.Errorf("read-grant key: %w", err)
	}
	if err := c.ReceiptAuthority.Validate(); err != nil {
		return err
	}
	if err := c.Subject.Validate(); err != nil {
		return err
	}
	if err := c.Control.Validate(); err != nil {
		return err
	}
	return (tetragonhealth.MetricsReader{Endpoint: c.MetricsEndpoint, Timeout: c.ReadTimeout, Limits: tetragonhealth.DefaultLimits()}).Validate()
}

func publicKey(value string) (ed25519.PublicKey, error) {
	key, err := hex.DecodeString(value)
	if err != nil || len(key) != ed25519.PublicKeySize || len(value) != 64 {
		return nil, fmt.Errorf("an outside-pinned 64-character Ed25519 public key is required")
	}
	return ed25519.PublicKey(key), nil
}

func readRegular(path string, maximum int64, private bool) ([]byte, error) {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") {
		return nil, fmt.Errorf("explicit absolute input path is required")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("read source input; restore the enrolled file: %w", err)
	}
	if !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > maximum || private && before.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("input must be a bounded regular file; private configuration and keys require mode 0600")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("source input changed before it could be read; restore trusted custody and retry")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) || len(raw) > int(maximum) || int64(len(raw)) != before.Size() {
		return nil, fmt.Errorf("source input changed during bounded read; preserve it and inspect the writer")
	}
	return raw, nil
}

func loadTLS(files TLSFiles) (*tls.Config, error) {
	ca, err := readRegular(files.CA, 64<<10, false)
	if err != nil {
		return nil, err
	}
	certificate, err := readRegular(files.Certificate, 64<<10, false)
	if err != nil {
		return nil, err
	}
	key, err := readRegular(files.Key, 64<<10, true)
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(certificate, key)
	if err != nil {
		return nil, fmt.Errorf("load enrolled client certificate/key pair: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("restore the explicit valid server CA bundle before retrying")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, ServerName: files.ServerName, RootCAs: pool, Certificates: []tls.Certificate{pair}}, nil
}
