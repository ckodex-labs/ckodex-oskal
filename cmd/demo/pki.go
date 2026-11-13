package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type keyMaterial struct{ ca, serverCert, serverKey, clientCert, clientKey, receiptPrivate, receiptPublic []byte }

func (d *demo) keys() (keyMaterial, error) {
	var out keyMaterial
	dir := filepath.Join(d.dir, "pki")
	if err := os.Mkdir(dir, 0700); err != nil {
		return out, err
	}
	serial := func() (*big.Int, error) { return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)) }
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return out, err
	}
	caSerial, err := serial()
	if err != nil {
		return out, err
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: caSerial, Subject: pkix.Name{CommonName: "oskal-demo-local-ca"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, MaxPathLenZero: true}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return out, err
	}
	out.ca = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	caPrivate, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		return out, err
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: caPrivate}), 0600); err != nil {
		return out, err
	}
	issue := func(name string, usage x509.ExtKeyUsage, dns []string) ([]byte, []byte, error) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		number, err := serial()
		if err != nil {
			return nil, nil, err
		}
		template := &x509.Certificate{SerialNumber: number, Subject: pkix.Name{CommonName: name}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, DNSNames: dns, ExtKeyUsage: []x509.ExtKeyUsage{usage}, KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
		cert, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if err != nil {
			return nil, nil, err
		}
		private, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), nil
	}
	out.serverCert, out.serverKey, err = issue("oskal-demo-tetragon", x509.ExtKeyUsageServerAuth, []string{"oskal-tetragon." + systemNamespace + ".svc"})
	if err != nil {
		return out, err
	}
	out.clientCert, out.clientKey, err = issue("oskal-demo-collector", x509.ExtKeyUsageClientAuth, nil)
	if err != nil {
		return out, err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return out, err
	}
	d.publicKey = hex.EncodeToString(public)
	out.receiptPrivate = []byte(hex.EncodeToString(private) + "\n")
	out.receiptPublic = []byte(d.publicKey + "\n")
	for name, data := range map[string][]byte{"ca.crt": out.ca, "server.crt": out.serverCert, "server.key": out.serverKey, "client.crt": out.clientCert, "client.key": out.clientKey, "receipt-signing.key": out.receiptPrivate, "receipt-signing.pub": out.receiptPublic} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			return out, err
		}
	}
	return out, nil
}
