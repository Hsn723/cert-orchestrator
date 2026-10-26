package healthtest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

const (
	// DefaultSerial is the serial number of issued certificates unless a spec says otherwise.
	DefaultSerial = 1001
)

var (
	// Now is the evaluation time used by tests. It has no sub-second part, because certificate validity
	// timestamps are truncated to seconds.
	Now = time.Date(2026, time.January, 15, 12, 0, 0, 0, time.UTC)
)

// ContextKey is a context key for tests that check context propagation.
type ContextKey struct{}

// Must fails the test immediately if err is not nil.
func Must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// PEMBlock encodes der as a PEM block of the given type.
func PEMBlock(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

// ConcatPEM concatenates PEM encoded data, for example to build a certificate chain.
func ConcatPEM(parts ...[]byte) []byte {
	return bytes.Join(parts, nil)
}

// TLSSecret returns a Secret holding the concatenated PEM data as tls.crt.
func TLSSecret(certPEM ...[]byte) *corev1.Secret {
	return &corev1.Secret{
		Data: map[string][]byte{corev1.TLSCertKey: ConcatPEM(certPEM...)},
	}
}

// SecretWithKey returns a Secret with some data under the given key.
func SecretWithKey(key string) *corev1.Secret {
	return &corev1.Secret{Data: map[string][]byte{key: []byte("data")}}
}

// NewKey generates an ECDSA P-256 key.
func NewKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Must(t, err)
	return key
}

// CASpec describes a CA. Zero times default to a validity of one day either side of the wall clock.
type CASpec struct {
	NotBefore time.Time
	NotAfter  time.Time
}

// CA is a self-signed certificate authority.
type CA struct {
	Key  *ecdsa.PrivateKey
	Cert *x509.Certificate
	DER  []byte
	PEM  []byte
}

// NewCA creates a self-signed CA.
func NewCA(t testing.TB, spec CASpec) *CA {
	t.Helper()
	if spec.NotBefore.IsZero() {
		spec.NotBefore = time.Now().Add(-24 * time.Hour)
	}
	if spec.NotAfter.IsZero() {
		spec.NotAfter = time.Now().Add(24 * time.Hour)
	}

	key := NewKey(t)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             spec.NotBefore,
		NotAfter:              spec.NotAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	Must(t, err)
	cert, err := x509.ParseCertificate(der)
	Must(t, err)
	return &CA{Key: key, Cert: cert, DER: der, PEM: PEMBlock("CERTIFICATE", der)}
}

// CertSpec describes a leaf certificate.
type CertSpec struct {
	Serial                int64
	CommonName            string
	DNSNames              []string
	NotBefore             time.Time
	NotAfter              time.Time
	Key                   *ecdsa.PrivateKey
	CRLDistributionPoints []string
	OCSPServer            []string
	ExtraExtensions       []pkix.Extension
}

// Cert is an issued leaf certificate.
type Cert struct {
	Key  *ecdsa.PrivateKey
	Cert *x509.Certificate
	DER  []byte
	PEM  []byte
}

// Issue issues a leaf certificate signed by the CA. Only Key and Cert of the CA are used.
func (ca *CA) Issue(t testing.TB, spec CertSpec) *Cert {
	t.Helper()
	if spec.Serial == 0 {
		spec.Serial = DefaultSerial
	}
	if spec.CommonName == "" {
		spec.CommonName = "example.com"
	}
	if spec.DNSNames == nil {
		spec.DNSNames = []string{spec.CommonName}
	}
	if spec.NotBefore.IsZero() {
		spec.NotBefore = time.Now().Add(-time.Hour).Truncate(time.Second)
	}
	if spec.NotAfter.IsZero() {
		spec.NotAfter = time.Now().Add(24 * time.Hour).Truncate(time.Second)
	}
	if spec.Key == nil {
		spec.Key = NewKey(t)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(spec.Serial),
		Subject:               pkix.Name{CommonName: spec.CommonName},
		DNSNames:              spec.DNSNames,
		NotBefore:             spec.NotBefore,
		NotAfter:              spec.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CRLDistributionPoints: spec.CRLDistributionPoints,
		OCSPServer:            spec.OCSPServer,
		ExtraExtensions:       spec.ExtraExtensions,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &spec.Key.PublicKey, ca.Key)
	Must(t, err)
	cert, err := x509.ParseCertificate(der)
	Must(t, err)
	return &Cert{Key: spec.Key, Cert: cert, DER: der, PEM: PEMBlock("CERTIFICATE", der)}
}
