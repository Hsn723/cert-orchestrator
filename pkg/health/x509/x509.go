package x509

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/hsn723/cert-orchestrator/pkg/health"
	corev1 "k8s.io/api/core/v1"
)

var _ health.Format = &X509Format{}

// X509Format evaluates classic X.509 certificate chains stored as tls.crt.
type X509Format struct {
	revocation health.RevocationChecker
	ct         health.CTChecker
}

// X509Option configures an X509Format.
type X509Option func(*X509Format)

// WithRevocationChecker enables revocation checking.
func WithRevocationChecker(r health.RevocationChecker) X509Option {
	return func(f *X509Format) { f.revocation = r }
}

// WithCTChecker enables Certificate Transparency checking.
func WithCTChecker(c health.CTChecker) X509Option {
	return func(f *X509Format) { f.ct = c }
}

// NewX509Format returns a Format that evaluates classic x509 certificates.
func NewX509Format(opts ...X509Option) *X509Format {
	f := &X509Format{}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// Name implements the Format interface.
func (*X509Format) Name() string {
	return "X509"
}

// Matches implements Format.
func (*X509Format) Matches(secret *corev1.Secret) bool {
	rest := secret.Data[corev1.TLSCertKey]
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return false
		}
		if block.Type == "CERTIFICATE" {
			return true
		}
	}
}

// Evaluate implements Format.
func (f *X509Format) Evaluate(ctx context.Context, secret *corev1.Secret, policy health.Policy, evalTime time.Time) health.Result {
	certPEM := secret.Data[corev1.TLSCertKey]
	chain, err := parseChain(certPEM)
	if err != nil {
		return health.Result{Problems: []string{err.Error()}}
	}
	res := health.Result{Parsed: true}

	if policy.CheckExpiry {
		checkExpiry(chain[0], &res, evalTime)
		if len(res.Problems) > 0 {
			// no point in asking the network about a certificate that is not valid anyway
			return res
		}
	}
	if policy.CheckRevocation && f.revocation != nil {
		f.checkRevocation(ctx, chain, &res)
	}
	if policy.CheckCT && f.ct != nil {
		f.checkCT(ctx, certPEM, &res)
	}
	return res
}

func parseChain(data []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		crt, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate in tls.crt: %w", err)
		}
		chain = append(chain, crt)
	}
	if len(chain) == 0 {
		return nil, errors.New("no certificate found in tls.crt")
	}
	return chain, nil
}

func checkExpiry(leaf *x509.Certificate, res *health.Result, evalTime time.Time) {
	switch {
	case evalTime.Before(leaf.NotBefore):
		res.Problems = append(res.Problems, fmt.Sprintf("not valid until %s", leaf.NotBefore.UTC().Format(time.RFC3339)))
	case !evalTime.Before(leaf.NotAfter):
		res.Problems = append(res.Problems, fmt.Sprintf("expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339)))
	}
}

func (f *X509Format) checkRevocation(ctx context.Context, chain []*x509.Certificate, res *health.Result) {
	if len(chain) < 2 {
		res.Warnings = append(res.Warnings, "issuer certificate not present in tls.crt, skipping revocation check")
		return
	}
	revoked, detail, err := f.revocation.IsRevoked(ctx, chain[0], chain[1])
	switch {
	case errors.Is(err, health.ErrNoRevocationInfo):
		return
	case err != nil:
		res.Warnings = append(res.Warnings, fmt.Sprintf("revocation status unknown: %v", err))
	case revoked:
		res.Problems = append(res.Problems, detail)
	}
}

func (f *X509Format) checkCT(ctx context.Context, chainPEM []byte, res *health.Result) {
	r, err := f.ct.Check(ctx, chainPEM)
	if err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("certificate transparency status unknown: %v", err))
		return
	}
	res.Warnings = append(res.Warnings, r.Warnings...)
	if r.Problem != "" {
		res.Problems = append(res.Problems, r.Problem)
	}
}
