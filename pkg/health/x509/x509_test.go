package x509

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"

	"github.com/hsn723/cert-orchestrator/internal/healthtest"
	"github.com/hsn723/cert-orchestrator/pkg/health"
)

type fakeRevocationChecker struct {
	revoked bool
	detail  string
	err     error

	calls  int
	ctx    context.Context
	leaf   *x509.Certificate
	issuer *x509.Certificate
}

var _ health.RevocationChecker = &fakeRevocationChecker{}

func (f *fakeRevocationChecker) IsRevoked(ctx context.Context, leaf, issuer *x509.Certificate) (bool, string, error) {
	f.calls++
	f.ctx = ctx
	f.leaf = leaf
	f.issuer = issuer
	return f.revoked, f.detail, f.err
}

type fakeCTChecker struct {
	result health.CTResult
	err    error

	calls    int
	ctx      context.Context
	chainPEM []byte
}

var _ health.CTChecker = &fakeCTChecker{}

func (f *fakeCTChecker) Check(ctx context.Context, chainPEM []byte) (health.CTResult, error) {
	f.calls++
	f.ctx = ctx
	f.chainPEM = chainPEM
	return f.result, f.err
}

type pkiSpec struct {
	leafNotBefore   time.Time
	leafNotAfter    time.Time
	issuerNotBefore time.Time
	issuerNotAfter  time.Time
}

type testPKI struct {
	leafPEM   []byte
	issuerPEM []byte
	chainPEM  []byte
	leafRaw   []byte
	issuerRaw []byte
}

func validSpec() pkiSpec {
	return pkiSpec{
		leafNotBefore:   healthtest.Now.Add(-24 * time.Hour),
		leafNotAfter:    healthtest.Now.Add(24 * time.Hour),
		issuerNotBefore: healthtest.Now.AddDate(-10, 0, 0),
		issuerNotAfter:  healthtest.Now.AddDate(10, 0, 0),
	}
}

func expiredSpec() pkiSpec {
	spec := validSpec()
	spec.leafNotBefore = healthtest.Now.Add(-48 * time.Hour)
	spec.leafNotAfter = healthtest.Now.Add(-time.Hour)
	return spec
}

func notYetValidSpec() pkiSpec {
	spec := validSpec()
	spec.leafNotBefore = healthtest.Now.Add(time.Hour)
	spec.leafNotAfter = healthtest.Now.Add(48 * time.Hour)
	return spec
}

func expiredIssuerSpec() pkiSpec {
	spec := validSpec()
	spec.issuerNotBefore = healthtest.Now.Add(-48 * time.Hour)
	spec.issuerNotAfter = healthtest.Now.Add(-time.Hour)
	return spec
}

// newTestPKI creates a CA and a leaf certificate signed by it.
func newTestPKI(t *testing.T, spec pkiSpec) *testPKI {
	t.Helper()
	ca := healthtest.NewCA(t, healthtest.CASpec{NotBefore: spec.issuerNotBefore, NotAfter: spec.issuerNotAfter})
	leaf := ca.Issue(t, healthtest.CertSpec{NotBefore: spec.leafNotBefore, NotAfter: spec.leafNotAfter})
	return &testPKI{
		leafPEM:   leaf.PEM,
		issuerPEM: ca.PEM,
		chainPEM:  healthtest.ConcatPEM(leaf.PEM, ca.PEM),
		leafRaw:   leaf.DER,
		issuerRaw: ca.DER,
	}
}

func rawsOf(chain []*x509.Certificate) [][]byte {
	if len(chain) == 0 {
		return nil
	}
	raws := make([][]byte, 0, len(chain))
	for _, c := range chain {
		raws = append(raws, c.Raw)
	}
	return raws
}

func TestName(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "X509", NewX509Format().Name())
}

func TestNewX509Format(t *testing.T) {
	t.Parallel()

	rev1 := &fakeRevocationChecker{}
	rev2 := &fakeRevocationChecker{}
	ct1 := &fakeCTChecker{}
	ct2 := &fakeCTChecker{}

	t.Run("NoOptions", func(t *testing.T) {
		t.Parallel()
		f := NewX509Format()
		assert.Nil(t, f.revocation)
		assert.Nil(t, f.ct)
	})
	t.Run("WithOptions", func(t *testing.T) {
		t.Parallel()
		f := NewX509Format(WithRevocationChecker(rev1), WithCTChecker(ct1))
		assert.Same(t, rev1, f.revocation)
		assert.Same(t, ct1, f.ct)
	})
	t.Run("LastOptionWins", func(t *testing.T) {
		t.Parallel()
		f := NewX509Format(
			WithRevocationChecker(rev1),
			WithRevocationChecker(rev2),
			WithCTChecker(ct1),
			WithCTChecker(ct2),
		)
		assert.Same(t, rev2, f.revocation)
		assert.Same(t, ct2, f.ct)
	})
}

func TestMatches(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, validSpec())
	keyPEM := healthtest.PEMBlock("PRIVATE KEY", []byte("key"))

	cases := []struct {
		title    string
		secret   *corev1.Secret
		expected bool
	}{
		{
			title:    "SingleCertificate",
			secret:   healthtest.TLSSecret(pki.leafPEM),
			expected: true,
		},
		{
			title:    "CertificateChain",
			secret:   healthtest.TLSSecret(pki.chainPEM),
			expected: true,
		},
		{
			title:    "CertificateAfterOtherBlock",
			secret:   healthtest.TLSSecret(keyPEM, pki.leafPEM),
			expected: true,
		},
		{
			// Matches only looks at the PEM block type, parse errors are reported by Evaluate
			title:    "MalformedCertificateBlock",
			secret:   healthtest.TLSSecret(healthtest.PEMBlock("CERTIFICATE", []byte("garbage"))),
			expected: true,
		},
		{
			title:    "OnlyNonCertificateBlock",
			secret:   healthtest.TLSSecret(keyPEM),
			expected: false,
		},
		{
			title:    "CertificateRequestBlock",
			secret:   healthtest.TLSSecret(healthtest.PEMBlock("CERTIFICATE REQUEST", []byte("csr"))),
			expected: false,
		},
		{
			title:    "GarbageData",
			secret:   healthtest.TLSSecret([]byte("not pem")),
			expected: false,
		},
		{
			title:    "EmptyData",
			secret:   &corev1.Secret{},
			expected: false,
		},
		{
			title: "CertificateInWrongKey",
			secret: &corev1.Secret{
				Data: map[string][]byte{corev1.TLSPrivateKeyKey: pki.leafPEM},
			},
			expected: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, NewX509Format().Matches(tc.secret))
		})
	}
}

func TestParseChain(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, validSpec())
	keyPEM := healthtest.PEMBlock("PRIVATE KEY", []byte("key"))

	cases := []struct {
		title       string
		data        []byte
		expectedRaw [][]byte
		errFunc     assert.ErrorAssertionFunc
		errContains string
	}{
		{
			title:       "SingleCertificate",
			data:        pki.leafPEM,
			expectedRaw: [][]byte{pki.leafRaw},
			errFunc:     assert.NoError,
		},
		{
			title:       "CertificateChain",
			data:        pki.chainPEM,
			expectedRaw: [][]byte{pki.leafRaw, pki.issuerRaw},
			errFunc:     assert.NoError,
		},
		{
			title:       "NonCertificateBlocksAreSkipped",
			data:        bytes.Join([][]byte{keyPEM, pki.leafPEM, keyPEM, pki.issuerPEM}, nil),
			expectedRaw: [][]byte{pki.leafRaw, pki.issuerRaw},
			errFunc:     assert.NoError,
		},
		{
			title:       "TrailingGarbageIsIgnored",
			data:        bytes.Join([][]byte{pki.leafPEM, []byte("trailing garbage")}, nil),
			expectedRaw: [][]byte{pki.leafRaw},
			errFunc:     assert.NoError,
		},
		{
			title:       "MalformedCertificate",
			data:        healthtest.PEMBlock("CERTIFICATE", []byte("garbage")),
			errFunc:     assert.Error,
			errContains: "failed to parse certificate in tls.crt",
		},
		{
			title:       "MalformedCertificateAfterValidOne",
			data:        bytes.Join([][]byte{pki.leafPEM, healthtest.PEMBlock("CERTIFICATE", []byte("garbage"))}, nil),
			errFunc:     assert.Error,
			errContains: "failed to parse certificate in tls.crt",
		},
		{
			title:       "OnlyNonCertificateBlock",
			data:        keyPEM,
			errFunc:     assert.Error,
			errContains: "no certificate found in tls.crt",
		},
		{
			title:       "GarbageData",
			data:        []byte("not pem"),
			errFunc:     assert.Error,
			errContains: "no certificate found in tls.crt",
		},
		{
			title:       "EmptyData",
			data:        nil,
			errFunc:     assert.Error,
			errContains: "no certificate found in tls.crt",
		},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			t.Parallel()
			chain, err := parseChain(tc.data)
			tc.errFunc(t, err)
			if tc.errContains != "" {
				assert.ErrorContains(t, err, tc.errContains)
			}
			assert.Equal(t, tc.expectedRaw, rawsOf(chain))
		})
	}
}

func TestCheckExpiry(t *testing.T) {
	t.Parallel()

	notBefore := healthtest.Now.Add(-time.Hour)
	notAfter := healthtest.Now.Add(time.Hour)
	expiredMessage := fmt.Sprintf("expired at %s", notAfter.UTC().Format(time.RFC3339))
	notYetValidMessage := fmt.Sprintf("not valid until %s", notBefore.UTC().Format(time.RFC3339))

	cases := []struct {
		title    string
		evalTime time.Time
		expected []string
	}{
		{
			title:    "ValidInTheMiddle",
			evalTime: healthtest.Now,
			expected: nil,
		},
		{
			title:    "ValidAtNotBefore",
			evalTime: notBefore,
			expected: nil,
		},
		{
			title:    "ValidOneSecondBeforeNotAfter",
			evalTime: notAfter.Add(-time.Second),
			expected: nil,
		},
		{
			title:    "NotYetValid",
			evalTime: notBefore.Add(-time.Second),
			expected: []string{notYetValidMessage},
		},
		{
			// the validity period is half-open: [NotBefore, NotAfter)
			title:    "ExpiredAtNotAfter",
			evalTime: notAfter,
			expected: []string{expiredMessage},
		},
		{
			title:    "Expired",
			evalTime: notAfter.Add(24 * time.Hour),
			expected: []string{expiredMessage},
		},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			t.Parallel()
			leaf := &x509.Certificate{NotBefore: notBefore, NotAfter: notAfter}
			res := health.Result{}
			checkExpiry(leaf, &res, tc.evalTime)
			assert.Equal(t, tc.expected, res.Problems)
			assert.Empty(t, res.Warnings)
		})
	}

	t.Run("NonUTCTimesAreReportedInUTC", func(t *testing.T) {
		t.Parallel()
		zone := time.FixedZone("JST", 9*60*60)
		leaf := &x509.Certificate{
			NotBefore: notBefore.In(zone),
			NotAfter:  notAfter.In(zone),
		}
		res := health.Result{}
		checkExpiry(leaf, &res, notAfter.Add(time.Minute))
		assert.Equal(t, []string{expiredMessage}, res.Problems)
	})
}

func TestEvaluate(t *testing.T) {
	t.Parallel()

	valid := newTestPKI(t, validSpec())
	expired := newTestPKI(t, expiredSpec())
	notYetValid := newTestPKI(t, notYetValidSpec())
	expiredIssuer := newTestPKI(t, expiredIssuerSpec())

	allChecks := health.Policy{CheckExpiry: true, CheckRevocation: true, CheckCT: true}
	expiredMessage := fmt.Sprintf("expired at %s", healthtest.Now.Add(-time.Hour).UTC().Format(time.RFC3339))
	notYetValidMessage := fmt.Sprintf("not valid until %s", healthtest.Now.Add(time.Hour).UTC().Format(time.RFC3339))
	revokedDetail := "revoked at 2026-01-01T00:00:00Z according to CRL (reason code 1)"
	noIssuerWarning := "issuer certificate not present in tls.crt, skipping revocation check"

	cases := []struct {
		title                   string
		secret                  *corev1.Secret
		policy                  health.Policy
		revocation              *fakeRevocationChecker
		ct                      *fakeCTChecker
		expected                health.Result
		expectedRevocationCalls int
		expectedCTCalls         int
	}{
		{
			title:    "ValidNoChecks",
			secret:   healthtest.TLSSecret(valid.chainPEM),
			policy:   health.Policy{},
			expected: health.Result{Parsed: true},
		},
		{
			title:                   "ValidAllChecksPass",
			secret:                  healthtest.TLSSecret(valid.chainPEM),
			policy:                  allChecks,
			revocation:              &fakeRevocationChecker{},
			ct:                      &fakeCTChecker{},
			expected:                health.Result{Parsed: true},
			expectedRevocationCalls: 1,
			expectedCTCalls:         1,
		},
		{
			title:                   "Expired",
			secret:                  healthtest.TLSSecret(expired.chainPEM),
			policy:                  allChecks,
			revocation:              &fakeRevocationChecker{},
			ct:                      &fakeCTChecker{},
			expected:                health.Result{Parsed: true, Problems: []string{expiredMessage}},
			expectedRevocationCalls: 0,
			expectedCTCalls:         0,
		},
		{
			title:                   "NotYetValid",
			secret:                  healthtest.TLSSecret(notYetValid.chainPEM),
			policy:                  allChecks,
			revocation:              &fakeRevocationChecker{},
			ct:                      &fakeCTChecker{},
			expected:                health.Result{Parsed: true, Problems: []string{notYetValidMessage}},
			expectedRevocationCalls: 0,
			expectedCTCalls:         0,
		},
		{
			title:                   "ExpiredButExpiryCheckDisabled",
			secret:                  healthtest.TLSSecret(expired.chainPEM),
			policy:                  health.Policy{CheckRevocation: true, CheckCT: true},
			revocation:              &fakeRevocationChecker{},
			ct:                      &fakeCTChecker{},
			expected:                health.Result{Parsed: true},
			expectedRevocationCalls: 1,
			expectedCTCalls:         1,
		},
		{
			// only the leaf is checked, validating the rest of the chain is cert-manager's job
			title:                   "ExpiredIssuerIsIgnored",
			secret:                  healthtest.TLSSecret(expiredIssuer.chainPEM),
			policy:                  allChecks,
			revocation:              &fakeRevocationChecker{},
			ct:                      &fakeCTChecker{},
			expected:                health.Result{Parsed: true},
			expectedRevocationCalls: 1,
			expectedCTCalls:         1,
		},
		{
			title:                   "Revoked",
			secret:                  healthtest.TLSSecret(valid.chainPEM),
			policy:                  allChecks,
			revocation:              &fakeRevocationChecker{revoked: true, detail: revokedDetail},
			ct:                      &fakeCTChecker{},
			expected:                health.Result{Parsed: true, Problems: []string{revokedDetail}},
			expectedRevocationCalls: 1,
			expectedCTCalls:         1,
		},
		{
			title:                   "RevocationStatusUnknown",
			secret:                  healthtest.TLSSecret(valid.chainPEM),
			policy:                  allChecks,
			revocation:              &fakeRevocationChecker{err: errors.New("boom")},
			ct:                      &fakeCTChecker{},
			expected:                health.Result{Parsed: true, Warnings: []string{"revocation status unknown: boom"}},
			expectedRevocationCalls: 1,
			expectedCTCalls:         1,
		},
		{
			// an error always wins over the revoked flag, an inconclusive check must never fail a certificate
			title:                   "RevocationErrorTakesPrecedenceOverRevoked",
			secret:                  healthtest.TLSSecret(valid.chainPEM),
			policy:                  allChecks,
			revocation:              &fakeRevocationChecker{revoked: true, detail: revokedDetail, err: errors.New("boom")},
			ct:                      &fakeCTChecker{},
			expected:                health.Result{Parsed: true, Warnings: []string{"revocation status unknown: boom"}},
			expectedRevocationCalls: 1,
			expectedCTCalls:         1,
		},
		{
			title:                   "RevocationInfoNotAvailable",
			secret:                  healthtest.TLSSecret(valid.chainPEM),
			policy:                  allChecks,
			revocation:              &fakeRevocationChecker{err: health.ErrNoRevocationInfo},
			ct:                      &fakeCTChecker{},
			expected:                health.Result{Parsed: true},
			expectedRevocationCalls: 1,
			expectedCTCalls:         1,
		},
		{
			title:                   "RevocationInfoNotAvailableWrapped",
			secret:                  healthtest.TLSSecret(valid.chainPEM),
			policy:                  allChecks,
			revocation:              &fakeRevocationChecker{err: fmt.Errorf("lookup failed: %w", health.ErrNoRevocationInfo)},
			ct:                      &fakeCTChecker{},
			expected:                health.Result{Parsed: true},
			expectedRevocationCalls: 1,
			expectedCTCalls:         1,
		},
		{
			title:                   "RevocationSkippedWithoutIssuer",
			secret:                  healthtest.TLSSecret(valid.leafPEM),
			policy:                  allChecks,
			revocation:              &fakeRevocationChecker{revoked: true, detail: revokedDetail},
			ct:                      &fakeCTChecker{},
			expected:                health.Result{Parsed: true, Warnings: []string{noIssuerWarning}},
			expectedRevocationCalls: 0,
			expectedCTCalls:         1,
		},
		{
			title:                   "RevocationDisabledByPolicy",
			secret:                  healthtest.TLSSecret(valid.chainPEM),
			policy:                  health.Policy{CheckExpiry: true, CheckCT: true},
			revocation:              &fakeRevocationChecker{revoked: true, detail: revokedDetail},
			ct:                      &fakeCTChecker{},
			expected:                health.Result{Parsed: true},
			expectedRevocationCalls: 0,
			expectedCTCalls:         1,
		},
		{
			title:                   "CTProblem",
			secret:                  healthtest.TLSSecret(valid.chainPEM),
			policy:                  allChecks,
			revocation:              &fakeRevocationChecker{},
			ct:                      &fakeCTChecker{result: health.CTResult{Problem: "certificate has no embedded SCTs"}},
			expected:                health.Result{Parsed: true, Problems: []string{"certificate has no embedded SCTs"}},
			expectedRevocationCalls: 1,
			expectedCTCalls:         1,
		},
		{
			title:                   "CTWarnings",
			secret:                  healthtest.TLSSecret(valid.chainPEM),
			policy:                  allChecks,
			revocation:              &fakeRevocationChecker{},
			ct:                      &fakeCTChecker{result: health.CTResult{Warnings: []string{"SCT[1]: log unreachable"}}},
			expected:                health.Result{Parsed: true, Warnings: []string{"SCT[1]: log unreachable"}},
			expectedRevocationCalls: 1,
			expectedCTCalls:         1,
		},
		{
			title:      "CTProblemAndWarnings",
			secret:     healthtest.TLSSecret(valid.chainPEM),
			policy:     allChecks,
			revocation: &fakeRevocationChecker{},
			ct: &fakeCTChecker{result: health.CTResult{
				Problem:  "SCTs from 1 distinct log operator(s), at least 2 required",
				Warnings: []string{"SCT[1]: log unreachable"},
			}},
			expected: health.Result{
				Parsed:   true,
				Problems: []string{"SCTs from 1 distinct log operator(s), at least 2 required"},
				Warnings: []string{"SCT[1]: log unreachable"},
			},
			expectedRevocationCalls: 1,
			expectedCTCalls:         1,
		},
		{
			title:                   "CTStatusUnknown",
			secret:                  healthtest.TLSSecret(valid.chainPEM),
			policy:                  allChecks,
			revocation:              &fakeRevocationChecker{},
			ct:                      &fakeCTChecker{err: errors.New("boom")},
			expected:                health.Result{Parsed: true, Warnings: []string{"certificate transparency status unknown: boom"}},
			expectedRevocationCalls: 1,
			expectedCTCalls:         1,
		},
		{
			// a result that comes with an error is discarded, only the error is reported
			title:  "CTErrorDiscardsResult",
			secret: healthtest.TLSSecret(valid.chainPEM),
			policy: allChecks,
			ct: &fakeCTChecker{
				result: health.CTResult{Problem: "ignored", Warnings: []string{"ignored"}},
				err:    errors.New("boom"),
			},
			expected:        health.Result{Parsed: true, Warnings: []string{"certificate transparency status unknown: boom"}},
			expectedCTCalls: 1,
		},
		{
			title:                   "CTDisabledByPolicy",
			secret:                  healthtest.TLSSecret(valid.chainPEM),
			policy:                  health.Policy{CheckExpiry: true, CheckRevocation: true},
			revocation:              &fakeRevocationChecker{},
			ct:                      &fakeCTChecker{result: health.CTResult{Problem: "should not be reported"}},
			expected:                health.Result{Parsed: true},
			expectedRevocationCalls: 1,
			expectedCTCalls:         0,
		},
		{
			title:      "ProblemsAndWarningsKeepCheckOrder",
			secret:     healthtest.TLSSecret(valid.chainPEM),
			policy:     allChecks,
			revocation: &fakeRevocationChecker{revoked: true, detail: revokedDetail},
			ct: &fakeCTChecker{result: health.CTResult{
				Problem:  "certificate has no embedded SCTs",
				Warnings: []string{"ct warning"},
			}},
			expected: health.Result{
				Parsed:   true,
				Problems: []string{revokedDetail, "certificate has no embedded SCTs"},
				Warnings: []string{"ct warning"},
			},
			expectedRevocationCalls: 1,
			expectedCTCalls:         1,
		},
		{
			title:                   "WarningsKeepCheckOrder",
			secret:                  healthtest.TLSSecret(valid.chainPEM),
			policy:                  allChecks,
			revocation:              &fakeRevocationChecker{err: errors.New("revocation boom")},
			ct:                      &fakeCTChecker{err: errors.New("ct boom")},
			expected:                health.Result{Parsed: true, Warnings: []string{"revocation status unknown: revocation boom", "certificate transparency status unknown: ct boom"}},
			expectedRevocationCalls: 1,
			expectedCTCalls:         1,
		},
		{
			title:    "CheckersNotConfigured",
			secret:   healthtest.TLSSecret(valid.chainPEM),
			policy:   allChecks,
			expected: health.Result{Parsed: true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			t.Parallel()
			var opts []X509Option
			// a nil pointer must not be wrapped in a non-nil interface
			if tc.revocation != nil {
				opts = append(opts, WithRevocationChecker(tc.revocation))
			}
			if tc.ct != nil {
				opts = append(opts, WithCTChecker(tc.ct))
			}
			f := NewX509Format(opts...)

			actual := f.Evaluate(context.Background(), tc.secret, tc.policy, healthtest.Now)
			assert.Equal(t, tc.expected, actual)
			if tc.revocation != nil {
				assert.Equal(t, tc.expectedRevocationCalls, tc.revocation.calls)
			}
			if tc.ct != nil {
				assert.Equal(t, tc.expectedCTCalls, tc.ct.calls)
			}
		})
	}
}

func TestEvaluateUnparsable(t *testing.T) {
	t.Parallel()

	cases := []struct {
		title       string
		secret      *corev1.Secret
		errContains string
	}{
		{
			title:       "MalformedCertificate",
			secret:      healthtest.TLSSecret(healthtest.PEMBlock("CERTIFICATE", []byte("garbage"))),
			errContains: "failed to parse certificate in tls.crt",
		},
		{
			title:       "EmptySecret",
			secret:      &corev1.Secret{},
			errContains: "no certificate found in tls.crt",
		},
		{
			title:       "OnlyNonCertificateBlock",
			secret:      healthtest.TLSSecret(healthtest.PEMBlock("PRIVATE KEY", []byte("key"))),
			errContains: "no certificate found in tls.crt",
		},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			t.Parallel()
			revocation := &fakeRevocationChecker{}
			ct := &fakeCTChecker{}
			f := NewX509Format(WithRevocationChecker(revocation), WithCTChecker(ct))

			policy := health.Policy{CheckExpiry: true, CheckRevocation: true, CheckCT: true}
			actual := f.Evaluate(context.Background(), tc.secret, policy, healthtest.Now)

			assert.False(t, actual.Parsed)
			assert.False(t, actual.Eligible())
			assert.Empty(t, actual.Warnings)
			if assert.Len(t, actual.Problems, 1) {
				assert.Contains(t, actual.Problems[0], tc.errContains)
			}
			assert.Zero(t, revocation.calls)
			assert.Zero(t, ct.calls)
		})
	}
}

func TestEvaluateEligibility(t *testing.T) {
	t.Parallel()

	valid := newTestPKI(t, validSpec())
	expired := newTestPKI(t, expiredSpec())
	policy := health.Policy{CheckExpiry: true, CheckRevocation: true, CheckCT: true}

	cases := []struct {
		title      string
		secret     *corev1.Secret
		revocation *fakeRevocationChecker
		ct         *fakeCTChecker
		expected   bool
	}{
		{
			title:      "AllChecksPass",
			secret:     healthtest.TLSSecret(valid.chainPEM),
			revocation: &fakeRevocationChecker{},
			ct:         &fakeCTChecker{},
			expected:   true,
		},
		{
			// inconclusive checks never make a certificate ineligible
			title:      "WarningsDoNotAffectEligibility",
			secret:     healthtest.TLSSecret(valid.chainPEM),
			revocation: &fakeRevocationChecker{err: errors.New("boom")},
			ct:         &fakeCTChecker{err: errors.New("boom")},
			expected:   true,
		},
		{
			title:      "Expired",
			secret:     healthtest.TLSSecret(expired.chainPEM),
			revocation: &fakeRevocationChecker{},
			ct:         &fakeCTChecker{},
			expected:   false,
		},
		{
			title:      "Revoked",
			secret:     healthtest.TLSSecret(valid.chainPEM),
			revocation: &fakeRevocationChecker{revoked: true, detail: "revoked"},
			ct:         &fakeCTChecker{},
			expected:   false,
		},
		{
			title:      "CTProblem",
			secret:     healthtest.TLSSecret(valid.chainPEM),
			revocation: &fakeRevocationChecker{},
			ct:         &fakeCTChecker{result: health.CTResult{Problem: "no SCTs"}},
			expected:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			t.Parallel()
			f := NewX509Format(WithRevocationChecker(tc.revocation), WithCTChecker(tc.ct))
			actual := f.Evaluate(context.Background(), tc.secret, policy, healthtest.Now)
			assert.Equal(t, tc.expected, actual.Eligible())
		})
	}
}

func TestEvaluatePassesChainToCheckers(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, validSpec())
	other := newTestPKI(t, validSpec())
	// leaf, issuer, and one more certificate: the issuer must be the second one, whatever follows
	secret := healthtest.TLSSecret(pki.leafPEM, pki.issuerPEM, other.issuerPEM)

	revocation := &fakeRevocationChecker{}
	ct := &fakeCTChecker{}
	f := NewX509Format(WithRevocationChecker(revocation), WithCTChecker(ct))

	policy := health.Policy{CheckExpiry: true, CheckRevocation: true, CheckCT: true}
	actual := f.Evaluate(context.Background(), secret, policy, healthtest.Now)
	assert.Equal(t, health.Result{Parsed: true}, actual)

	if assert.NotNil(t, revocation.leaf) && assert.NotNil(t, revocation.issuer) {
		assert.Equal(t, pki.leafRaw, revocation.leaf.Raw)
		assert.Equal(t, pki.issuerRaw, revocation.issuer.Raw)
	}
	// the CT checker gets the whole tls.crt as is
	assert.Equal(t, secret.Data[corev1.TLSCertKey], ct.chainPEM)
}

func TestEvaluatePropagatesContext(t *testing.T) {
	t.Parallel()

	pki := newTestPKI(t, validSpec())
	revocation := &fakeRevocationChecker{}
	ct := &fakeCTChecker{}
	f := NewX509Format(WithRevocationChecker(revocation), WithCTChecker(ct))

	ctx := context.WithValue(context.Background(), healthtest.ContextKey{}, "value")
	policy := health.Policy{CheckExpiry: true, CheckRevocation: true, CheckCT: true}
	f.Evaluate(ctx, healthtest.TLSSecret(pki.chainPEM), policy, healthtest.Now)

	if assert.NotNil(t, revocation.ctx) {
		assert.Equal(t, "value", revocation.ctx.Value(healthtest.ContextKey{}))
	}
	if assert.NotNil(t, ct.ctx) {
		assert.Equal(t, "value", ct.ctx.Value(healthtest.ContextKey{}))
	}
}
