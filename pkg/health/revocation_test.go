package health

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hsn723/cert-orchestrator/internal/healthtest"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ocsp"
)

const (
	revLeafSerial        = healthtest.DefaultSerial
	revCRLRevokedDetail  = "revoked at 2026-01-15T12:00:00Z according to CRL (reason code 1)"
	revOCSPRevokedDetail = "revoked at 2026-01-15T12:00:00Z according to OCSP (reason code 1)"
)

// newRevCA creates a self-signed CA. Calling it twice yields two CAs with the same subject but different
// keys, which is how the tests build "impostor" signers.
func newRevCA(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	ca := healthtest.NewCA(t, healthtest.CASpec{})
	return ca.Key, ca.Cert
}

func newRevLeaf(t *testing.T, caKey *ecdsa.PrivateKey, ca *x509.Certificate, crlURLs, ocspURLs []string) *x509.Certificate {
	t.Helper()
	issuer := &healthtest.CA{Key: caKey, Cert: ca}
	return issuer.Issue(t, healthtest.CertSpec{CRLDistributionPoints: crlURLs, OCSPServer: ocspURLs}).Cert
}

func revEntry(serial int64) x509.RevocationListEntry {
	return x509.RevocationListEntry{
		SerialNumber:   big.NewInt(serial),
		RevocationTime: healthtest.Now,
		ReasonCode:     1,
	}
}

// revCRL describes a CRL. Zero times default to a fresh CRL: issued an hour ago, valid for a day.
type revCRL struct {
	entries    []x509.RevocationListEntry
	thisUpdate time.Time
	nextUpdate time.Time
}

func (c revCRL) der(t *testing.T, key *ecdsa.PrivateKey, issuer *x509.Certificate) []byte {
	t.Helper()
	thisUpdate, nextUpdate := c.thisUpdate, c.nextUpdate
	if thisUpdate.IsZero() {
		thisUpdate = time.Now().Add(-time.Hour)
	}
	if nextUpdate.IsZero() {
		nextUpdate = time.Now().Add(24 * time.Hour)
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: c.entries,
	}, issuer, key)
	healthtest.Must(t, err)
	return der
}

func revOCSPResponse(t *testing.T, issuer *x509.Certificate, key *ecdsa.PrivateKey, status int, serial int64, thisUpdate, nextUpdate time.Time) []byte {
	t.Helper()
	template := ocsp.Response{
		Status:       status,
		SerialNumber: big.NewInt(serial),
		ThisUpdate:   thisUpdate,
		NextUpdate:   nextUpdate,
	}
	if status == ocsp.Revoked {
		template.RevokedAt = healthtest.Now
		template.RevocationReason = ocsp.KeyCompromise
	}
	der, err := ocsp.CreateResponse(issuer, issuer, template, key)
	healthtest.Must(t, err)
	return der
}

// revServer is a fake CRL distribution point or OCSP responder.
type revServer struct {
	server *httptest.Server
	hits   atomic.Int64

	mu          sync.Mutex
	status      int
	body        []byte
	method      string
	contentType string
	reqBody     []byte
}

func newRevServer(t *testing.T) *revServer {
	t.Helper()
	s := &revServer{status: http.StatusOK}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		reqBody, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		defer s.mu.Unlock()
		s.method = r.Method
		s.contentType = r.Header.Get("Content-Type")
		s.reqBody = reqBody
		w.WriteHeader(s.status)
		_, _ = w.Write(s.body)
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *revServer) url() string {
	return s.server.URL
}

func (s *revServer) set(status int, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = status
	s.body = body
}

func (s *revServer) lastRequest() (method, contentType string, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.method, s.contentType, s.reqBody
}

// revFixture is a CA, a leaf certificate pointing at fake CRL and OCSP servers, and a checker.
type revFixture struct {
	caKey   *ecdsa.PrivateKey
	ca      *x509.Certificate
	leaf    *x509.Certificate
	crls    []*revServer
	ocsps   []*revServer
	checker *NetworkRevocationChecker
}

func newRevFixture(t *testing.T, crlCount, ocspCount int) *revFixture {
	t.Helper()
	f := &revFixture{checker: NewNetworkRevocationChecker()}
	f.caKey, f.ca = newRevCA(t)

	var crlURLs, ocspURLs []string
	for i := 0; i < crlCount; i++ {
		s := newRevServer(t)
		f.crls = append(f.crls, s)
		crlURLs = append(crlURLs, s.url())
	}
	for i := 0; i < ocspCount; i++ {
		s := newRevServer(t)
		f.ocsps = append(f.ocsps, s)
		ocspURLs = append(ocspURLs, s.url())
	}
	f.leaf = newRevLeaf(t, f.caKey, f.ca, crlURLs, ocspURLs)
	return f
}

func (f *revFixture) serveCRL(t *testing.T, i int, spec revCRL) {
	t.Helper()
	f.crls[i].set(http.StatusOK, spec.der(t, f.caKey, f.ca))
}

func (f *revFixture) serveOCSP(t *testing.T, i, status int, serial int64) {
	t.Helper()
	now := time.Now()
	f.ocsps[i].set(http.StatusOK, revOCSPResponse(t, f.ca, f.caKey, status, serial, now.Add(-time.Hour), now.Add(24*time.Hour)))
}

func (f *revFixture) isRevoked() (bool, string, error) {
	return f.checker.IsRevoked(context.Background(), f.leaf, f.ca)
}

// expireCaches makes every cached verdict stale.
func (f *revFixture) expireCaches() {
	f.checker.mu.Lock()
	defer f.checker.mu.Unlock()
	past := time.Now().Add(-time.Minute)
	for k, v := range f.checker.crlCache {
		v.expires = past
		f.checker.crlCache[k] = v
	}
	for k, v := range f.checker.ocspCache {
		v.expires = past
		f.checker.ocspCache[k] = v
	}
}

func TestNewNetworkRevocationChecker(t *testing.T) {
	t.Parallel()
	c := NewNetworkRevocationChecker()
	if assert.NotNil(t, c.client) {
		assert.Equal(t, revocationFetchTimeout, c.client.Timeout)
	}
	assert.NotNil(t, c.ocspCache)
	assert.NotNil(t, c.crlCache)
}

func TestCacheExpiry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.January, 15, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		title      string
		nextUpdate time.Time
		expected   time.Time
	}{
		{
			title:      "NoNextUpdate",
			nextUpdate: time.Time{},
			expected:   now.Add(revocationCacheTTL),
		},
		{
			title:      "NextUpdateBeforeTTL",
			nextUpdate: now.Add(10 * time.Minute),
			expected:   now.Add(10 * time.Minute),
		},
		{
			title:      "NextUpdateAfterTTLIsCapped",
			nextUpdate: now.Add(24 * time.Hour),
			expected:   now.Add(revocationCacheTTL),
		},
		{
			title:      "NextUpdateExactlyAtTTL",
			nextUpdate: now.Add(revocationCacheTTL),
			expected:   now.Add(revocationCacheTTL),
		},
		{
			title:      "NextUpdateInThePast",
			nextUpdate: now.Add(-time.Minute),
			expected:   now.Add(-time.Minute),
		},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, cacheExpiry(now, tc.nextUpdate))
		})
	}
}

func TestFetch(t *testing.T) {
	t.Parallel()

	t.Run("UnsupportedURLs", func(t *testing.T) {
		t.Parallel()
		for _, u := range []string{"ftp://example.com/crl", "file:///etc/passwd", "://bad", "", "example.com/crl", "ldap://example.com/crl"} {
			c := NewNetworkRevocationChecker()
			body, err := c.fetch(context.Background(), http.MethodGet, u, "", nil, 1024)
			assert.ErrorContains(t, err, "unsupported URL", u)
			assert.Nil(t, body, u)
		}
	})
	t.Run("Get", func(t *testing.T) {
		t.Parallel()
		s := newRevServer(t)
		s.set(http.StatusOK, []byte("hello"))
		c := NewNetworkRevocationChecker()

		body, err := c.fetch(context.Background(), http.MethodGet, s.url(), "", nil, 1024)
		assert.NoError(t, err)
		assert.Equal(t, []byte("hello"), body)

		method, contentType, reqBody := s.lastRequest()
		assert.Equal(t, http.MethodGet, method)
		assert.Empty(t, contentType)
		assert.Empty(t, reqBody)
	})
	t.Run("PostWithPayload", func(t *testing.T) {
		t.Parallel()
		s := newRevServer(t)
		s.set(http.StatusOK, []byte("ok"))
		c := NewNetworkRevocationChecker()

		body, err := c.fetch(context.Background(), http.MethodPost, s.url(), "application/test", []byte("payload"), 1024)
		assert.NoError(t, err)
		assert.Equal(t, []byte("ok"), body)

		method, contentType, reqBody := s.lastRequest()
		assert.Equal(t, http.MethodPost, method)
		assert.Equal(t, "application/test", contentType)
		assert.Equal(t, []byte("payload"), reqBody)
	})
	t.Run("UnexpectedStatus", func(t *testing.T) {
		t.Parallel()
		s := newRevServer(t)
		s.set(http.StatusInternalServerError, []byte("boom"))
		c := NewNetworkRevocationChecker()

		body, err := c.fetch(context.Background(), http.MethodGet, s.url(), "", nil, 1024)
		assert.ErrorContains(t, err, "unexpected status 500")
		assert.Nil(t, body)
	})
	t.Run("ResponseAtLimit", func(t *testing.T) {
		t.Parallel()
		s := newRevServer(t)
		s.set(http.StatusOK, []byte("0123456789"))
		c := NewNetworkRevocationChecker()

		body, err := c.fetch(context.Background(), http.MethodGet, s.url(), "", nil, 10)
		assert.NoError(t, err)
		assert.Equal(t, []byte("0123456789"), body)
	})
	t.Run("ResponseOverLimit", func(t *testing.T) {
		t.Parallel()
		s := newRevServer(t)
		s.set(http.StatusOK, []byte("0123456789A"))
		c := NewNetworkRevocationChecker()

		body, err := c.fetch(context.Background(), http.MethodGet, s.url(), "", nil, 10)
		assert.ErrorContains(t, err, "response exceeds 10 bytes")
		assert.Nil(t, body)
	})
	t.Run("ConnectionRefused", func(t *testing.T) {
		t.Parallel()
		s := httptest.NewServer(http.NotFoundHandler())
		u := s.URL
		s.Close()
		c := NewNetworkRevocationChecker()

		body, err := c.fetch(context.Background(), http.MethodGet, u, "", nil, 1024)
		assert.Error(t, err)
		assert.Nil(t, body)
	})
}

func TestIsRevokedNoRevocationInfo(t *testing.T) {
	t.Parallel()
	f := newRevFixture(t, 0, 0)

	revoked, detail, err := f.isRevoked()
	assert.ErrorIs(t, err, ErrNoRevocationInfo)
	assert.False(t, revoked)
	assert.Empty(t, detail)
}

func TestIsRevokedByCRL(t *testing.T) {
	t.Parallel()

	now := time.Now()
	cases := []struct {
		title       string
		crls        int
		setup       func(t *testing.T, f *revFixture)
		revoked     bool
		detail      string
		errFunc     assert.ErrorAssertionFunc
		errContains string
		hits        []int64
	}{
		{
			title: "NotRevoked",
			crls:  1,
			setup: func(t *testing.T, f *revFixture) {
				f.serveCRL(t, 0, revCRL{entries: []x509.RevocationListEntry{revEntry(9999)}})
			},
			errFunc: assert.NoError,
			hits:    []int64{1},
		},
		{
			title: "NotRevokedEmptyCRL",
			crls:  1,
			setup: func(t *testing.T, f *revFixture) {
				f.serveCRL(t, 0, revCRL{})
			},
			errFunc: assert.NoError,
		},
		{
			title: "Revoked",
			crls:  1,
			setup: func(t *testing.T, f *revFixture) {
				f.serveCRL(t, 0, revCRL{entries: []x509.RevocationListEntry{revEntry(9999), revEntry(revLeafSerial)}})
			},
			revoked: true,
			detail:  revCRLRevokedDetail,
			errFunc: assert.NoError,
		},
		{
			title: "RevokedPEMEncodedCRL",
			crls:  1,
			setup: func(t *testing.T, f *revFixture) {
				der := revCRL{entries: []x509.RevocationListEntry{revEntry(revLeafSerial)}}.der(t, f.caKey, f.ca)
				f.crls[0].set(http.StatusOK, healthtest.PEMBlock("X509 CRL", der))
			},
			revoked: true,
			detail:  revCRLRevokedDetail,
			errFunc: assert.NoError,
		},
		{
			title: "StaleCRL",
			crls:  1,
			setup: func(t *testing.T, f *revFixture) {
				f.serveCRL(t, 0, revCRL{thisUpdate: now.Add(-48 * time.Hour), nextUpdate: now.Add(-24 * time.Hour)})
			},
			errFunc:     assert.Error,
			errContains: "stale CRL",
		},
		{
			title: "MalformedCRL",
			crls:  1,
			setup: func(_ *testing.T, f *revFixture) {
				f.crls[0].set(http.StatusOK, []byte("garbage"))
			},
			errFunc:     assert.Error,
			errContains: "failed to parse CRL",
		},
		{
			title: "EmptyResponse",
			crls:  1,
			setup: func(_ *testing.T, f *revFixture) {
				f.crls[0].set(http.StatusOK, nil)
			},
			errFunc:     assert.Error,
			errContains: "failed to parse CRL",
		},
		{
			// a CRL signed by somebody else must not be trusted, even if it lists nothing
			title: "SignedByAnotherKey",
			crls:  1,
			setup: func(t *testing.T, f *revFixture) {
				impostorKey, impostor := newRevCA(t)
				f.crls[0].set(http.StatusOK, revCRL{}.der(t, impostorKey, impostor))
			},
			errFunc:     assert.Error,
			errContains: "failed to verify CRL signature",
		},
		{
			title: "ServerError",
			crls:  1,
			setup: func(_ *testing.T, f *revFixture) {
				f.crls[0].set(http.StatusInternalServerError, nil)
			},
			errFunc:     assert.Error,
			errContains: "unexpected status 500",
		},
		{
			title: "NextDistributionPointUsedWhenFirstFails",
			crls:  2,
			setup: func(t *testing.T, f *revFixture) {
				f.crls[0].set(http.StatusInternalServerError, nil)
				f.serveCRL(t, 1, revCRL{entries: []x509.RevocationListEntry{revEntry(revLeafSerial)}})
			},
			revoked: true,
			detail:  revCRLRevokedDetail,
			errFunc: assert.NoError,
			hits:    []int64{1, 1},
		},
		{
			// the first CRL that answers is authoritative
			title: "FirstSuccessfulDistributionPointWins",
			crls:  2,
			setup: func(t *testing.T, f *revFixture) {
				f.serveCRL(t, 0, revCRL{})
				f.serveCRL(t, 1, revCRL{entries: []x509.RevocationListEntry{revEntry(revLeafSerial)}})
			},
			errFunc: assert.NoError,
			hits:    []int64{1, 0},
		},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			t.Parallel()
			f := newRevFixture(t, tc.crls, 0)
			tc.setup(t, f)

			revoked, detail, err := f.isRevoked()
			tc.errFunc(t, err)
			if tc.errContains != "" {
				assert.ErrorContains(t, err, tc.errContains)
			}
			assert.Equal(t, tc.revoked, revoked)
			assert.Equal(t, tc.detail, detail)
			for i, hits := range tc.hits {
				assert.Equal(t, hits, f.crls[i].hits.Load(), "CRL server %d", i)
			}
		})
	}
}

func TestIsRevokedByCRLAllDistributionPointsFail(t *testing.T) {
	t.Parallel()
	f := newRevFixture(t, 2, 0)
	f.crls[0].set(http.StatusInternalServerError, nil)
	f.crls[1].set(http.StatusOK, []byte("garbage"))

	revoked, detail, err := f.isRevoked()
	assert.False(t, revoked)
	assert.Empty(t, detail)
	// every failure is reported, with the endpoint it came from
	assert.ErrorContains(t, err, "CRL "+f.crls[0].url())
	assert.ErrorContains(t, err, "unexpected status 500")
	assert.ErrorContains(t, err, "CRL "+f.crls[1].url())
	assert.ErrorContains(t, err, "failed to parse CRL")
}

func TestIsRevokedByOCSP(t *testing.T) {
	t.Parallel()

	now := time.Now()
	cases := []struct {
		title       string
		setup       func(t *testing.T, f *revFixture)
		revoked     bool
		detail      string
		errFunc     assert.ErrorAssertionFunc
		errContains string
	}{
		{
			title: "Good",
			setup: func(t *testing.T, f *revFixture) {
				f.serveOCSP(t, 0, ocsp.Good, revLeafSerial)
			},
			errFunc: assert.NoError,
		},
		{
			title: "Revoked",
			setup: func(t *testing.T, f *revFixture) {
				f.serveOCSP(t, 0, ocsp.Revoked, revLeafSerial)
			},
			revoked: true,
			detail:  revOCSPRevokedDetail,
			errFunc: assert.NoError,
		},
		{
			title: "StatusUnknown",
			setup: func(t *testing.T, f *revFixture) {
				f.serveOCSP(t, 0, ocsp.Unknown, revLeafSerial)
			},
			errFunc:     assert.Error,
			errContains: "OCSP responder does not know this certificate",
		},
		{
			title: "StaleResponse",
			setup: func(t *testing.T, f *revFixture) {
				f.ocsps[0].set(http.StatusOK, revOCSPResponse(t, f.ca, f.caKey, ocsp.Good, revLeafSerial, now.Add(-2*time.Hour), now.Add(-time.Minute)))
			},
			errFunc:     assert.Error,
			errContains: "stale OCSP response",
		},
		{
			title: "MalformedResponse",
			setup: func(_ *testing.T, f *revFixture) {
				f.ocsps[0].set(http.StatusOK, []byte("garbage"))
			},
			errFunc:     assert.Error,
			errContains: "failed to parse OCSP response",
		},
		{
			title: "EmptyResponse",
			setup: func(_ *testing.T, f *revFixture) {
				f.ocsps[0].set(http.StatusOK, nil)
			},
			errFunc:     assert.Error,
			errContains: "failed to parse OCSP response",
		},
		{
			// a response that does not verify against the issuer must not be trusted
			title: "SignedByAnotherKey",
			setup: func(t *testing.T, f *revFixture) {
				otherKey, _ := newRevCA(t)
				f.ocsps[0].set(http.StatusOK, revOCSPResponse(t, f.ca, otherKey, ocsp.Good, revLeafSerial, now.Add(-time.Hour), now.Add(24*time.Hour)))
			},
			errFunc:     assert.Error,
			errContains: "failed to parse OCSP response",
		},
		{
			title: "ResponseForAnotherCertificate",
			setup: func(t *testing.T, f *revFixture) {
				f.serveOCSP(t, 0, ocsp.Good, 4242)
			},
			errFunc:     assert.Error,
			errContains: "failed to parse OCSP response",
		},
		{
			title: "ServerError",
			setup: func(_ *testing.T, f *revFixture) {
				f.ocsps[0].set(http.StatusInternalServerError, nil)
			},
			errFunc:     assert.Error,
			errContains: "unexpected status 500",
		},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			t.Parallel()
			f := newRevFixture(t, 0, 1)
			tc.setup(t, f)

			revoked, detail, err := f.isRevoked()
			tc.errFunc(t, err)
			if tc.errContains != "" {
				assert.ErrorContains(t, err, tc.errContains)
			}
			assert.Equal(t, tc.revoked, revoked)
			assert.Equal(t, tc.detail, detail)
		})
	}
}

func TestIsRevokedByOCSPMultipleServers(t *testing.T) {
	t.Parallel()

	t.Run("NextServerUsedWhenFirstFails", func(t *testing.T) {
		t.Parallel()
		f := newRevFixture(t, 0, 2)
		f.ocsps[0].set(http.StatusInternalServerError, nil)
		f.serveOCSP(t, 1, ocsp.Revoked, revLeafSerial)

		revoked, detail, err := f.isRevoked()
		assert.NoError(t, err)
		assert.True(t, revoked)
		assert.Equal(t, revOCSPRevokedDetail, detail)
		assert.EqualValues(t, 1, f.ocsps[0].hits.Load())
		assert.EqualValues(t, 1, f.ocsps[1].hits.Load())
	})
	t.Run("FirstSuccessfulServerWins", func(t *testing.T) {
		t.Parallel()
		f := newRevFixture(t, 0, 2)
		f.serveOCSP(t, 0, ocsp.Good, revLeafSerial)
		f.serveOCSP(t, 1, ocsp.Revoked, revLeafSerial)

		revoked, _, err := f.isRevoked()
		assert.NoError(t, err)
		assert.False(t, revoked)
		assert.EqualValues(t, 0, f.ocsps[1].hits.Load())
	})
	t.Run("AllServersFail", func(t *testing.T) {
		t.Parallel()
		f := newRevFixture(t, 0, 2)
		f.ocsps[0].set(http.StatusInternalServerError, nil)
		f.ocsps[1].set(http.StatusOK, []byte("garbage"))

		revoked, detail, err := f.isRevoked()
		assert.False(t, revoked)
		assert.Empty(t, detail)
		assert.ErrorContains(t, err, "OCSP "+f.ocsps[0].url())
		assert.ErrorContains(t, err, "unexpected status 500")
		assert.ErrorContains(t, err, "OCSP "+f.ocsps[1].url())
		assert.ErrorContains(t, err, "failed to parse OCSP response")
	})
}

func TestIsRevokedCRLTakesPrecedenceOverOCSP(t *testing.T) {
	t.Parallel()

	t.Run("CRLVerdictIsUsed", func(t *testing.T) {
		t.Parallel()
		f := newRevFixture(t, 1, 1)
		f.serveCRL(t, 0, revCRL{entries: []x509.RevocationListEntry{revEntry(revLeafSerial)}})
		f.serveOCSP(t, 0, ocsp.Good, revLeafSerial)

		revoked, detail, err := f.isRevoked()
		assert.NoError(t, err)
		assert.True(t, revoked)
		assert.Equal(t, revCRLRevokedDetail, detail)
		assert.EqualValues(t, 0, f.ocsps[0].hits.Load())
	})
	t.Run("NoFallbackToOCSPWhenCRLFails", func(t *testing.T) {
		t.Parallel()
		f := newRevFixture(t, 1, 1)
		f.crls[0].set(http.StatusInternalServerError, nil)
		f.serveOCSP(t, 0, ocsp.Revoked, revLeafSerial)

		revoked, detail, err := f.isRevoked()
		assert.ErrorContains(t, err, "unexpected status 500")
		assert.False(t, revoked)
		assert.Empty(t, detail)
		assert.EqualValues(t, 0, f.ocsps[0].hits.Load())
	})
}

func TestOCSPRequest(t *testing.T) {
	t.Parallel()
	f := newRevFixture(t, 0, 1)
	f.serveOCSP(t, 0, ocsp.Good, revLeafSerial)

	_, _, err := f.isRevoked()
	assert.NoError(t, err)

	method, contentType, body := f.ocsps[0].lastRequest()
	assert.Equal(t, http.MethodPost, method)
	assert.Equal(t, "application/ocsp-request", contentType)
	req, err := ocsp.ParseRequest(body)
	if assert.NoError(t, err) {
		assert.Zero(t, req.SerialNumber.Cmp(f.leaf.SerialNumber))
	}
}

func TestCRLRequest(t *testing.T) {
	t.Parallel()
	f := newRevFixture(t, 1, 0)
	f.serveCRL(t, 0, revCRL{})

	_, _, err := f.isRevoked()
	assert.NoError(t, err)

	method, contentType, body := f.crls[0].lastRequest()
	assert.Equal(t, http.MethodGet, method)
	assert.Empty(t, contentType)
	assert.Empty(t, body)
}

func TestCRLCache(t *testing.T) {
	t.Parallel()

	t.Run("ServedFromCache", func(t *testing.T) {
		t.Parallel()
		f := newRevFixture(t, 1, 0)
		f.serveCRL(t, 0, revCRL{entries: []x509.RevocationListEntry{revEntry(revLeafSerial)}})

		for i := 0; i < 3; i++ {
			revoked, detail, err := f.isRevoked()
			assert.NoError(t, err)
			assert.True(t, revoked)
			assert.Equal(t, revCRLRevokedDetail, detail)
		}
		assert.EqualValues(t, 1, f.crls[0].hits.Load())
	})
	t.Run("ExpiredEntryIsRefetched", func(t *testing.T) {
		t.Parallel()
		f := newRevFixture(t, 1, 0)
		f.serveCRL(t, 0, revCRL{})

		_, _, err := f.isRevoked()
		assert.NoError(t, err)
		f.expireCaches()
		_, _, err = f.isRevoked()
		assert.NoError(t, err)
		assert.EqualValues(t, 2, f.crls[0].hits.Load())
	})
	t.Run("NewRevocationIsPickedUpAfterExpiry", func(t *testing.T) {
		t.Parallel()
		f := newRevFixture(t, 1, 0)
		f.serveCRL(t, 0, revCRL{})
		revoked, _, err := f.isRevoked()
		assert.NoError(t, err)
		assert.False(t, revoked)

		// until the cache entry expires the old verdict stands
		f.serveCRL(t, 0, revCRL{entries: []x509.RevocationListEntry{revEntry(revLeafSerial)}})
		revoked, _, err = f.isRevoked()
		assert.NoError(t, err)
		assert.False(t, revoked)

		f.expireCaches()
		revoked, detail, err := f.isRevoked()
		assert.NoError(t, err)
		assert.True(t, revoked)
		assert.Equal(t, revCRLRevokedDetail, detail)
	})
	t.Run("FailuresAreNotCached", func(t *testing.T) {
		t.Parallel()
		f := newRevFixture(t, 1, 0)
		f.crls[0].set(http.StatusInternalServerError, nil)

		_, _, err := f.isRevoked()
		assert.Error(t, err)
		assert.Empty(t, f.checker.crlCache)

		f.serveCRL(t, 0, revCRL{})
		_, _, err = f.isRevoked()
		assert.NoError(t, err)
		_, _, err = f.isRevoked()
		assert.NoError(t, err)
		assert.EqualValues(t, 2, f.crls[0].hits.Load())
	})
	t.Run("ExpiryFollowsNextUpdate", func(t *testing.T) {
		t.Parallel()
		f := newRevFixture(t, 1, 0)
		nextUpdate := time.Now().Add(10 * time.Minute)
		f.serveCRL(t, 0, revCRL{nextUpdate: nextUpdate})

		_, _, err := f.isRevoked()
		assert.NoError(t, err)
		if entry, ok := f.checker.crlCache[f.crls[0].url()]; assert.True(t, ok) {
			// CRL timestamps have a resolution of one second
			assert.WithinDuration(t, nextUpdate, entry.expires, 2*time.Second)
		}
	})
	t.Run("ExpiryIsCappedAtOneHour", func(t *testing.T) {
		t.Parallel()
		f := newRevFixture(t, 1, 0)
		f.serveCRL(t, 0, revCRL{nextUpdate: time.Now().Add(24 * time.Hour)})

		_, _, err := f.isRevoked()
		assert.NoError(t, err)
		if entry, ok := f.checker.crlCache[f.crls[0].url()]; assert.True(t, ok) {
			assert.WithinDuration(t, time.Now().Add(revocationCacheTTL), entry.expires, time.Minute)
		}
	})
}

func TestOCSPCache(t *testing.T) {
	t.Parallel()

	t.Run("ServedFromCache", func(t *testing.T) {
		t.Parallel()
		f := newRevFixture(t, 0, 1)
		f.serveOCSP(t, 0, ocsp.Good, revLeafSerial)

		for i := 0; i < 3; i++ {
			revoked, _, err := f.isRevoked()
			assert.NoError(t, err)
			assert.False(t, revoked)
		}
		assert.EqualValues(t, 1, f.ocsps[0].hits.Load())
	})
	t.Run("RevokedVerdictIsCached", func(t *testing.T) {
		t.Parallel()
		f := newRevFixture(t, 0, 1)
		f.serveOCSP(t, 0, ocsp.Revoked, revLeafSerial)

		for i := 0; i < 3; i++ {
			revoked, detail, err := f.isRevoked()
			assert.NoError(t, err)
			assert.True(t, revoked)
			assert.Equal(t, revOCSPRevokedDetail, detail)
		}
		assert.EqualValues(t, 1, f.ocsps[0].hits.Load())
	})
	t.Run("ExpiredEntryIsRefetched", func(t *testing.T) {
		t.Parallel()
		f := newRevFixture(t, 0, 1)
		f.serveOCSP(t, 0, ocsp.Good, revLeafSerial)

		revoked, _, err := f.isRevoked()
		assert.NoError(t, err)
		assert.False(t, revoked)

		f.serveOCSP(t, 0, ocsp.Revoked, revLeafSerial)
		f.expireCaches()
		revoked, detail, err := f.isRevoked()
		assert.NoError(t, err)
		assert.True(t, revoked)
		assert.Equal(t, revOCSPRevokedDetail, detail)
		assert.EqualValues(t, 2, f.ocsps[0].hits.Load())
	})
	t.Run("FailuresAreNotCached", func(t *testing.T) {
		t.Parallel()
		f := newRevFixture(t, 0, 1)

		f.ocsps[0].set(http.StatusInternalServerError, nil)
		_, _, err := f.isRevoked()
		assert.Error(t, err)

		// an "unknown" answer is an error too, and must not stick
		f.serveOCSP(t, 0, ocsp.Unknown, revLeafSerial)
		_, _, err = f.isRevoked()
		assert.Error(t, err)
		assert.Empty(t, f.checker.ocspCache)

		f.serveOCSP(t, 0, ocsp.Good, revLeafSerial)
		revoked, _, err := f.isRevoked()
		assert.NoError(t, err)
		assert.False(t, revoked)
		_, _, err = f.isRevoked()
		assert.NoError(t, err)
		assert.EqualValues(t, 3, f.ocsps[0].hits.Load())
	})
}

func TestIsRevokedContextCanceled(t *testing.T) {
	t.Parallel()

	t.Run("CRL", func(t *testing.T) {
		t.Parallel()
		f := newRevFixture(t, 1, 0)
		f.serveCRL(t, 0, revCRL{})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		revoked, detail, err := f.checker.IsRevoked(ctx, f.leaf, f.ca)
		assert.ErrorIs(t, err, context.Canceled)
		assert.False(t, revoked)
		assert.Empty(t, detail)
	})
	t.Run("OCSP", func(t *testing.T) {
		t.Parallel()
		f := newRevFixture(t, 0, 1)
		f.serveOCSP(t, 0, ocsp.Good, revLeafSerial)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		revoked, detail, err := f.checker.IsRevoked(ctx, f.leaf, f.ca)
		assert.ErrorIs(t, err, context.Canceled)
		assert.False(t, revoked)
		assert.Empty(t, detail)
	})
}

func TestIsRevokedConcurrently(t *testing.T) {
	t.Parallel()

	for _, kind := range []string{"CRL", "OCSP"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			var f *revFixture
			expectedDetail := revCRLRevokedDetail
			if kind == "CRL" {
				f = newRevFixture(t, 1, 0)
				f.serveCRL(t, 0, revCRL{entries: []x509.RevocationListEntry{revEntry(revLeafSerial)}})
			} else {
				f = newRevFixture(t, 0, 1)
				f.serveOCSP(t, 0, ocsp.Revoked, revLeafSerial)
				expectedDetail = revOCSPRevokedDetail
			}

			const workers = 8
			var wg sync.WaitGroup
			revoked := make([]bool, workers)
			details := make([]string, workers)
			errs := make([]error, workers)
			for i := 0; i < workers; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					revoked[i], details[i], errs[i] = f.isRevoked()
				}()
			}
			wg.Wait()

			for i := 0; i < workers; i++ {
				assert.NoError(t, errs[i])
				assert.True(t, revoked[i])
				assert.Equal(t, expectedDetail, details[i])
			}
		})
	}
}
