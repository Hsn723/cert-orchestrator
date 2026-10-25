package health

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

const (
	revocationFetchTimeout = 30 * time.Second
	revocationCacheTTL     = time.Hour
	maxOCSPResponseBytes   = 1 << 20  // 1 MB
	maxCRLBytes            = 64 << 20 // 64 MB
)

// ErrNoRevocationInfo is returned when a certificate advertises neither CRL nor OCSP endpoints.
var ErrNoRevocationInfo = errors.New("certificate has no CRL or OCSP information")

// RevocationChecker determines whether a certificate has been revoked.
type RevocationChecker interface {
	IsRevoked(ctx context.Context, leaf, issuer *x509.Certificate) (revoked bool, detail string, err error)
}

type verdict struct {
	revoked bool
	detail  string
	expires time.Time
}

type revokedEntry struct {
	at     time.Time
	reason int
}

type crlEntry struct {
	revoked map[string]revokedEntry
	expires time.Time
}

// NetworkRevocationChecker checks CRLs, and falls back to OCSP only for certificates that have no CRL distribution points.
// Results are cached in memory until the response's nextUpdate (capped at one hour).
type NetworkRevocationChecker struct {
	client    *http.Client
	mu        sync.Mutex
	ocspCache map[string]verdict
	crlCache  map[string]crlEntry
}

// NewNetworkRevocationChecker returns a NetworkRevocationChecker.
func NewNetworkRevocationChecker() *NetworkRevocationChecker {
	return &NetworkRevocationChecker{
		client:    &http.Client{Timeout: revocationFetchTimeout},
		ocspCache: make(map[string]verdict),
		crlCache:  make(map[string]crlEntry),
	}
}

// IsRevoked implements RevocationChecker.
func (c *NetworkRevocationChecker) IsRevoked(ctx context.Context, leaf, issuer *x509.Certificate) (bool, string, error) {
	switch {
	case len(leaf.CRLDistributionPoints) > 0:
		return c.isRevokedByCRL(ctx, leaf, issuer)
	case len(leaf.OCSPServer) > 0:
		return c.isRevokedByOCSP(ctx, leaf, issuer)
	default:
		return false, "", ErrNoRevocationInfo
	}
}

func (c *NetworkRevocationChecker) isRevokedByCRL(ctx context.Context, leaf, issuer *x509.Certificate) (bool, string, error) {
	var errs []error
	for _, u := range leaf.CRLDistributionPoints {
		v, err := c.checkCRL(ctx, u, leaf, issuer)
		if err != nil {
			errs = append(errs, fmt.Errorf("CRL %s: %w", u, err))
			continue
		}
		return v.revoked, v.detail, nil
	}
	return false, "", errors.Join(errs...)
}

func (c *NetworkRevocationChecker) isRevokedByOCSP(ctx context.Context, leaf, issuer *x509.Certificate) (bool, string, error) {
	var errs []error
	for _, server := range leaf.OCSPServer {
		v, err := c.checkOCSP(ctx, server, leaf, issuer)
		if err != nil {
			errs = append(errs, fmt.Errorf("OCSP %s: %w", server, err))
			continue
		}
		return v.revoked, v.detail, nil
	}
	return false, "", errors.Join(errs...)
}

func (c *NetworkRevocationChecker) checkCRL(ctx context.Context, rawURL string, leaf, issuer *x509.Certificate) (verdict, error) {
	now := time.Now()

	c.mu.Lock()
	entry, ok := c.crlCache[rawURL]
	c.mu.Unlock()
	if !ok || !now.Before(entry.expires) {
		var err error
		entry, err = c.fetchCRL(ctx, rawURL, issuer, now)
		if err != nil {
			return verdict{}, err
		}
		c.mu.Lock()
		c.crlCache[rawURL] = entry
		c.mu.Unlock()
	}

	if rev, ok := entry.revoked[leaf.SerialNumber.String()]; ok {
		return verdict{
			revoked: true,
			detail: fmt.Sprintf("revoked at %s according to CRL (reason code %d)",
				rev.at.UTC().Format(time.RFC3339), rev.reason),
		}, nil
	}
	return verdict{}, nil
}

func (c *NetworkRevocationChecker) fetchCRL(ctx context.Context, rawURL string, issuer *x509.Certificate, now time.Time) (crlEntry, error) {
	body, err := c.fetch(ctx, http.MethodGet, rawURL, "", nil, maxCRLBytes)
	if err != nil {
		return crlEntry{}, err
	}
	if block, _ := pem.Decode(body); block != nil {
		body = block.Bytes
	}
	list, err := x509.ParseRevocationList(body)
	if err != nil {
		return crlEntry{}, fmt.Errorf("failed to parse CRL: %w", err)
	}
	if err := list.CheckSignatureFrom(issuer); err != nil {
		return crlEntry{}, fmt.Errorf("failed to verify CRL signature: %w", err)
	}
	if !list.NextUpdate.IsZero() && !now.Before(list.NextUpdate) {
		return crlEntry{}, errors.New("stale CRL")
	}

	entry := crlEntry{
		revoked: make(map[string]revokedEntry, len(list.RevokedCertificateEntries)),
		expires: cacheExpiry(now, list.NextUpdate),
	}
	for _, r := range list.RevokedCertificateEntries {
		entry.revoked[r.SerialNumber.String()] = revokedEntry{at: r.RevocationTime, reason: r.ReasonCode}
	}
	return entry, nil
}

func (c *NetworkRevocationChecker) fetch(ctx context.Context, method, rawURL, contentType string, payload []byte, limit int64) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("unsupported URL %q", rawURL)
	}
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response exceeds %d bytes", limit)
	}
	return data, nil
}

func (c *NetworkRevocationChecker) checkOCSP(ctx context.Context, server string, leaf, issuer *x509.Certificate) (verdict, error) {
	now := time.Now()
	key := server + "|" + leaf.SerialNumber.Text(16)

	c.mu.Lock()
	v, ok := c.ocspCache[key]
	c.mu.Unlock()
	if ok && now.Before(v.expires) {
		return v, nil
	}

	reqBytes, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		return verdict{}, err
	}
	body, err := c.fetch(ctx, http.MethodPost, server, "application/ocsp-request", reqBytes, maxOCSPResponseBytes)
	if err != nil {
		return verdict{}, err
	}
	resp, err := ocsp.ParseResponseForCert(body, leaf, issuer)
	if err != nil {
		return verdict{}, fmt.Errorf("failed to parse OCSP response: %w", err)
	}
	if !resp.NextUpdate.IsZero() && !now.Before(resp.NextUpdate) {
		return verdict{}, errors.New("stale OCSP response")
	}

	v = verdict{expires: cacheExpiry(now, resp.NextUpdate)}
	switch resp.Status {
	case ocsp.Good:
	case ocsp.Revoked:
		v.revoked = true
		v.detail = fmt.Sprintf("revoked at %s according to OCSP (reason code %d)",
			resp.RevokedAt.UTC().Format(time.RFC3339), resp.RevocationReason)
	default:
		return verdict{}, errors.New("OCSP responder does not know this certificate")
	}

	c.mu.Lock()
	c.ocspCache[key] = v
	c.mu.Unlock()
	return v, nil
}

func cacheExpiry(now, nextUpdate time.Time) time.Time {
	expires := now.Add(revocationCacheTTL)
	if !nextUpdate.IsZero() && nextUpdate.Before(expires) {
		return nextUpdate
	}
	return expires
}
