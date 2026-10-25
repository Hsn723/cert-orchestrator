package health

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/ctutil"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
)

const (
	ctRequestTimeout = 30 * time.Second
	ctLogListRefresh = 24 * time.Hour
	ctLogListRetry   = 10 * time.Minute
	minSCTOperators  = 2
)

// CTResult is the outcome of a Certificate Transparency check.
type CTResult struct {
	// Problem is non-empty if the certificate definitively fails the policy.
	Problem string
	// Warnings lists inconclusive findings, such as an unreachable log.
	Warnings []string
}

// CTChecker verifies that a certificate satisfies Certificate Transparency requirements.
// The chain is passed as PEM so that implementations are free to use their own X.509 types.
type CTChecker interface {
	Check(ctx context.Context, chainPEM []byte) (CTResult, error)
}

var _ CTChecker = (*LogListCTChecker)(nil)

type sctOutcome int

const (
	// sctValid: valid signature and proven to be included in the log.
	sctValid sctOutcome = iota
	// sctPending: valid signature, not included yet but still within the log's maximum merge delay.
	sctPending
	// sctUnverifiable: valid or unknown signature, but the check could not be completed. Counts, with a warning.
	sctUnverifiable
	// sctInvalid: definitively bad. Does not count.
	sctInvalid
)

// LogListCTChecker verifies the SCTs embedded in a certificate against the public CT log list, the way
// browsers do. For every SCT it verifies the log's signature offline, and then asks the log for an
// inclusion proof. Successful inclusion proofs are cached forever since they cannot become invalid,
// so steady-state evaluations make no network requests to CT logs.
//
// Only RFC 6962 logs are supported. SCTs from other kinds of logs are reported as unknown.
type LogListCTChecker struct {
	client  *http.Client
	listURL string

	mu       sync.Mutex
	list     *loglist3.LogList
	listAt   time.Time
	infos    map[[sha256.Size]byte]*ctutil.LogInfo
	included map[string]struct{}
}

// NewLogListCTChecker returns a LogListCTChecker that uses the list of all known CT logs.
func NewLogListCTChecker() *LogListCTChecker {
	return &LogListCTChecker{
		client:   &http.Client{Timeout: ctRequestTimeout},
		listURL:  loglist3.AllLogListURL,
		infos:    make(map[[sha256.Size]byte]*ctutil.LogInfo),
		included: make(map[string]struct{}),
	}
}

// Check implements CTChecker.
func (c *LogListCTChecker) Check(ctx context.Context, chainPEM []byte) (CTResult, error) {
	chain, err := x509util.CertificatesFromPEM(chainPEM)
	if err != nil {
		return CTResult{}, fmt.Errorf("failed to parse certificate chain: %w", err)
	}
	if len(chain) == 0 {
		return CTResult{}, errors.New("no certificate found")
	}
	leaf := chain[0]
	if len(leaf.SCTList.SCTList) == 0 {
		return CTResult{Problem: "certificate has no embedded SCTs"}, nil
	}
	if len(chain) < 2 {
		return CTResult{}, errors.New("issuer certificate not present in tls.crt, cannot reconstruct the precertificate")
	}

	list, err := c.logList()
	if err != nil {
		return CTResult{}, err
	}
	merkleLeaf, err := ct.MerkleTreeLeafForEmbeddedSCT([]*x509.Certificate{leaf, chain[1]}, 0)
	if err != nil {
		return CTResult{}, fmt.Errorf("failed to build Merkle tree leaf: %w", err)
	}

	var res CTResult
	var failures []string
	operators := map[string]struct{}{}
	for i := range leaf.SCTList.SCTList {
		sct, err := x509util.ExtractSCT(&leaf.SCTList.SCTList[i])
		if err != nil {
			failures = append(failures, fmt.Sprintf("SCT[%d]: failed to deserialize: %v", i, err))
			continue
		}
		outcome, operator, detail := c.checkSCT(ctx, list, leaf, merkleLeaf, sct)
		switch outcome {
		case sctValid, sctPending:
			operators[operator] = struct{}{}
		case sctUnverifiable:
			operators[operator] = struct{}{}
			res.Warnings = append(res.Warnings, fmt.Sprintf("SCT[%d]: %s", i, detail))
		case sctInvalid:
			failures = append(failures, fmt.Sprintf("SCT[%d]: %s", i, detail))
		}
	}

	if len(operators) >= minSCTOperators {
		res.Warnings = append(res.Warnings, failures...)
		return res, nil
	}
	res.Problem = fmt.Sprintf("SCTs from %d distinct log operator(s), at least %d required", len(operators), minSCTOperators)
	if len(failures) > 0 {
		res.Problem += ": " + strings.Join(failures, "; ")
	}
	return res, nil
}

// logList returns the cached log list, refreshing it daily. A stale list is kept if a refresh fails.
// The lock is held during the fetch, which is acceptable at this call rate.
func (c *LogListCTChecker) logList() (*loglist3.LogList, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.list != nil && time.Since(c.listAt) < ctLogListRefresh {
		return c.list, nil
	}

	data, err := x509util.ReadFileOrURL(c.listURL, c.client)
	var list *loglist3.LogList
	if err == nil {
		list, err = loglist3.NewFromJSON(data)
	}
	if err != nil {
		if c.list != nil {
			c.listAt = time.Now().Add(-ctLogListRefresh + ctLogListRetry)
			return c.list, nil
		}
		return nil, fmt.Errorf("failed to load CT log list: %w", err)
	}
	c.list = list
	c.listAt = time.Now()
	c.infos = make(map[[sha256.Size]byte]*ctutil.LogInfo)
	return list, nil
}

func (c *LogListCTChecker) checkSCT(ctx context.Context, list *loglist3.LogList, leaf *x509.Certificate, merkleLeaf *ct.MerkleTreeLeaf, sct *ct.SignedCertificateTimestamp) (sctOutcome, string, string) {
	keyID := sct.LogID.KeyID
	log := list.FindLogByKeyHash(keyID)
	if log == nil {
		return sctInvalid, "", fmt.Sprintf("unknown log %x", keyID)
	}
	operator := operatorOf(list, keyID)

	info, err := c.logInfo(keyID, log)
	if err != nil {
		return sctUnverifiable, operator, fmt.Sprintf("log %q: %v", log.Description, err)
	}
	if err := info.VerifySCTSignature(*sct, *merkleLeaf); err != nil {
		return sctInvalid, operator, fmt.Sprintf("invalid signature from log %q: %v", log.Description, err)
	}

	cacheKey := fmt.Sprintf("%x/%x", sha256.Sum256(leaf.Raw), keyID)
	if c.isIncluded(cacheKey) {
		return sctValid, operator, ""
	}
	if _, err := info.VerifyInclusion(ctx, *merkleLeaf, sct.Timestamp); err != nil {
		switch age := time.Since(ct.TimestampToTime(sct.Timestamp)); {
		case age < info.MMD:
			return sctPending, operator, ""
		case isDefinitiveInclusionFailure(err):
			return sctInvalid, operator, fmt.Sprintf("not included in log %q: %v", log.Description, err)
		default:
			return sctUnverifiable, operator, fmt.Sprintf("inclusion check against log %q inconclusive: %v", log.Description, err)
		}
	}
	c.markIncluded(cacheKey)
	return sctValid, operator, ""
}

func operatorOf(list *loglist3.LogList, keyID [sha256.Size]byte) string {
	for _, op := range list.Operators {
		for _, l := range op.Logs {
			if bytes.Equal(l.LogID, keyID[:]) {
				return op.Name
			}
		}
	}
	return fmt.Sprintf("log-%x", keyID)
}

func (c *LogListCTChecker) logInfo(keyID [sha256.Size]byte, log *loglist3.Log) (*ctutil.LogInfo, error) {
	c.mu.Lock()
	info, ok := c.infos[keyID]
	c.mu.Unlock()
	if ok {
		return info, nil
	}
	info, err := ctutil.NewLogInfo(log, c.client)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.infos[keyID] = info
	c.mu.Unlock()
	return info, nil
}

func (c *LogListCTChecker) isIncluded(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.included[key]
	return ok
}

func (c *LogListCTChecker) markIncluded(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.included[key] = struct{}{}
}

// isDefinitiveInclusionFailure reports whether the log positively answered that it does not contain the
// leaf, as opposed to being unreachable or erroring. LogInfo.VerifyInclusion flattens its errors into
// strings, so this can only be a heuristic.
func isDefinitiveInclusionFailure(err error) bool {
	msg := strings.ToLower(err.Error())
	for _, marker := range []string{"404", "not found", "no such", "verify inclusion proof"} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}
