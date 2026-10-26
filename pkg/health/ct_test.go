package health

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/hsn723/cert-orchestrator/internal/healthtest"
	"github.com/stretchr/testify/assert"
)

const (
	ctTestMMDSeconds = 24 * 60 * 60
	ctTestOldSCT     = 48 * time.Hour
	ctTestRecentSCT  = time.Minute
)

var (
	// oidSCTList is the OID of the embedded SCT list extension (RFC 6962, section 3.3).
	oidSCTList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
)

func ctSign(key *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	digest := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, key, digest[:])
}

func ctDigitallySigned(sig []byte) ct.DigitallySigned {
	return ct.DigitallySigned{
		Algorithm: tls.SignatureAndHashAlgorithm{Hash: tls.SHA256, Signature: tls.ECDSA},
		Signature: sig,
	}
}

// ctLogMode controls how a fake CT log answers.
type ctLogMode int32

const (
	// ctLogIncluded serves a valid signed tree head and an inclusion proof for the registered leaf.
	ctLogIncluded ctLogMode = iota
	// ctLogNotFound serves a valid signed tree head, but answers 404 to get-proof-by-hash.
	ctLogNotFound
	// ctLogDown answers 500 to everything.
	ctLogDown
)

// ctTestLog is a fake RFC 6962 CT log. Its tree always holds exactly one leaf, so the root hash is the
// leaf hash and the audit path is empty.
type ctTestLog struct {
	description string
	operator    string
	key         *ecdsa.PrivateKey
	keyDER      []byte
	id          [sha256.Size]byte
	server      *httptest.Server

	mode       atomic.Int32
	sthCalls   atomic.Int64
	proofCalls atomic.Int64

	mu       sync.Mutex
	leafHash [sha256.Size]byte
}

func newCTTestLog(t *testing.T, description, operator string, mode ctLogMode) *ctTestLog {
	t.Helper()
	key := healthtest.NewKey(t)
	keyDER, err := stdx509.MarshalPKIXPublicKey(&key.PublicKey)
	healthtest.Must(t, err)

	l := &ctTestLog{
		description: description,
		operator:    operator,
		key:         key,
		keyDER:      keyDER,
		id:          sha256.Sum256(keyDER),
	}
	l.mode.Store(int32(mode))

	mux := http.NewServeMux()
	mux.HandleFunc("/ct/v1/get-sth", l.handleSTH)
	mux.HandleFunc("/ct/v1/get-proof-by-hash", l.handleProof)
	l.server = httptest.NewTLSServer(mux)
	t.Cleanup(l.server.Close)
	return l
}

func (l *ctTestLog) setMode(mode ctLogMode) {
	l.mode.Store(int32(mode))
}

func (l *ctTestLog) expectLeaf(hash [sha256.Size]byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.leafHash = hash
}

func (l *ctTestLog) currentLeaf() [sha256.Size]byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.leafHash
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (l *ctTestLog) handleSTH(w http.ResponseWriter, _ *http.Request) {
	l.sthCalls.Add(1)
	if ctLogMode(l.mode.Load()) == ctLogDown {
		http.Error(w, "down", http.StatusInternalServerError)
		return
	}

	root := l.currentLeaf()
	sth := ct.SignedTreeHead{
		Version:        ct.V1,
		TreeSize:       1,
		Timestamp:      uint64(time.Now().UnixMilli()),
		SHA256RootHash: ct.SHA256Hash(root),
	}
	input, err := ct.SerializeSTHSignatureInput(sth)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sig, err := ctSign(l.key, input)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	signature, err := tls.Marshal(tls.DigitallySigned(ctDigitallySigned(sig)))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{
		"tree_size":           sth.TreeSize,
		"timestamp":           sth.Timestamp,
		"sha256_root_hash":    base64.StdEncoding.EncodeToString(root[:]),
		"tree_head_signature": base64.StdEncoding.EncodeToString(signature),
	})
}

func (l *ctTestLog) handleProof(w http.ResponseWriter, r *http.Request) {
	l.proofCalls.Add(1)
	switch ctLogMode(l.mode.Load()) {
	case ctLogDown:
		http.Error(w, "down", http.StatusInternalServerError)
	case ctLogNotFound:
		http.Error(w, "unknown hash", http.StatusNotFound)
	default:
		leaf := l.currentLeaf()
		if r.URL.Query().Get("hash") != base64.StdEncoding.EncodeToString(leaf[:]) {
			http.Error(w, "unknown hash", http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]any{"leaf_index": 0, "audit_path": []string{}})
	}
}

// ctTestHTTPClient returns an HTTP client that trusts the certificate of httptest TLS servers.
func ctTestHTTPClient(t *testing.T) *http.Client {
	t.Helper()
	s := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(s.Close)
	client := s.Client()
	client.Timeout = 10 * time.Second
	return client
}

// ctIssuer is a CA that issues leaf certificates with embedded SCTs.
type ctIssuer struct {
	ca     *healthtest.CA
	ctCert *ctx509.Certificate
}

func parseCTCert(t *testing.T, der []byte) *ctx509.Certificate {
	t.Helper()
	cert, err := ctx509.ParseCertificate(der)
	if err != nil && ctx509.IsFatal(err) {
		t.Fatal(err)
	}
	return cert
}

func newCTIssuer(t *testing.T) *ctIssuer {
	t.Helper()
	ca := healthtest.NewCA(t, healthtest.CASpec{})
	return &ctIssuer{ca: ca, ctCert: parseCTCert(t, ca.DER)}
}

func sctListExtension(t *testing.T, scts [][]byte) pkix.Extension {
	t.Helper()
	list := ctx509.SignedCertificateTimestampList{}
	for _, sct := range scts {
		list.SCTList = append(list.SCTList, ctx509.SerializedSCT{Val: sct})
	}
	serialized, err := tls.Marshal(list)
	healthtest.Must(t, err)
	// the extension value is an OCTET STRING holding the TLS-encoded list
	value, err := asn1.Marshal(serialized)
	healthtest.Must(t, err)
	return pkix.Extension{Id: oidSCTList, Value: value}
}

type ctSCTSpec struct {
	log *ctTestLog
	age time.Duration
	// signer overrides the key the SCT is signed with. Defaults to the log's own key.
	signer *ecdsa.PrivateKey
}

// issue creates a leaf certificate with one embedded SCT per spec, and returns the PEM encoded chain.
//
// The SCT signatures cover the certificate without the SCT extension, so the certificate is created
// twice: first with a placeholder SCT list, to compute what the logs would have signed, then with the
// real list. Everything but the SCT extension is identical between the two.
func (i *ctIssuer) issue(t *testing.T, scts []ctSCTSpec, leafOnly bool) []byte {
	t.Helper()
	spec := healthtest.CertSpec{
		Key:       healthtest.NewKey(t),
		NotBefore: time.Now().Add(-time.Hour).Truncate(time.Second),
		NotAfter:  time.Now().Add(24 * time.Hour).Truncate(time.Second),
	}
	create := func(extensions ...pkix.Extension) *healthtest.Cert {
		s := spec
		s.ExtraExtensions = extensions
		return i.ca.Issue(t, s)
	}

	var leaf *healthtest.Cert
	if len(scts) == 0 {
		leaf = create()
	} else {
		placeholder := ct.SignedCertificateTimestamp{
			SCTVersion: ct.V1,
			Signature:  ctDigitallySigned([]byte{0}),
		}
		placeholderRaw, err := tls.Marshal(placeholder)
		healthtest.Must(t, err)
		precert := parseCTCert(t, create(sctListExtension(t, [][]byte{placeholderRaw})).DER)

		raws := make([][]byte, 0, len(scts))
		for _, sctSpec := range scts {
			timestamp := uint64(time.Now().Add(-sctSpec.age).UnixMilli())
			merkleLeaf, err := ct.MerkleTreeLeafForEmbeddedSCT([]*ctx509.Certificate{precert, i.ctCert}, timestamp)
			healthtest.Must(t, err)

			sct := ct.SignedCertificateTimestamp{
				SCTVersion: ct.V1,
				LogID:      ct.LogID{KeyID: sctSpec.log.id},
				Timestamp:  timestamp,
			}
			input, err := ct.SerializeSCTSignatureInput(sct, ct.LogEntry{Leaf: *merkleLeaf})
			healthtest.Must(t, err)
			signer := sctSpec.signer
			if signer == nil {
				signer = sctSpec.log.key
			}
			sig, err := ctSign(signer, input)
			healthtest.Must(t, err)
			sct.Signature = ctDigitallySigned(sig)
			raw, err := tls.Marshal(sct)
			healthtest.Must(t, err)
			raws = append(raws, raw)

			leafHash, err := ct.LeafHashForLeaf(merkleLeaf)
			healthtest.Must(t, err)
			sctSpec.log.expectLeaf(leafHash)
		}
		leaf = create(sctListExtension(t, raws))
	}

	if leafOnly {
		return leaf.PEM
	}
	return healthtest.ConcatPEM(leaf.PEM, i.ca.PEM)
}

type ctListedLog struct {
	log *ctTestLog
	// key overrides the public key in the log list. Defaults to the log's real key.
	key []byte
}

type ctListedOperator struct {
	name string
	logs []ctListedLog
}

func ctLogListJSON(t *testing.T, operators []ctListedOperator) []byte {
	t.Helper()
	type jsonLog struct {
		Description string         `json:"description"`
		LogID       string         `json:"log_id"`
		Key         string         `json:"key"`
		URL         string         `json:"url"`
		MMD         int            `json:"mmd"`
		State       map[string]any `json:"state"`
	}
	type jsonOperator struct {
		Name  string    `json:"name"`
		Email []string  `json:"email"`
		Logs  []jsonLog `json:"logs"`
	}
	list := struct {
		Version          string         `json:"version"`
		LogListTimestamp string         `json:"log_list_timestamp"`
		Operators        []jsonOperator `json:"operators"`
	}{
		Version:          "1.0",
		LogListTimestamp: "2026-01-01T00:00:00Z",
		Operators:        []jsonOperator{},
	}
	for _, op := range operators {
		jsonOp := jsonOperator{Name: op.name, Email: []string{"ct@example.com"}, Logs: []jsonLog{}}
		for _, listed := range op.logs {
			key := listed.key
			if key == nil {
				key = listed.log.keyDER
			}
			jsonOp.Logs = append(jsonOp.Logs, jsonLog{
				Description: listed.log.description,
				LogID:       base64.StdEncoding.EncodeToString(listed.log.id[:]),
				Key:         base64.StdEncoding.EncodeToString(key),
				URL:         listed.log.server.URL,
				MMD:         ctTestMMDSeconds,
				State:       map[string]any{"usable": map[string]any{"timestamp": "2024-01-01T00:00:00Z"}},
			})
		}
		list.Operators = append(list.Operators, jsonOp)
	}
	data, err := json.Marshal(list)
	healthtest.Must(t, err)
	return data
}

// ctListServer serves the log list.
type ctListServer struct {
	server *httptest.Server
	hits   atomic.Int64

	mu     sync.Mutex
	body   []byte
	broken bool
}

func newCTListServer(t *testing.T, body []byte) *ctListServer {
	t.Helper()
	s := &ctListServer{body: body}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.hits.Add(1)
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.broken {
			http.Error(w, "broken", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(s.body)
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *ctListServer) set(body []byte, broken bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body = body
	s.broken = broken
}

type ctLogSpec struct {
	operator string
	mode     ctLogMode
	// unlisted logs are missing from the log list.
	unlisted bool
	// badKey logs are listed with a public key that cannot be parsed.
	badKey bool
}

type ctSCTRef struct {
	log         int
	age         time.Duration
	wrongSigner bool
}

type ctFixtureSpec struct {
	logs       []ctLogSpec
	scts       []ctSCTRef
	leafOnly   bool
	listBroken bool
}

type ctFixture struct {
	checker  *LogListCTChecker
	list     *ctListServer
	logs     []*ctTestLog
	chainPEM []byte
}

func newCTFixture(t *testing.T, spec ctFixtureSpec) *ctFixture {
	t.Helper()
	logs := make([]*ctTestLog, len(spec.logs))
	var operators []ctListedOperator
	for i, ls := range spec.logs {
		logs[i] = newCTTestLog(t, fmt.Sprintf("log-%d", i), ls.operator, ls.mode)
		if ls.unlisted {
			continue
		}
		listed := ctListedLog{log: logs[i]}
		if ls.badKey {
			listed.key = []byte("not a key")
		}
		found := false
		for j := range operators {
			if operators[j].name == ls.operator {
				operators[j].logs = append(operators[j].logs, listed)
				found = true
				break
			}
		}
		if !found {
			operators = append(operators, ctListedOperator{name: ls.operator, logs: []ctListedLog{listed}})
		}
	}
	list := newCTListServer(t, ctLogListJSON(t, operators))
	if spec.listBroken {
		list.set(nil, true)
	}

	otherKey := healthtest.NewKey(t)
	scts := make([]ctSCTSpec, 0, len(spec.scts))
	for _, ref := range spec.scts {
		sct := ctSCTSpec{log: logs[ref.log], age: ref.age}
		if ref.wrongSigner {
			sct.signer = otherKey
		}
		scts = append(scts, sct)
	}

	checker := NewLogListCTChecker()
	checker.client = ctTestHTTPClient(t)
	checker.listURL = list.server.URL
	return &ctFixture{
		checker:  checker,
		list:     list,
		logs:     logs,
		chainPEM: newCTIssuer(t).issue(t, scts, spec.leafOnly),
	}
}

func TestIsDefinitiveInclusionFailure(t *testing.T) {
	t.Parallel()
	cases := []struct {
		title    string
		err      error
		expected bool
	}{
		{
			title:    "HTTPNotFound",
			err:      errors.New(`got HTTP Status "404 Not Found"`),
			expected: true,
		},
		{
			title:    "NotFoundText",
			err:      errors.New("leaf was not found"),
			expected: true,
		},
		{
			title:    "NotFoundIsCaseInsensitive",
			err:      errors.New("NOT FOUND"),
			expected: true,
		},
		{
			title:    "NoSuchHash",
			err:      errors.New("no such hash"),
			expected: true,
		},
		{
			title:    "ProofVerificationFailed",
			err:      errors.New("failed to verify inclusion proof at size 5: root mismatch"),
			expected: true,
		},
		{
			title:    "ConnectionRefused",
			err:      errors.New("dial tcp 127.0.0.1:1: connect: connection refused"),
			expected: false,
		},
		{
			title:    "DeadlineExceeded",
			err:      context.DeadlineExceeded,
			expected: false,
		},
		{
			title:    "ServerError",
			err:      errors.New(`got HTTP Status "500 Internal Server Error"`),
			expected: false,
		},
		{
			title:    "EmptyMessage",
			err:      errors.New(""),
			expected: false,
		},
		{
			title:    "WrappedNotFound",
			err:      fmt.Errorf("lookup failed: %w", errors.New("404")),
			expected: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, isDefinitiveInclusionFailure(tc.err))
		})
	}
}

func TestOperatorOf(t *testing.T) {
	t.Parallel()

	log0 := newCTTestLog(t, "log-0", "Operator A", ctLogIncluded)
	log1 := newCTTestLog(t, "log-1", "Operator A", ctLogIncluded)
	log2 := newCTTestLog(t, "log-2", "Operator B", ctLogIncluded)
	unlisted := newCTTestLog(t, "log-3", "Operator C", ctLogIncluded)

	list, err := loglist3.NewFromJSON(ctLogListJSON(t, []ctListedOperator{
		{name: "Operator A", logs: []ctListedLog{{log: log0}, {log: log1}}},
		{name: "Operator B", logs: []ctListedLog{{log: log2}}},
	}))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		title    string
		id       [sha256.Size]byte
		expected string
	}{
		{title: "FirstLogOfFirstOperator", id: log0.id, expected: "Operator A"},
		{title: "SecondLogOfFirstOperator", id: log1.id, expected: "Operator A"},
		{title: "LogOfSecondOperator", id: log2.id, expected: "Operator B"},
		{
			title:    "UnknownLogFallsBackToLogID",
			id:       unlisted.id,
			expected: fmt.Sprintf("log-%x", unlisted.id),
		},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, operatorOf(list, tc.id))
		})
	}
}

func TestIncludedCache(t *testing.T) {
	t.Parallel()
	c := NewLogListCTChecker()

	assert.False(t, c.isIncluded("a"))
	c.markIncluded("a")
	assert.True(t, c.isIncluded("a"))
	assert.False(t, c.isIncluded("b"))
	// marking twice is harmless
	c.markIncluded("a")
	assert.True(t, c.isIncluded("a"))
}

func TestLogInfo(t *testing.T) {
	t.Parallel()

	good := newCTTestLog(t, "good", "Operator A", ctLogIncluded)
	bad := newCTTestLog(t, "bad", "Operator B", ctLogIncluded)
	list, err := loglist3.NewFromJSON(ctLogListJSON(t, []ctListedOperator{
		{name: "Operator A", logs: []ctListedLog{{log: good}}},
		{name: "Operator B", logs: []ctListedLog{{log: bad, key: []byte("not a key")}}},
	}))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("CachedPerLog", func(t *testing.T) {
		t.Parallel()
		c := NewLogListCTChecker()
		log := list.FindLogByKeyHash(good.id)
		if !assert.NotNil(t, log) {
			return
		}
		info1, err := c.logInfo(good.id, log)
		assert.NoError(t, err)
		info2, err := c.logInfo(good.id, log)
		assert.NoError(t, err)
		assert.NotNil(t, info1)
		assert.Same(t, info1, info2)
		assert.Equal(t, "good", info1.Description)
		assert.Equal(t, time.Duration(ctTestMMDSeconds)*time.Second, info1.MMD)
	})
	t.Run("InvalidKeyIsAnErrorAndNotCached", func(t *testing.T) {
		t.Parallel()
		c := NewLogListCTChecker()
		log := list.FindLogByKeyHash(bad.id)
		if !assert.NotNil(t, log) {
			return
		}
		info, err := c.logInfo(bad.id, log)
		assert.Error(t, err)
		assert.Nil(t, info)
		assert.Empty(t, c.infos)
	})
}

func TestLogList(t *testing.T) {
	t.Parallel()

	log := newCTTestLog(t, "log-0", "Operator A", ctLogIncluded)
	validList := ctLogListJSON(t, []ctListedOperator{{name: "Operator A", logs: []ctListedLog{{log: log}}}})

	newChecker := func(t *testing.T, body []byte, broken bool) (*LogListCTChecker, *ctListServer) {
		t.Helper()
		s := newCTListServer(t, body)
		s.set(body, broken)
		c := NewLogListCTChecker()
		c.listURL = s.server.URL
		return c, s
	}

	t.Run("LoadedOnceAndCached", func(t *testing.T) {
		t.Parallel()
		c, s := newChecker(t, validList, false)

		list1, err := c.logList()
		assert.NoError(t, err)
		list2, err := c.logList()
		assert.NoError(t, err)

		if assert.NotNil(t, list1) {
			assert.NotNil(t, list1.FindLogByKeyHash(log.id))
		}
		assert.Same(t, list1, list2)
		assert.EqualValues(t, 1, s.hits.Load())
	})
	t.Run("RefreshedWhenExpired", func(t *testing.T) {
		t.Parallel()
		c, s := newChecker(t, validList, false)

		list1, err := c.logList()
		assert.NoError(t, err)
		// log infos belong to a list, they must not survive a refresh
		c.infos[log.id] = nil
		c.listAt = time.Now().Add(-2 * ctLogListRefresh)

		list2, err := c.logList()
		assert.NoError(t, err)
		assert.NotSame(t, list1, list2)
		assert.EqualValues(t, 2, s.hits.Load())
		assert.Empty(t, c.infos)
		assert.WithinDuration(t, time.Now(), c.listAt, time.Minute)
	})
	t.Run("FailureWithoutCachedList", func(t *testing.T) {
		t.Parallel()
		c, s := newChecker(t, nil, true)

		list, err := c.logList()
		assert.ErrorContains(t, err, "failed to load CT log list")
		assert.Nil(t, list)
		assert.Nil(t, c.list)
		assert.EqualValues(t, 1, s.hits.Load())
	})
	t.Run("InvalidJSONWithoutCachedList", func(t *testing.T) {
		t.Parallel()
		c, _ := newChecker(t, []byte("{"), false)

		list, err := c.logList()
		assert.ErrorContains(t, err, "failed to load CT log list")
		assert.Nil(t, list)
	})
	t.Run("StaleListKeptWhenRefreshFails", func(t *testing.T) {
		t.Parallel()
		c, s := newChecker(t, validList, false)

		list1, err := c.logList()
		assert.NoError(t, err)
		s.set(nil, true)
		c.listAt = time.Now().Add(-2 * ctLogListRefresh)

		list2, err := c.logList()
		assert.NoError(t, err)
		assert.Same(t, list1, list2)
		assert.EqualValues(t, 2, s.hits.Load())

		// the next retry is scheduled ctLogListRetry from now: not refetched right away...
		list3, err := c.logList()
		assert.NoError(t, err)
		assert.Same(t, list1, list3)
		assert.EqualValues(t, 2, s.hits.Load())
		// ...but refetched once the retry delay has elapsed
		assert.WithinDuration(t, time.Now().Add(ctLogListRetry-ctLogListRefresh), c.listAt, time.Minute)
	})
	t.Run("RecoversAfterFailure", func(t *testing.T) {
		t.Parallel()
		c, s := newChecker(t, validList, false)

		_, err := c.logList()
		assert.NoError(t, err)
		s.set(nil, true)
		c.listAt = time.Now().Add(-2 * ctLogListRefresh)
		_, err = c.logList()
		assert.NoError(t, err)

		s.set(validList, false)
		c.listAt = time.Now().Add(-2 * ctLogListRefresh)
		list, err := c.logList()
		assert.NoError(t, err)
		assert.NotNil(t, list)
		assert.WithinDuration(t, time.Now(), c.listAt, time.Minute)
	})
}

func TestCheckInputErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		title       string
		fixture     *ctFixtureSpec
		chainPEM    []byte
		errContains string
	}{
		{
			title:    "EmptyInput",
			chainPEM: nil,
		},
		{
			title:    "GarbageInput",
			chainPEM: []byte("not pem"),
		},
		{
			title:       "MalformedCertificate",
			chainPEM:    healthtest.PEMBlock("CERTIFICATE", []byte("garbage")),
			errContains: "failed to parse certificate chain",
		},
		{
			title: "IssuerMissing",
			fixture: &ctFixtureSpec{
				logs:     []ctLogSpec{{operator: "A"}, {operator: "B"}},
				scts:     []ctSCTRef{{log: 0, age: ctTestOldSCT}, {log: 1, age: ctTestOldSCT}},
				leafOnly: true,
			},
			errContains: "issuer certificate not present in tls.crt",
		},
		{
			title: "LogListUnavailable",
			fixture: &ctFixtureSpec{
				logs:       []ctLogSpec{{operator: "A"}, {operator: "B"}},
				scts:       []ctSCTRef{{log: 0, age: ctTestOldSCT}, {log: 1, age: ctTestOldSCT}},
				listBroken: true,
			},
			errContains: "failed to load CT log list",
		},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			t.Parallel()
			checker := NewLogListCTChecker()
			chainPEM := tc.chainPEM
			var f *ctFixture
			if tc.fixture != nil {
				f = newCTFixture(t, *tc.fixture)
				checker = f.checker
				chainPEM = f.chainPEM
			}

			res, err := checker.Check(context.Background(), chainPEM)
			assert.Error(t, err)
			if tc.errContains != "" {
				assert.ErrorContains(t, err, tc.errContains)
			}
			assert.Equal(t, CTResult{}, res)
		})
	}
}

func TestCheckWithoutSCTs(t *testing.T) {
	t.Parallel()

	f := newCTFixture(t, ctFixtureSpec{logs: []ctLogSpec{{operator: "A"}}})
	res, err := f.checker.Check(context.Background(), f.chainPEM)

	assert.NoError(t, err)
	assert.Equal(t, CTResult{Problem: "certificate has no embedded SCTs"}, res)
	// a certificate without SCTs is rejected before any network access
	assert.Zero(t, f.list.hits.Load())
}

func TestCheck(t *testing.T) {
	t.Parallel()

	cases := []struct {
		title           string
		spec            ctFixtureSpec
		problemContains []string
		warningContains []string
	}{
		{
			title: "TwoOperatorsIncluded",
			spec: ctFixtureSpec{
				logs: []ctLogSpec{{operator: "A"}, {operator: "B"}},
				scts: []ctSCTRef{{log: 0, age: ctTestOldSCT}, {log: 1, age: ctTestOldSCT}},
			},
		},
		{
			title: "ThreeOperatorsIncluded",
			spec: ctFixtureSpec{
				logs: []ctLogSpec{{operator: "A"}, {operator: "B"}, {operator: "C"}},
				scts: []ctSCTRef{{log: 0, age: ctTestOldSCT}, {log: 1, age: ctTestOldSCT}, {log: 2, age: ctTestOldSCT}},
			},
		},
		{
			title: "SingleOperatorTwoLogs",
			spec: ctFixtureSpec{
				logs: []ctLogSpec{{operator: "A"}, {operator: "A"}},
				scts: []ctSCTRef{{log: 0, age: ctTestOldSCT}, {log: 1, age: ctTestOldSCT}},
			},
			problemContains: []string{"SCTs from 1 distinct log operator(s), at least 2 required"},
		},
		{
			title: "SingleSCT",
			spec: ctFixtureSpec{
				logs: []ctLogSpec{{operator: "A"}},
				scts: []ctSCTRef{{log: 0, age: ctTestOldSCT}},
			},
			problemContains: []string{"SCTs from 1 distinct log operator(s), at least 2 required"},
		},
		{
			title: "UnknownLog",
			spec: ctFixtureSpec{
				logs: []ctLogSpec{{operator: "A"}, {operator: "B", unlisted: true}},
				scts: []ctSCTRef{{log: 0, age: ctTestOldSCT}, {log: 1, age: ctTestOldSCT}},
			},
			problemContains: []string{"SCTs from 1 distinct log operator(s)", "SCT[1]: unknown log"},
		},
		{
			title: "UnknownLogIgnoredWhenPolicyIsSatisfied",
			spec: ctFixtureSpec{
				logs: []ctLogSpec{{operator: "A"}, {operator: "B"}, {operator: "C", unlisted: true}},
				scts: []ctSCTRef{{log: 0, age: ctTestOldSCT}, {log: 1, age: ctTestOldSCT}, {log: 2, age: ctTestOldSCT}},
			},
			warningContains: []string{"SCT[2]: unknown log"},
		},
		{
			title: "InvalidSignature",
			spec: ctFixtureSpec{
				logs: []ctLogSpec{{operator: "A"}, {operator: "B"}},
				scts: []ctSCTRef{{log: 0, age: ctTestOldSCT}, {log: 1, age: ctTestOldSCT, wrongSigner: true}},
			},
			problemContains: []string{"SCTs from 1 distinct log operator(s)", `SCT[1]: invalid signature from log "log-1"`},
		},
		{
			title: "InvalidSignatureIgnoredWhenPolicyIsSatisfied",
			spec: ctFixtureSpec{
				logs: []ctLogSpec{{operator: "A"}, {operator: "B"}, {operator: "C"}},
				scts: []ctSCTRef{{log: 0, age: ctTestOldSCT}, {log: 1, age: ctTestOldSCT}, {log: 2, age: ctTestOldSCT, wrongSigner: true}},
			},
			warningContains: []string{`SCT[2]: invalid signature from log "log-2"`},
		},
		{
			// the log has not necessarily merged the entry yet, which is not held against the certificate
			title: "PendingWithinMMD",
			spec: ctFixtureSpec{
				logs: []ctLogSpec{{operator: "A", mode: ctLogDown}, {operator: "B", mode: ctLogDown}},
				scts: []ctSCTRef{{log: 0, age: ctTestRecentSCT}, {log: 1, age: ctTestRecentSCT}},
			},
		},
		{
			title: "PendingWithinMMDEvenIfLogSaysNotFound",
			spec: ctFixtureSpec{
				logs: []ctLogSpec{{operator: "A", mode: ctLogNotFound}, {operator: "B", mode: ctLogNotFound}},
				scts: []ctSCTRef{{log: 0, age: ctTestRecentSCT}, {log: 1, age: ctTestRecentSCT}},
			},
		},
		{
			// an unreachable log is inconclusive: it counts, with a warning
			title: "UnverifiableAfterMMD",
			spec: ctFixtureSpec{
				logs: []ctLogSpec{{operator: "A", mode: ctLogDown}, {operator: "B", mode: ctLogDown}},
				scts: []ctSCTRef{{log: 0, age: ctTestOldSCT}, {log: 1, age: ctTestOldSCT}},
			},
			warningContains: []string{
				`SCT[0]: inclusion check against log "log-0" inconclusive`,
				`SCT[1]: inclusion check against log "log-1" inconclusive`,
			},
		},
		{
			title: "NotIncludedAfterMMD",
			spec: ctFixtureSpec{
				logs: []ctLogSpec{{operator: "A", mode: ctLogNotFound}, {operator: "B", mode: ctLogNotFound}},
				scts: []ctSCTRef{{log: 0, age: ctTestOldSCT}, {log: 1, age: ctTestOldSCT}},
			},
			problemContains: []string{
				"SCTs from 0 distinct log operator(s), at least 2 required",
				`SCT[0]: not included in log "log-0"`,
				`SCT[1]: not included in log "log-1"`,
			},
		},
		{
			title: "NotIncludedIgnoredWhenPolicyIsSatisfied",
			spec: ctFixtureSpec{
				logs: []ctLogSpec{{operator: "A"}, {operator: "B"}, {operator: "C", mode: ctLogNotFound}},
				scts: []ctSCTRef{{log: 0, age: ctTestOldSCT}, {log: 1, age: ctTestOldSCT}, {log: 2, age: ctTestOldSCT}},
			},
			warningContains: []string{`SCT[2]: not included in log "log-2"`},
		},
		{
			// one log is down, the other proves inclusion: the policy is still met, with a warning
			title: "OneLogDown",
			spec: ctFixtureSpec{
				logs: []ctLogSpec{{operator: "A"}, {operator: "B", mode: ctLogDown}},
				scts: []ctSCTRef{{log: 0, age: ctTestOldSCT}, {log: 1, age: ctTestOldSCT}},
			},
			warningContains: []string{`SCT[1]: inclusion check against log "log-1" inconclusive`},
		},
		{
			// the log cannot be queried at all, so its SCT is unverifiable, and counts
			title: "LogInfoCannotBeBuilt",
			spec: ctFixtureSpec{
				logs: []ctLogSpec{{operator: "A"}, {operator: "B", badKey: true}},
				scts: []ctSCTRef{{log: 0, age: ctTestOldSCT}, {log: 1, age: ctTestOldSCT}},
			},
			warningContains: []string{`SCT[1]: log "log-1":`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			t.Parallel()
			f := newCTFixture(t, tc.spec)

			res, err := f.checker.Check(context.Background(), f.chainPEM)
			assert.NoError(t, err)

			if len(tc.problemContains) == 0 {
				assert.Empty(t, res.Problem)
			}
			for _, s := range tc.problemContains {
				assert.Contains(t, res.Problem, s)
			}
			if assert.Len(t, res.Warnings, len(tc.warningContains)) {
				for i, s := range tc.warningContains {
					assert.Contains(t, res.Warnings[i], s)
				}
			}
		})
	}
}

func TestCheckCachesSuccessfulInclusion(t *testing.T) {
	t.Parallel()

	f := newCTFixture(t, ctFixtureSpec{
		logs: []ctLogSpec{{operator: "A"}, {operator: "B"}},
		scts: []ctSCTRef{{log: 0, age: ctTestOldSCT}, {log: 1, age: ctTestOldSCT}},
	})

	res, err := f.checker.Check(context.Background(), f.chainPEM)
	assert.NoError(t, err)
	assert.Equal(t, CTResult{}, res)
	for _, l := range f.logs {
		assert.EqualValues(t, 1, l.proofCalls.Load(), l.description)
	}
	sthCalls := []int64{f.logs[0].sthCalls.Load(), f.logs[1].sthCalls.Load()}

	// inclusion cannot be revoked, so the second run does not talk to the logs at all
	res, err = f.checker.Check(context.Background(), f.chainPEM)
	assert.NoError(t, err)
	assert.Equal(t, CTResult{}, res)
	for i, l := range f.logs {
		assert.EqualValues(t, 1, l.proofCalls.Load(), l.description)
		assert.Equal(t, sthCalls[i], l.sthCalls.Load(), l.description)
	}
	// the log list is cached too
	assert.EqualValues(t, 1, f.list.hits.Load())
}

func TestCheckDoesNotCacheFailures(t *testing.T) {
	t.Parallel()

	f := newCTFixture(t, ctFixtureSpec{
		logs: []ctLogSpec{{operator: "A", mode: ctLogDown}, {operator: "B", mode: ctLogDown}},
		scts: []ctSCTRef{{log: 0, age: ctTestOldSCT}, {log: 1, age: ctTestOldSCT}},
	})

	res, err := f.checker.Check(context.Background(), f.chainPEM)
	assert.NoError(t, err)
	assert.Empty(t, res.Problem)
	assert.Len(t, res.Warnings, 2)

	// once the logs are back, the inclusion is verified, and the warnings are gone
	for _, l := range f.logs {
		l.setMode(ctLogIncluded)
	}
	res, err = f.checker.Check(context.Background(), f.chainPEM)
	assert.NoError(t, err)
	assert.Equal(t, CTResult{}, res)
	for _, l := range f.logs {
		assert.EqualValues(t, 1, l.proofCalls.Load(), l.description)
	}
}

func TestCheckConcurrently(t *testing.T) {
	t.Parallel()

	f := newCTFixture(t, ctFixtureSpec{
		logs: []ctLogSpec{{operator: "A"}, {operator: "B"}},
		scts: []ctSCTRef{{log: 0, age: ctTestOldSCT}, {log: 1, age: ctTestOldSCT}},
	})

	var wg sync.WaitGroup
	results := make([]CTResult, 8)
	errs := make([]error, len(results))
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = f.checker.Check(context.Background(), f.chainPEM)
		}()
	}
	wg.Wait()

	for i := range results {
		assert.NoError(t, errs[i])
		assert.Equal(t, CTResult{}, results[i])
	}
}
