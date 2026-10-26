package health

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hsn723/cert-orchestrator/internal/healthtest"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

// fakeFormat is a Format that records how it is called.
type fakeFormat struct {
	name string
	// matches is the answer of Matches, unless matchFunc is set.
	matches   bool
	matchFunc func(secret *corev1.Secret) bool
	result    Result

	matchCalls atomic.Int64
	evalCalls  atomic.Int64

	mu          sync.Mutex
	matchSecret *corev1.Secret
	evalCtx     context.Context
	evalSecret  *corev1.Secret
	evalPolicy  Policy
	evalTime    time.Time
}

var _ Format = &fakeFormat{}

func (f *fakeFormat) Name() string {
	return f.name
}

func (f *fakeFormat) Matches(secret *corev1.Secret) bool {
	f.matchCalls.Add(1)
	f.mu.Lock()
	f.matchSecret = secret
	f.mu.Unlock()
	if f.matchFunc != nil {
		return f.matchFunc(secret)
	}
	return f.matches
}

func (f *fakeFormat) Evaluate(ctx context.Context, secret *corev1.Secret, policy Policy, evalTime time.Time) Result {
	f.evalCalls.Add(1)
	f.mu.Lock()
	f.evalCtx = ctx
	f.evalSecret = secret
	f.evalPolicy = policy
	f.evalTime = evalTime
	f.mu.Unlock()
	return f.result
}

func TestDefault(t *testing.T) {
	t.Parallel()
	policy := Default()
	assert.True(t, policy.CheckExpiry)
	assert.True(t, policy.CheckRevocation)
	assert.True(t, policy.CheckCT)
	assert.Equal(t, Policy{CheckExpiry: true, CheckRevocation: true, CheckCT: true}, policy)
}

func TestResultEligible(t *testing.T) {
	t.Parallel()
	cases := []struct {
		title    string
		result   Result
		expected bool
	}{
		{
			title:    "ParsedWithoutProblems",
			result:   Result{Parsed: true},
			expected: true,
		},
		{
			title:    "ParsedWithEmptyProblems",
			result:   Result{Parsed: true, Problems: []string{}},
			expected: true,
		},
		{
			// warnings are inconclusive checks, they never make a credential ineligible
			title:    "ParsedWithWarningsOnly",
			result:   Result{Parsed: true, Warnings: []string{"revocation status unknown"}},
			expected: true,
		},
		{
			title:    "ParsedWithOneProblem",
			result:   Result{Parsed: true, Problems: []string{"expired"}},
			expected: false,
		},
		{
			title:    "ParsedWithProblemsAndWarnings",
			result:   Result{Parsed: true, Problems: []string{"expired"}, Warnings: []string{"warning"}},
			expected: false,
		},
		{
			title:    "ParsedWithSeveralProblems",
			result:   Result{Parsed: true, Problems: []string{"expired", "revoked"}},
			expected: false,
		},
		{
			title:    "NotParsedWithoutProblems",
			result:   Result{Parsed: false},
			expected: false,
		},
		{
			title:    "NotParsedWithProblems",
			result:   Result{Parsed: false, Problems: []string{"no certificate found in tls.crt"}},
			expected: false,
		},
		{
			title:    "ZeroValue",
			result:   Result{},
			expected: false,
		},
		{
			title:    "FormatDoesNotMatter",
			result:   Result{Format: "X509", Parsed: true},
			expected: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, tc.result.Eligible())
		})
	}
}

func TestNewEvaluator(t *testing.T) {
	t.Parallel()

	t.Run("NoFormats", func(t *testing.T) {
		t.Parallel()
		e := NewEvaluator()
		if assert.NotNil(t, e) {
			assert.Empty(t, e.formats)
		}
	})
	t.Run("FormatsKeepTheirOrder", func(t *testing.T) {
		t.Parallel()
		first := &fakeFormat{name: "first"}
		second := &fakeFormat{name: "second"}
		third := &fakeFormat{name: "third"}

		e := NewEvaluator(first, second, third)
		if assert.Len(t, e.formats, 3) {
			assert.Same(t, first, e.formats[0])
			assert.Same(t, second, e.formats[1])
			assert.Same(t, third, e.formats[2])
		}
	})
}

func TestEvaluatorEvaluate(t *testing.T) {
	t.Parallel()

	noFormatResult := Result{Problems: []string{"no supported certificate format found in Secret"}}

	cases := []struct {
		title    string
		formats  []*fakeFormat
		expected Result
		// expectedMatchCalls and expectedEvalCalls are per format, in the order of formats
		expectedMatchCalls []int64
		expectedEvalCalls  []int64
	}{
		{
			title:              "NoFormats",
			formats:            nil,
			expected:           noFormatResult,
			expectedMatchCalls: []int64{},
			expectedEvalCalls:  []int64{},
		},
		{
			title: "NoFormatMatches",
			formats: []*fakeFormat{
				{name: "a", matches: false, result: Result{Parsed: true}},
				{name: "b", matches: false, result: Result{Parsed: true}},
			},
			expected:           noFormatResult,
			expectedMatchCalls: []int64{1, 1},
			expectedEvalCalls:  []int64{0, 0},
		},
		{
			title: "SingleMatchingFormat",
			formats: []*fakeFormat{
				{name: "a", matches: true, result: Result{Parsed: true}},
			},
			expected:           Result{Format: "a", Parsed: true},
			expectedMatchCalls: []int64{1},
			expectedEvalCalls:  []int64{1},
		},
		{
			// a format that does not match is never evaluated
			title: "NonMatchingFormatIsSkipped",
			formats: []*fakeFormat{
				{name: "a", matches: false, result: Result{Parsed: true, Problems: []string{"from a"}}},
				{name: "b", matches: true, result: Result{Parsed: true}},
			},
			expected:           Result{Format: "b", Parsed: true},
			expectedMatchCalls: []int64{1, 1},
			expectedEvalCalls:  []int64{0, 1},
		},
		{
			// the first match wins, later formats are not even asked
			title: "FirstMatchWins",
			formats: []*fakeFormat{
				{name: "specific", matches: true, result: Result{Parsed: true}},
				{name: "generic", matches: true, result: Result{Parsed: true, Problems: []string{"from generic"}}},
			},
			expected:           Result{Format: "specific", Parsed: true},
			expectedMatchCalls: []int64{1, 0},
			expectedEvalCalls:  []int64{1, 0},
		},
		{
			title: "FirstMatchWinsAmongSeveral",
			formats: []*fakeFormat{
				{name: "a", matches: false},
				{name: "b", matches: true, result: Result{Parsed: true}},
				{name: "c", matches: true},
				{name: "d", matches: true},
			},
			expected:           Result{Format: "b", Parsed: true},
			expectedMatchCalls: []int64{1, 1, 0, 0},
			expectedEvalCalls:  []int64{0, 1, 0, 0},
		},
		{
			// a matching format that finds the credential ineligible does not fall through to the next one
			title: "NoFallThroughOnProblems",
			formats: []*fakeFormat{
				{name: "specific", matches: true, result: Result{Parsed: true, Problems: []string{"expired"}}},
				{name: "generic", matches: true, result: Result{Parsed: true}},
			},
			expected:           Result{Format: "specific", Parsed: true, Problems: []string{"expired"}},
			expectedMatchCalls: []int64{1, 0},
			expectedEvalCalls:  []int64{1, 0},
		},
		{
			title: "ResultIsPassedThrough",
			formats: []*fakeFormat{
				{name: "a", matches: true, result: Result{
					Parsed:   true,
					Problems: []string{"problem 1", "problem 2"},
					Warnings: []string{"warning 1", "warning 2"},
				}},
			},
			expected: Result{
				Format:   "a",
				Parsed:   true,
				Problems: []string{"problem 1", "problem 2"},
				Warnings: []string{"warning 1", "warning 2"},
			},
			expectedMatchCalls: []int64{1},
			expectedEvalCalls:  []int64{1},
		},
		{
			// the name reported in the result is the one of the format that did the evaluation,
			// whatever the format put there itself
			title: "FormatNameOverridesResultFormat",
			formats: []*fakeFormat{
				{name: "real", matches: true, result: Result{Format: "bogus", Parsed: true}},
			},
			expected:           Result{Format: "real", Parsed: true},
			expectedMatchCalls: []int64{1},
			expectedEvalCalls:  []int64{1},
		},
		{
			title: "UnparsedResultIsPassedThrough",
			formats: []*fakeFormat{
				{name: "a", matches: true, result: Result{Problems: []string{"failed to parse certificate in tls.crt"}}},
			},
			expected:           Result{Format: "a", Problems: []string{"failed to parse certificate in tls.crt"}},
			expectedMatchCalls: []int64{1},
			expectedEvalCalls:  []int64{1},
		},
		{
			title: "FormatWithEmptyName",
			formats: []*fakeFormat{
				{name: "", matches: true, result: Result{Format: "bogus", Parsed: true}},
			},
			expected:           Result{Parsed: true},
			expectedMatchCalls: []int64{1},
			expectedEvalCalls:  []int64{1},
		},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			t.Parallel()
			formats := make([]Format, 0, len(tc.formats))
			for _, f := range tc.formats {
				formats = append(formats, f)
			}
			e := NewEvaluator(formats...)

			actual := e.Evaluate(context.Background(), healthtest.SecretWithKey(corev1.TLSCertKey), Default(), healthtest.Now)
			assert.Equal(t, tc.expected, actual)

			matchCalls := make([]int64, 0, len(tc.formats))
			evalCalls := make([]int64, 0, len(tc.formats))
			for _, f := range tc.formats {
				matchCalls = append(matchCalls, f.matchCalls.Load())
				evalCalls = append(evalCalls, f.evalCalls.Load())
			}
			assert.Equal(t, tc.expectedMatchCalls, matchCalls)
			assert.Equal(t, tc.expectedEvalCalls, evalCalls)
		})
	}
}

func TestEvaluatorEvaluateNoFormatIsNotEligible(t *testing.T) {
	t.Parallel()
	actual := NewEvaluator(&fakeFormat{name: "a", matches: false}).
		Evaluate(context.Background(), &corev1.Secret{}, Default(), healthtest.Now)

	assert.False(t, actual.Parsed)
	assert.False(t, actual.Eligible())
	assert.Empty(t, actual.Format)
	assert.Empty(t, actual.Warnings)
}

func TestEvaluatorEvaluatePassesArguments(t *testing.T) {
	t.Parallel()

	skipped := &fakeFormat{name: "skipped", matches: false}
	matching := &fakeFormat{name: "matching", matches: true, result: Result{Parsed: true}}
	e := NewEvaluator(skipped, matching)

	secret := healthtest.SecretWithKey(corev1.TLSCertKey)
	policy := Policy{CheckExpiry: true, CheckCT: true}
	ctx := context.WithValue(context.Background(), healthtest.ContextKey{}, "value")

	e.Evaluate(ctx, secret, policy, healthtest.Now)

	// every format that is asked gets the Secret as is
	assert.Same(t, secret, skipped.matchSecret)
	assert.Same(t, secret, matching.matchSecret)

	// Evaluate gets the context, the Secret, the policy and the evaluation time unchanged
	assert.Same(t, secret, matching.evalSecret)
	assert.Equal(t, policy, matching.evalPolicy)
	assert.Equal(t, healthtest.Now, matching.evalTime)
	if assert.NotNil(t, matching.evalCtx) {
		assert.Equal(t, "value", matching.evalCtx.Value(healthtest.ContextKey{}))
	}
}

func TestEvaluatorEvaluateDoesNotMutateFormatResult(t *testing.T) {
	t.Parallel()

	format := &fakeFormat{name: "a", matches: true, result: Result{Format: "bogus", Parsed: true}}
	e := NewEvaluator(format)

	first := e.Evaluate(context.Background(), &corev1.Secret{}, Default(), healthtest.Now)
	assert.Equal(t, "a", first.Format)
	// the result is returned by value, the format's own result is left alone
	assert.Equal(t, "bogus", format.result.Format)

	// and evaluating again gives the same answer
	second := e.Evaluate(context.Background(), &corev1.Secret{}, Default(), healthtest.Now)
	assert.Equal(t, first, second)
	assert.EqualValues(t, 2, format.evalCalls.Load())
}

func TestEvaluatorEvaluateDispatchesOnSecret(t *testing.T) {
	t.Parallel()

	const (
		keyA = "format-a"
		keyB = "format-b"
	)
	hasKey := func(key string) func(*corev1.Secret) bool {
		return func(secret *corev1.Secret) bool {
			_, ok := secret.Data[key]
			return ok
		}
	}
	newEvaluator := func() (*Evaluator, *fakeFormat, *fakeFormat) {
		a := &fakeFormat{name: "A", matchFunc: hasKey(keyA), result: Result{Parsed: true}}
		b := &fakeFormat{name: "B", matchFunc: hasKey(keyB), result: Result{Parsed: true}}
		return NewEvaluator(a, b), a, b
	}

	cases := []struct {
		title    string
		secret   *corev1.Secret
		expected Result
		evalA    int64
		evalB    int64
	}{
		{
			title:    "SecretForFirstFormat",
			secret:   healthtest.SecretWithKey(keyA),
			expected: Result{Format: "A", Parsed: true},
			evalA:    1,
			evalB:    0,
		},
		{
			title:    "SecretForSecondFormat",
			secret:   healthtest.SecretWithKey(keyB),
			expected: Result{Format: "B", Parsed: true},
			evalA:    0,
			evalB:    1,
		},
		{
			// the order of the formats decides when a Secret matches several
			title: "SecretForBothFormats",
			secret: &corev1.Secret{Data: map[string][]byte{
				keyA: []byte("data"),
				keyB: []byte("data"),
			}},
			expected: Result{Format: "A", Parsed: true},
			evalA:    1,
			evalB:    0,
		},
		{
			title:    "SecretForNoFormat",
			secret:   healthtest.SecretWithKey("other"),
			expected: Result{Problems: []string{"no supported certificate format found in Secret"}},
			evalA:    0,
			evalB:    0,
		},
		{
			title:    "EmptySecret",
			secret:   &corev1.Secret{},
			expected: Result{Problems: []string{"no supported certificate format found in Secret"}},
			evalA:    0,
			evalB:    0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			t.Parallel()
			e, a, b := newEvaluator()

			actual := e.Evaluate(context.Background(), tc.secret, Default(), healthtest.Now)
			assert.Equal(t, tc.expected, actual)
			assert.Equal(t, tc.evalA, a.evalCalls.Load())
			assert.Equal(t, tc.evalB, b.evalCalls.Load())
		})
	}
}

func TestEvaluatorEvaluateConcurrently(t *testing.T) {
	t.Parallel()

	skipped := &fakeFormat{name: "skipped", matches: false}
	matching := &fakeFormat{name: "matching", matches: true, result: Result{Parsed: true}}
	e := NewEvaluator(skipped, matching)

	const workers = 16
	var wg sync.WaitGroup
	results := make([]Result, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = e.Evaluate(context.Background(), &corev1.Secret{}, Default(), healthtest.Now)
		}()
	}
	wg.Wait()

	for i := 0; i < workers; i++ {
		assert.Equal(t, Result{Format: "matching", Parsed: true}, results[i])
	}
	assert.EqualValues(t, workers, skipped.matchCalls.Load())
	assert.EqualValues(t, 0, skipped.evalCalls.Load())
	assert.EqualValues(t, workers, matching.matchCalls.Load())
	assert.EqualValues(t, workers, matching.evalCalls.Load())
}
