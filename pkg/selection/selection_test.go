package selection

import (
	"testing"

	"github.com/stretchr/testify/assert"

	apiv1 "github.com/hsn723/cert-orchestrator/api/v1"
	"github.com/hsn723/cert-orchestrator/pkg/health"
)

// eligibleCandidate is available, evaluated and cleared every check.
func eligibleCandidate(name string, primary bool) Candidate {
	return Candidate{
		Name:      name,
		Primary:   primary,
		Available: true,
		Evaluated: true,
		Result:    health.Result{Parsed: true},
	}
}

// ineligibleCandidate is available and evaluated, but failed a check.
func ineligibleCandidate(name string, primary bool) Candidate {
	return Candidate{
		Name:      name,
		Primary:   primary,
		Available: true,
		Evaluated: true,
		Result:    health.Result{Parsed: true, Problems: []string{"expired"}},
	}
}

// unavailableCandidate has no Secret yet.
func unavailableCandidate(name string, primary bool) Candidate {
	return Candidate{Name: name, Primary: primary}
}

// unevaluatedCandidate has a Secret, but was not evaluated, as when the algorithm does not use health.
func unevaluatedCandidate(name string, primary bool) Candidate {
	return Candidate{
		Name:      name,
		Primary:   primary,
		Available: true,
		Result:    health.Result{Parsed: true},
	}
}

type selectCase struct {
	title    string
	in       Input
	expected Decision
}

func runSelectCases(t *testing.T, algorithm Algorithm, cases []selectCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, algorithm.Select(tc.in))
		})
	}
}

type fakeAlgorithm struct {
	name apiv1.SelectionAlgorithm
	id   string
}

var _ Algorithm = fakeAlgorithm{}

func (f fakeAlgorithm) Name() apiv1.SelectionAlgorithm { return f.name }

func (fakeAlgorithm) HealthPolicy() *health.Policy { return nil }

func (f fakeAlgorithm) Select(Input) Decision { return Decision{Reason: f.id} }

func TestCandidateEligible(t *testing.T) {
	t.Parallel()
	cases := []struct {
		title     string
		candidate Candidate
		expected  bool
	}{
		{
			title:     "AvailableEvaluatedAndClean",
			candidate: Candidate{Available: true, Evaluated: true, Result: health.Result{Parsed: true}},
			expected:  true,
		},
		{
			// warnings are inconclusive checks, they never make a candidate ineligible
			title: "WarningsOnly",
			candidate: Candidate{
				Available: true,
				Evaluated: true,
				Result:    health.Result{Parsed: true, Warnings: []string{"revocation status unknown"}},
			},
			expected: true,
		},
		{
			title: "WithProblems",
			candidate: Candidate{
				Available: true,
				Evaluated: true,
				Result:    health.Result{Parsed: true, Problems: []string{"expired"}},
			},
			expected: false,
		},
		{
			title:     "NotParsed",
			candidate: Candidate{Available: true, Evaluated: true, Result: health.Result{Parsed: false}},
			expected:  false,
		},
		{
			title:     "NotAvailable",
			candidate: Candidate{Available: false, Evaluated: true, Result: health.Result{Parsed: true}},
			expected:  false,
		},
		{
			// a result that was never computed means nothing, even if it looks clean
			title:     "NotEvaluated",
			candidate: Candidate{Available: true, Evaluated: false, Result: health.Result{Parsed: true}},
			expected:  false,
		},
		{
			title:     "ZeroValue",
			candidate: Candidate{},
			expected:  false,
		},
		{
			title:     "PrimaryFlagDoesNotMatter",
			candidate: Candidate{Primary: true, Available: true, Evaluated: true, Result: health.Result{Parsed: true}},
			expected:  true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, tc.candidate.Eligible())
		})
	}
}

func TestPrimary(t *testing.T) {
	t.Parallel()
	cases := []struct {
		title    string
		in       Input
		expected Candidate
		found    bool
	}{
		{
			title:    "NoCandidates",
			in:       Input{},
			expected: Candidate{},
			found:    false,
		},
		{
			title:    "OnlyFallbacks",
			in:       Input{Candidates: []Candidate{eligibleCandidate("a", false), eligibleCandidate("b", false)}},
			expected: Candidate{},
			found:    false,
		},
		{
			title:    "PrimaryFirst",
			in:       Input{Candidates: []Candidate{eligibleCandidate("a", true), eligibleCandidate("b", false)}},
			expected: eligibleCandidate("a", true),
			found:    true,
		},
		{
			title:    "PrimaryLast",
			in:       Input{Candidates: []Candidate{eligibleCandidate("a", false), eligibleCandidate("b", true)}},
			expected: eligibleCandidate("b", true),
			found:    true,
		},
		{
			// the primary is returned whatever its state
			title:    "UnavailablePrimary",
			in:       Input{Candidates: []Candidate{unavailableCandidate("a", true), eligibleCandidate("b", false)}},
			expected: unavailableCandidate("a", true),
			found:    true,
		},
		{
			title: "FirstPrimaryWhenSeveral",
			in: Input{Candidates: []Candidate{
				eligibleCandidate("a", false),
				ineligibleCandidate("b", true),
				eligibleCandidate("c", true),
			}},
			expected: ineligibleCandidate("b", true),
			found:    true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			t.Parallel()
			actual, found := primary(tc.in)
			assert.Equal(t, tc.found, found)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestFirstEligible(t *testing.T) {
	t.Parallel()
	cases := []struct {
		title    string
		in       Input
		expected Candidate
		found    bool
	}{
		{
			title:    "NoCandidates",
			in:       Input{},
			expected: Candidate{},
			found:    false,
		},
		{
			title: "NoneEligible",
			in: Input{Candidates: []Candidate{
				ineligibleCandidate("a", true),
				unavailableCandidate("b", false),
				unevaluatedCandidate("c", false),
			}},
			expected: Candidate{},
			found:    false,
		},
		{
			title:    "SingleEligible",
			in:       Input{Candidates: []Candidate{ineligibleCandidate("a", true), eligibleCandidate("b", false)}},
			expected: eligibleCandidate("b", false),
			found:    true,
		},
		{
			title: "FirstFallbackWhenSeveralAreEligible",
			in: Input{Candidates: []Candidate{
				ineligibleCandidate("a", true),
				eligibleCandidate("b", false),
				eligibleCandidate("c", false),
			}},
			expected: eligibleCandidate("b", false),
			found:    true,
		},
		{
			title:    "EligiblePrimaryFirst",
			in:       Input{Candidates: []Candidate{eligibleCandidate("a", true), eligibleCandidate("b", false)}},
			expected: eligibleCandidate("a", true),
			found:    true,
		},
		{
			// the primary wins whatever its position in the list
			title: "EligiblePrimaryLast",
			in: Input{Candidates: []Candidate{
				eligibleCandidate("a", false),
				eligibleCandidate("b", false),
				eligibleCandidate("c", true),
			}},
			expected: eligibleCandidate("c", true),
			found:    true,
		},
		{
			title: "EligiblePrimaryInTheMiddle",
			in: Input{Candidates: []Candidate{
				eligibleCandidate("a", false),
				eligibleCandidate("b", true),
				eligibleCandidate("c", false),
			}},
			expected: eligibleCandidate("b", true),
			found:    true,
		},
		{
			title: "IneligiblePrimaryIsSkipped",
			in: Input{Candidates: []Candidate{
				eligibleCandidate("a", false),
				ineligibleCandidate("b", true),
			}},
			expected: eligibleCandidate("a", false),
			found:    true,
		},
		{
			// candidates are identified by name: an eligible candidate without one cannot be selected,
			// and does not hide the ones after it
			title: "EligibleCandidateWithoutNameIsIgnored",
			in: Input{Candidates: []Candidate{
				eligibleCandidate("", false),
				eligibleCandidate("b", false),
			}},
			expected: eligibleCandidate("b", false),
			found:    true,
		},
		{
			// found is false because candidates are identified by name, the returned candidate is
			// not meaningful then and callers must not use it
			title:    "OnlyEligibleCandidateWithoutName",
			in:       Input{Candidates: []Candidate{eligibleCandidate("", false)}},
			expected: eligibleCandidate("", false),
			found:    false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			t.Parallel()
			actual, found := firstEligible(tc.in)
			assert.Equal(t, tc.found, found)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestAllChecks(t *testing.T) {
	t.Parallel()

	policy := allChecks()
	if assert.NotNil(t, policy) {
		assert.Equal(t, health.Default(), *policy)
	}

	// every call returns a fresh policy: changing one must not leak into the next
	policy.CheckCT = false
	policy.CheckExpiry = false
	other := allChecks()
	assert.NotSame(t, policy, other)
	assert.Equal(t, health.Default(), *other)
}

func TestAlgorithms(t *testing.T) {
	t.Parallel()
	defaultPolicy := health.Default()
	cases := []struct {
		title          string
		algorithm      Algorithm
		expectedName   apiv1.SelectionAlgorithm
		expectedPolicy *health.Policy
	}{
		{
			title:          "ForcePrimary",
			algorithm:      ForcePrimary{},
			expectedName:   apiv1.SelectionAlgorithmForcePrimary,
			expectedPolicy: nil,
		},
		{
			title:          "Strict",
			algorithm:      Strict{},
			expectedName:   apiv1.SelectionAlgorithmStrict,
			expectedPolicy: &defaultPolicy,
		},
		{
			title:          "PrimaryIfNone",
			algorithm:      PrimaryIfNone{},
			expectedName:   apiv1.SelectionAlgorithmPrimaryIfNone,
			expectedPolicy: &defaultPolicy,
		},
		{
			title:          "Manual",
			algorithm:      Manual{},
			expectedName:   apiv1.SelectionAlgorithmManual,
			expectedPolicy: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expectedName, tc.algorithm.Name())
			// a nil policy means the algorithm does not use health, and candidates are not evaluated
			assert.Equal(t, tc.expectedPolicy, tc.algorithm.HealthPolicy())
		})
	}

	t.Run("HealthPoliciesAreIndependent", func(t *testing.T) {
		t.Parallel()
		for _, algorithm := range []Algorithm{Strict{}, PrimaryIfNone{}} {
			policy := algorithm.HealthPolicy()
			if !assert.NotNil(t, policy) {
				continue
			}
			policy.CheckRevocation = false
			assert.Equal(t, health.Default(), *algorithm.HealthPolicy(), algorithm.Name())
		}
	})
}

func TestForcePrimarySelect(t *testing.T) {
	t.Parallel()

	selectedA := Decision{
		Selected: "a",
		Reason:   ReasonForcedPrimary,
		Message:  "primary certificate a selected unconditionally",
	}
	noPrimary := Decision{
		Reason:  ReasonNoEligibleCertificate,
		Message: "no primary certificate found",
	}

	runSelectCases(t, ForcePrimary{}, []selectCase{
		{
			title:    "EligiblePrimary",
			in:       Input{Candidates: []Candidate{eligibleCandidate("a", true), eligibleCandidate("b", false)}},
			expected: selectedA,
		},
		{
			// no matter what: health is not looked at
			title:    "IneligiblePrimary",
			in:       Input{Candidates: []Candidate{ineligibleCandidate("a", true), eligibleCandidate("b", false)}},
			expected: selectedA,
		},
		{
			// the primary is selected even before its Secret exists, activating it is up to the controller
			title:    "UnavailablePrimary",
			in:       Input{Candidates: []Candidate{unavailableCandidate("a", true), eligibleCandidate("b", false)}},
			expected: selectedA,
		},
		{
			title:    "UnevaluatedPrimary",
			in:       Input{Candidates: []Candidate{unevaluatedCandidate("a", true)}},
			expected: selectedA,
		},
		{
			title:    "PrimaryListedAfterFallbacks",
			in:       Input{Candidates: []Candidate{eligibleCandidate("b", false), eligibleCandidate("a", true)}},
			expected: selectedA,
		},
		{
			title: "ActiveFallbackIsIgnored",
			in: Input{
				Candidates: []Candidate{eligibleCandidate("a", true), eligibleCandidate("b", false)},
				Active:     "b",
			},
			expected: selectedA,
		},
		{
			title:    "NoPrimary",
			in:       Input{Candidates: []Candidate{eligibleCandidate("b", false), eligibleCandidate("c", false)}},
			expected: noPrimary,
		},
		{
			title:    "NoCandidates",
			in:       Input{},
			expected: noPrimary,
		},
	})
}

func TestStrictSelect(t *testing.T) {
	t.Parallel()

	selected := func(name string) Decision {
		return Decision{
			Selected: name,
			Reason:   ReasonEligible,
			Message:  "certificate " + name + " selected",
		}
	}
	noEligible := Decision{
		Reason:  ReasonNoEligibleCertificate,
		Message: "no eligible certificate found",
	}

	runSelectCases(t, Strict{}, []selectCase{
		{
			title:    "EligiblePrimary",
			in:       Input{Candidates: []Candidate{eligibleCandidate("a", true), eligibleCandidate("b", false)}},
			expected: selected("a"),
		},
		{
			title:    "IneligiblePrimaryFailsOverToFallback",
			in:       Input{Candidates: []Candidate{ineligibleCandidate("a", true), eligibleCandidate("b", false)}},
			expected: selected("b"),
		},
		{
			title:    "UnavailablePrimaryFailsOverToFallback",
			in:       Input{Candidates: []Candidate{unavailableCandidate("a", true), eligibleCandidate("b", false)}},
			expected: selected("b"),
		},
		{
			title: "FirstEligibleFallbackWins",
			in: Input{Candidates: []Candidate{
				ineligibleCandidate("a", true),
				ineligibleCandidate("b", false),
				eligibleCandidate("c", false),
				eligibleCandidate("d", false),
			}},
			expected: selected("c"),
		},
		{
			// the primary is preferred over the fallbacks whatever the order of the candidates
			title:    "EligiblePrimaryListedAfterFallbacks",
			in:       Input{Candidates: []Candidate{eligibleCandidate("b", false), eligibleCandidate("a", true)}},
			expected: selected("a"),
		},
		{
			// no stickiness: the primary takes over again as soon as it is eligible
			title: "ActiveFallbackFailsBackToEligiblePrimary",
			in: Input{
				Candidates: []Candidate{eligibleCandidate("a", true), eligibleCandidate("b", false)},
				Active:     "b",
			},
			expected: selected("a"),
		},
		{
			title: "ActiveCandidateThatBecameIneligibleIsReplaced",
			in: Input{
				Candidates: []Candidate{ineligibleCandidate("a", true), ineligibleCandidate("b", false), eligibleCandidate("c", false)},
				Active:     "b",
			},
			expected: selected("c"),
		},
		{
			title: "NothingIsSelectedWhenNoneIsEligible",
			in: Input{
				Candidates: []Candidate{ineligibleCandidate("a", true), ineligibleCandidate("b", false)},
				Active:     "a",
			},
			expected: noEligible,
		},
		{
			// the primary is not a fallback for Strict, even if it is the only candidate available
			title:    "UnevaluatedCandidatesAreNotEligible",
			in:       Input{Candidates: []Candidate{unevaluatedCandidate("a", true), unevaluatedCandidate("b", false)}},
			expected: noEligible,
		},
		{
			title:    "NoCandidatesAvailable",
			in:       Input{Candidates: []Candidate{unavailableCandidate("a", true), unavailableCandidate("b", false)}},
			expected: noEligible,
		},
		{
			title:    "NoCandidates",
			in:       Input{},
			expected: noEligible,
		},
	})
}

func TestPrimaryIfNoneSelect(t *testing.T) {
	t.Parallel()

	selected := func(name string) Decision {
		return Decision{
			Selected: name,
			Reason:   ReasonEligible,
			Message:  "certificate " + name + " selected",
		}
	}
	fallback := func(name string) Decision {
		return Decision{
			Selected: name,
			Reason:   ReasonPrimaryFallback,
			Message:  "no eligible certificate found, primary " + name + " selected as fallback",
		}
	}
	noEligible := Decision{
		Reason:  ReasonNoEligibleCertificate,
		Message: "no eligible certificate found",
	}

	runSelectCases(t, PrimaryIfNone{}, []selectCase{
		{
			title:    "EligiblePrimary",
			in:       Input{Candidates: []Candidate{eligibleCandidate("a", true), eligibleCandidate("b", false)}},
			expected: selected("a"),
		},
		{
			title:    "IneligiblePrimaryFailsOverToFallback",
			in:       Input{Candidates: []Candidate{ineligibleCandidate("a", true), eligibleCandidate("b", false)}},
			expected: selected("b"),
		},
		{
			title: "FirstEligibleFallbackWins",
			in: Input{Candidates: []Candidate{
				ineligibleCandidate("a", true),
				eligibleCandidate("b", false),
				eligibleCandidate("c", false),
			}},
			expected: selected("b"),
		},
		{
			title:    "EligiblePrimaryListedAfterFallbacks",
			in:       Input{Candidates: []Candidate{eligibleCandidate("b", false), eligibleCandidate("a", true)}},
			expected: selected("a"),
		},
		{
			// the whole point of the preset: consumers are never left without a Secret
			title:    "NoneEligibleFallsBackToPrimary",
			in:       Input{Candidates: []Candidate{ineligibleCandidate("a", true), ineligibleCandidate("b", false)}},
			expected: fallback("a"),
		},
		{
			// even when the current selection is a fallback that just turned ineligible
			title: "NoneEligibleFallsBackToPrimaryFromActiveFallback",
			in: Input{
				Candidates: []Candidate{ineligibleCandidate("a", true), ineligibleCandidate("b", false)},
				Active:     "b",
			},
			expected: fallback("a"),
		},
		{
			title:    "NoneEligibleFallsBackToPrimaryListedLast",
			in:       Input{Candidates: []Candidate{ineligibleCandidate("b", false), ineligibleCandidate("a", true)}},
			expected: fallback("a"),
		},
		{
			// the primary only has to exist
			title:    "UnevaluatedPrimaryIsTheFallback",
			in:       Input{Candidates: []Candidate{unevaluatedCandidate("a", true), unevaluatedCandidate("b", false)}},
			expected: fallback("a"),
		},
		{
			title:    "FallbackSecretsMissingFallsBackToPrimary",
			in:       Input{Candidates: []Candidate{ineligibleCandidate("a", true), unavailableCandidate("b", false)}},
			expected: fallback("a"),
		},
		{
			// nothing can be served when the primary has no Secret
			title:    "UnavailablePrimaryCannotBeTheFallback",
			in:       Input{Candidates: []Candidate{unavailableCandidate("a", true), ineligibleCandidate("b", false)}},
			expected: noEligible,
		},
		{
			title:    "NoPrimary",
			in:       Input{Candidates: []Candidate{ineligibleCandidate("b", false), ineligibleCandidate("c", false)}},
			expected: noEligible,
		},
		{
			title:    "NoCandidates",
			in:       Input{},
			expected: noEligible,
		},
	})
}

func TestManualSelect(t *testing.T) {
	t.Parallel()

	expected := Decision{
		Unmanaged: true,
		Reason:    ReasonManualSelection,
		Message:   "selection is left to an external actor",
	}

	// manual selection never looks at its input
	runSelectCases(t, Manual{}, []selectCase{
		{
			title:    "NoCandidates",
			in:       Input{},
			expected: expected,
		},
		{
			title:    "EligibleCandidates",
			in:       Input{Candidates: []Candidate{eligibleCandidate("a", true), eligibleCandidate("b", false)}},
			expected: expected,
		},
		{
			title:    "IneligibleCandidates",
			in:       Input{Candidates: []Candidate{ineligibleCandidate("a", true), unavailableCandidate("b", false)}},
			expected: expected,
		},
		{
			title: "ActiveCandidate",
			in: Input{
				Candidates: []Candidate{eligibleCandidate("a", true), eligibleCandidate("b", false)},
				Active:     "b",
			},
			expected: expected,
		},
	})
}

func TestNewRegistry(t *testing.T) {
	t.Parallel()

	t.Run("NoAlgorithms", func(t *testing.T) {
		t.Parallel()
		r := NewRegistry()
		if assert.NotNil(t, r) {
			assert.Empty(t, r.algorithms)
		}
		algorithm, ok := r.Lookup(apiv1.SelectionAlgorithmStrict)
		assert.False(t, ok)
		assert.Nil(t, algorithm)
	})
	t.Run("LookupByName", func(t *testing.T) {
		t.Parallel()
		a := fakeAlgorithm{name: "A", id: "a"}
		b := fakeAlgorithm{name: "B", id: "b"}
		r := NewRegistry(a, b)

		found, ok := r.Lookup("A")
		assert.True(t, ok)
		assert.Equal(t, a, found)
		found, ok = r.Lookup("B")
		assert.True(t, ok)
		assert.Equal(t, b, found)
	})
	t.Run("UnknownName", func(t *testing.T) {
		t.Parallel()
		r := NewRegistry(fakeAlgorithm{name: "A", id: "a"})

		algorithm, ok := r.Lookup("Nope")
		assert.False(t, ok)
		assert.Nil(t, algorithm)
	})
	t.Run("NamesAreCaseSensitive", func(t *testing.T) {
		t.Parallel()
		r := NewRegistry(fakeAlgorithm{name: "A", id: "a"})

		_, ok := r.Lookup("a")
		assert.False(t, ok)
	})
	t.Run("LastAlgorithmWinsForDuplicateNames", func(t *testing.T) {
		t.Parallel()
		r := NewRegistry(
			fakeAlgorithm{name: "A", id: "first"},
			fakeAlgorithm{name: "A", id: "second"},
		)

		assert.Len(t, r.algorithms, 1)
		found, ok := r.Lookup("A")
		if assert.True(t, ok) {
			assert.Equal(t, "second", found.Select(Input{}).Reason)
		}
	})
	t.Run("CustomAlgorithmCanReplaceABuiltIn", func(t *testing.T) {
		t.Parallel()
		r := NewRegistry(Strict{}, fakeAlgorithm{name: apiv1.SelectionAlgorithmStrict, id: "custom"})

		found, ok := r.Lookup(apiv1.SelectionAlgorithmStrict)
		if assert.True(t, ok) {
			assert.Equal(t, "custom", found.Select(Input{}).Reason)
		}
	})
}
