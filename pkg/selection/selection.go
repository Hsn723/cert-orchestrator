package selection

import (
	"fmt"

	apiv1 "github.com/hsn723/cert-orchestrator/api/v1"
	"github.com/hsn723/cert-orchestrator/pkg/health"
)

const (
	// ReasonEligible means the first eligible certificate was selected.
	ReasonEligible = "Eligible"
	// ReasonForcedPrimary means the primary was selected unconditionally.
	ReasonForcedPrimary = "ForcedPrimary"
	// ReasonPrimaryFallback means the primary was selected because no certificate is eligible.
	ReasonPrimaryFallback = "PrimaryFallback"
	// ReasonNoEligibleCertificate means nothing was selected because no certificate is eligible.
	ReasonNoEligibleCertificate = "NoEligibleCertificate"
	// ReasonManualSelection means selection is left to an external actor.
	ReasonManualSelection = "ManualSelection"
)

// Candidate is a certificate of a CertificateSet.
type Candidate struct {
	// Name is the name of the Certificate resource.
	Name string
	// Primary indicates whether this is the primary candidate.
	Primary bool
	// Available reports whether the candidate's Secret exists and holds a certificate.
	Available bool
	// Evaluated reports whether the Result is conclusive.
	Evaluated bool
	Result    health.Result
}

// Eligible reports whether the candidate is available and cleared every health check.
func (c Candidate) Eligible() bool {
	return c.Available && c.Evaluated && c.Result.Eligible()
}

// Input is the input to the selection algorithm.
type Input struct {
	// Candidates is the list of candidates to choose from.
	Candidates []Candidate
	// Active is the name of the currently active candidate, if any.
	Active string
}

// Decision is the output of the selection algorithm.
type Decision struct {
	// Selected is the name of the candidate to activate, or empty if no change is needed.
	Selected string
	// Unmanaged means the algorithm is not managing the candidate selection.
	Unmanaged bool
	// Reason is a short string describing the reason for the decision.
	Reason string
	// Message is a detailed message explaining the decision.
	Message string
}

// Algorithm is the certificate selection algorithm
type Algorithm interface {
	// Name is the algorithm name.
	Name() apiv1.SelectionAlgorithm
	// HealthPolicy returns the health.Policy used to evaluate candidates.
	HealthPolicy() *health.Policy
	// Select runs the algorithm.
	Select(in Input) Decision
}

// Registry looks up Algorithms by preset name.
type Registry struct {
	algorithms map[apiv1.SelectionAlgorithm]Algorithm
}

// NewRegistry returns a new Registry for the given algorithms.
func NewRegistry(algorithms ...Algorithm) *Registry {
	r := &Registry{algorithms: make(map[apiv1.SelectionAlgorithm]Algorithm)}
	for _, a := range algorithms {
		r.algorithms[a.Name()] = a
	}
	return r
}

// DefaultRegistry returns a Registry with all built-in presets.
func DefaultRegistry() *Registry {
	return NewRegistry(ForcePrimary{}, Strict{}, PrimaryIfNone{}, Manual{})
}

// Lookup returns the Algorithm for the given name.
func (r *Registry) Lookup(name apiv1.SelectionAlgorithm) (Algorithm, bool) {
	a, ok := r.algorithms[name]
	return a, ok
}

// ForcePrimary always selects the primary, no matter what. Health is not evaluated.
type ForcePrimary struct{}

func (ForcePrimary) Name() apiv1.SelectionAlgorithm {
	return apiv1.SelectionAlgorithmForcePrimary
}

func (ForcePrimary) HealthPolicy() *health.Policy { return nil }

func (ForcePrimary) Select(in Input) Decision {
	p, ok := primary(in)
	if !ok {
		return Decision{
			Reason:  ReasonNoEligibleCertificate,
			Message: "no primary certificate found",
		}
	}
	return Decision{
		Selected: p.Name,
		Reason:   ReasonForcedPrimary,
		Message:  fmt.Sprintf("primary certificate %s selected unconditionally", p.Name),
	}
}

// Strict only considers candidates that clear all health checks. If none are eligible, nothing is selected.
type Strict struct{}

func (Strict) Name() apiv1.SelectionAlgorithm {
	return apiv1.SelectionAlgorithmStrict
}

func (Strict) HealthPolicy() *health.Policy {
	return allChecks()
}

func (Strict) Select(in Input) Decision {
	if c, ok := firstEligible(in); ok {
		return Decision{
			Selected: c.Name,
			Reason:   ReasonEligible,
			Message:  fmt.Sprintf("certificate %s selected", c.Name),
		}
	}
	return Decision{
		Reason:  ReasonNoEligibleCertificate,
		Message: "no eligible certificate found",
	}
}

// PrimaryIfNone behaves like Strict, but selects the primary if no certificate is eligible.
type PrimaryIfNone struct{}

func (PrimaryIfNone) Name() apiv1.SelectionAlgorithm {
	return apiv1.SelectionAlgorithmPrimaryIfNone
}

func (PrimaryIfNone) HealthPolicy() *health.Policy {
	return allChecks()
}

func (PrimaryIfNone) Select(in Input) Decision {
	if c, ok := firstEligible(in); ok {
		return Decision{
			Selected: c.Name,
			Reason:   ReasonEligible,
			Message:  fmt.Sprintf("certificate %s selected", c.Name),
		}
	}
	if p, ok := primary(in); ok && p.Available {
		return Decision{
			Selected: p.Name,
			Reason:   ReasonPrimaryFallback,
			Message:  fmt.Sprintf("no eligible certificate found, primary %s selected as fallback", p.Name),
		}
	}
	return Decision{
		Reason:  ReasonNoEligibleCertificate,
		Message: "no eligible certificate found",
	}
}

// Manual never changes the selection. The active candidate is chosen by externally.
type Manual struct{}

func (Manual) Name() apiv1.SelectionAlgorithm {
	return apiv1.SelectionAlgorithmManual
}

func (Manual) HealthPolicy() *health.Policy { return nil }

func (Manual) Select(in Input) Decision {
	return Decision{
		Unmanaged: true,
		Reason:    ReasonManualSelection,
		Message:   "selection is left to an external actor",
	}
}

func allChecks() *health.Policy {
	p := health.Default()
	return &p
}

func primary(in Input) (Candidate, bool) {
	for _, c := range in.Candidates {
		if c.Primary {
			return c, true
		}
	}
	return Candidate{}, false
}

func firstEligible(in Input) (Candidate, bool) {
	var candidate Candidate
	for _, c := range in.Candidates {
		if c.Eligible() {
			if candidate.Name == "" || c.Primary {
				candidate = c
			}
		}
	}
	return candidate, candidate.Name != ""
}
