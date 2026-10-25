package health

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// Policy selects which checks to run.
type Policy struct {
	// CheckExpiry checks whether the certificate is expired.
	CheckExpiry bool
	// CheckRevocation checks whether the certificate is revoked.
	CheckRevocation bool
	// CheckCT checks whether the certificate is logged in a Certificate Transparency log.
	CheckCT bool
}

// Default returns a Policy with every checks enabled.
func Default() Policy {
	return Policy{
		CheckExpiry:     true,
		CheckRevocation: true,
		CheckCT:         true,
	}
}

// Result is the outcome of a health check.
type Result struct {
	// Format is the name of the certificate format.
	Format string
	// Parsed reports whether a credential could be parsed out of the Secret.
	Parsed bool
	// Problems lists failures.
	Problems []string
	// Warnings lists checks that are inconclusive, possibly due to network errors.
	// Warnings are not considered fatal.
	Warnings []string
}

// Eligible reports whether a credential was parsed and cleared every check.
func (r Result) Eligible() bool {
	return r.Parsed && len(r.Problems) == 0
}

// Format knows how to recognize and evaluate one kind of certificate credential in a Secret.
type Format interface {
	// Name identifies the format in logs and results.
	Name() string
	// Matches reports whether the Secret holds a credential of this format.
	Matches(secret *corev1.Secret) bool
	// Evaluate evaluates the credential. It is only called after Matches returned true.
	Evaluate(ctx context.Context, secret *corev1.Secret, policy Policy, evalTime time.Time) Result
}

// Evaluator dispatches Secrets to the first matching Format.
type Evaluator struct {
	formats []Format
}

// NewEvaluator returns an Evaluator. Formats are tried in the order given and the first match wins,
// so more specific formats must be listed before more generic ones.
func NewEvaluator(formats ...Format) *Evaluator {
	return &Evaluator{formats: formats}
}

// Evaluate applies the policy to the credential stored in the Secret.
func (e *Evaluator) Evaluate(ctx context.Context, secret *corev1.Secret, policy Policy, evalTime time.Time) Result {
	for _, f := range e.formats {
		if !f.Matches(secret) {
			continue
		}
		res := f.Evaluate(ctx, secret, policy, evalTime)
		res.Format = f.Name()
		return res
	}
	return Result{Problems: []string{"no supported certificate format found in Secret"}}
}
