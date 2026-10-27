/*
Copyright 2026 Hsn723.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/recorder"

	apiv1 "github.com/hsn723/cert-orchestrator/api/v1"
	"github.com/hsn723/cert-orchestrator/pkg/health"
	"github.com/hsn723/cert-orchestrator/pkg/selection"
)

const (
	fieldOwner                = "cert-orchestrator"
	certificateOwnerKey       = ".metadata.controller"
	defaultEvaluationInterval = time.Minute
)

// SecretEvaluator evaluates the health of the certificate credential stored in a Secret.
// It is declared here, where it is consumed, so tests can substitute a fake.
type SecretEvaluator interface {
	Evaluate(ctx context.Context, secret *corev1.Secret, policy health.Policy, evalTime time.Time) health.Result
}

var _ SecretEvaluator = (*health.Evaluator)(nil)

// CertificateSetReconciler reconciles a CertificateSet object
type CertificateSetReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	Recorder   recorder.EventRecorder
	Evaluator  SecretEvaluator
	Algorithms *selection.Registry
}

// member ties a generated Certificate to its possibly not yet existing Secret.
type member struct {
	target    apiv1.CertificateTarget
	secret    *corev1.Secret
	available bool
	ready     bool
}

type conditionState struct {
	status  v1.ConditionStatus
	reason  string
	message string
}

// +kubebuilder:rbac:groups=cert-orchestrator.atelierhsn.com,resources=certificatesets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cert-orchestrator.atelierhsn.com,resources=certificatesets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=cert-orchestrator.atelierhsn.com,resources=certificatesets/finalizers,verbs=update
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificates,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *CertificateSetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	cs := &apiv1.CertificateSet{}
	if err := r.Get(ctx, req.NamespacedName, cs); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !cs.DeletionTimestamp.IsZero() {
		// Certificates and the canonical Secret are garbage collected through their owner references
		return ctrl.Result{}, nil
	}
	return r.reconcile(ctx, cs)
}

func (r *CertificateSetReconciler) reconcile(ctx context.Context, cs *apiv1.CertificateSet) (ctrl.Result, error) {
	logger := logf.FromContext(ctx)
	base := cs.DeepCopy()
	cs.Status.ObservedGeneration = cs.Generation

	algorithm, ok := r.Algorithms.Lookup(cs.Spec.SelectionAlgorithm)
	if !ok {
		msg := fmt.Sprintf("unknown selection algorithm %q", cs.Spec.SelectionAlgorithm)
		setCondition(cs, apiv1.CertificateSetConditionTypeSelected, v1.ConditionFalse, "UnknownSelectionAlgorithm", msg)
		return ctrl.Result{}, r.patchStatus(ctx, cs, base)
	}

	targets := cs.Targets()
	if err := r.reconcileCertificates(ctx, cs, targets); err != nil {
		logger.Error(err, "failed to reconcile Certificates")
		r.Recorder.Eventf(cs, nil, corev1.EventTypeWarning, "CertificateSyncFailed", "Sync", "%s", err.Error())
		setCondition(cs, apiv1.CertificateSetConditionTypeReady, v1.ConditionFalse, "CertificateSyncFailed", err.Error())
		if statusErr := r.patchStatus(ctx, cs, base); statusErr != nil {
			return ctrl.Result{}, statusErr
		}
		return ctrl.Result{}, err
	}

	members, err := r.gather(ctx, cs, targets)
	if err != nil {
		logger.Error(err, "failed to gather Secrets")
		return ctrl.Result{}, err
	}

	evaluationTime := time.Now()
	hasEvaluated := algorithm.HealthPolicy() != nil
	candidates := r.evaluate(ctx, cs, algorithm, members, evaluationTime)
	if hasEvaluated {
		cs.Status.LastEvaluationTime = &v1.Time{Time: evaluationTime}
	}

	active := activeNames(members)
	current := ""
	if len(active) == 1 {
		current = active[0]
	}
	decision := algorithm.Select(selection.Input{
		Candidates: candidates,
		Active:     current,
	})

	effective, selected, err := r.applyDecision(ctx, cs, members, decision, active)
	if err != nil {
		logger.Error(err, "failed to update active Secret annotations")
		r.Recorder.Eventf(cs, nil, corev1.EventTypeWarning, "SecretActivationFailed", "Activation", "%s", err.Error())
		return ctrl.Result{}, err
	}
	ready, err := r.canonicalState(ctx, cs, members, effective)
	if err != nil {
		return ctrl.Result{}, err
	}

	cs.Status.ActiveCertificate = effective
	setCondition(cs, apiv1.CertificateSetConditionTypeSelected, selected.status, selected.reason, selected.message)
	setCondition(cs, apiv1.CertificateSetConditionTypeReady, ready.status, ready.reason, ready.message)
	r.setCertificatesReadyCondition(cs, members)

	result := ctrl.Result{}
	if hasEvaluated {
		result.RequeueAfter = nextEvaluationTime(cs, evaluationTime)
	}
	return result, r.patchStatus(ctx, cs, base)
}

func (r *CertificateSetReconciler) patchStatus(ctx context.Context, cs, base *apiv1.CertificateSet) error {
	return r.Status().Patch(ctx, cs, client.MergeFrom(base))
}

func (r *CertificateSetReconciler) reconcileCertificates(ctx context.Context, cs *apiv1.CertificateSet, targets []apiv1.CertificateTarget) error {
	logger := logf.FromContext(ctx)

	desired := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		desired[t.Name] = struct{}{}
		if err := r.applyCertificate(ctx, cs, t); err != nil {
			return fmt.Errorf("failed to apply Certificate %q: %w", t.Name, err)
		}
	}
	owned := &cmapi.CertificateList{}
	listOpts := []client.ListOption{
		client.InNamespace(cs.Namespace),
		client.MatchingFields{certificateOwnerKey: cs.Name},
	}
	if err := r.List(ctx, owned, listOpts...); err != nil {
		return err
	}
	for i := range owned.Items {
		if _, ok := desired[owned.Items[i].Name]; ok {
			continue
		}
		if err := r.Delete(ctx, &owned.Items[i]); err != nil {
			return fmt.Errorf("failed to delete Certificate %q: %w", owned.Items[i].Name, err)
		}
		logger.Info("deleted Certificate of a removed issuer", "name", owned.Items[i].Name)
	}
	return nil
}

func (r *CertificateSetReconciler) applyCertificate(ctx context.Context, cs *apiv1.CertificateSet, t apiv1.CertificateTarget) error {
	spec := cs.Spec.Template.Spec.DeepCopy()
	spec.IssuerRef = t.IssuerRef
	spec.SecretName = t.Name
	spec.SecretTemplate = secretTemplateFor(spec.SecretTemplate, cs, t)

	cert := &cmapi.Certificate{
		ObjectMeta: v1.ObjectMeta{
			Name:      t.Name,
			Namespace: cs.Namespace,
		},
		Spec: *spec,
	}
	gvk, err := apiutil.GVKForObject(cert, r.Scheme)
	if err != nil {
		return err
	}
	cert.SetGroupVersionKind(gvk)
	if err := controllerutil.SetControllerReference(cs, cert, r.Scheme); err != nil {
		return err
	}

	// Applying a typed object would send zero-valued status and timestamps, so convert and strip them.
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(cert)
	if err != nil {
		return err
	}
	u := &unstructured.Unstructured{Object: obj}
	unstructured.RemoveNestedField(u.Object, "status")
	unstructured.RemoveNestedField(u.Object, "metadata", "creationTimestamp")
	applyConfig := client.ApplyConfigurationFromUnstructured(u)
	return r.Apply(ctx, applyConfig, client.FieldOwner(fieldOwner), client.ForceOwnership)
}

func (r *CertificateSetReconciler) gather(ctx context.Context, cs *apiv1.CertificateSet, targets []apiv1.CertificateTarget) ([]member, error) {
	members := make([]member, 0, len(targets))
	for _, t := range targets {
		m := member{target: t}
		key := client.ObjectKey{
			Name:      t.Name,
			Namespace: cs.Namespace,
		}
		secret := &corev1.Secret{}
		if err := r.Get(ctx, key, secret); client.IgnoreNotFound(err) != nil {
			return nil, err
		}
		m.secret = secret
		m.available = len(secret.Data[corev1.TLSCertKey]) > 0

		cert := &cmapi.Certificate{}
		if err := r.Get(ctx, key, cert); client.IgnoreNotFound(err) != nil {
			return nil, err
		}
		m.ready = certificateReady(cert)
		members = append(members, m)
	}
	return members, nil
}

func (r *CertificateSetReconciler) evaluate(ctx context.Context, cs *apiv1.CertificateSet, algorithm selection.Algorithm, members []member, evaluationTime time.Time) []selection.Candidate {
	logger := logf.FromContext(ctx)
	policy := algorithm.HealthPolicy()

	candidates := make([]selection.Candidate, 0, len(members))
	for _, m := range members {
		c := selection.Candidate{
			Name:      m.target.Name,
			Primary:   m.target.Priority == apiv1.CertificatePriorityPrimary,
			Available: m.available,
		}
		if policy != nil && m.available {
			c.Result = r.Evaluator.Evaluate(ctx, m.secret, *policy, evaluationTime)
			c.Evaluated = true
			for _, w := range c.Result.Warnings {
				logger.Info("inconclusive health check", "certificateSet", cs.Name, "secret", m.target.Name, "format", c.Result.Format, "warning", w)
			}
		}
		candidates = append(candidates, c)
	}
	return candidates
}

func (r *CertificateSetReconciler) applyDecision(ctx context.Context, cs *apiv1.CertificateSet, members []member, decision selection.Decision, active []string) (string, conditionState, error) {
	current := ""
	if len(active) == 1 {
		current = active[0]
	}
	conflict := conditionState{
		v1.ConditionFalse,
		"MultipleActiveSecrets",
		fmt.Sprintf("multiple Secrets are active: %v", active),
	}
	switch {
	case decision.Unmanaged:
		switch {
		case len(active) > 1:
			return "", conflict, nil
		case current == "":
			return "", conditionState{
				v1.ConditionFalse,
				"NoActiveSecret",
				"no Secret is active and the selection algorithm is unmanaged",
			}, nil
		default:
			return current, conditionState{
				v1.ConditionTrue,
				decision.Reason,
				fmt.Sprintf("Secret %q is manually selected", current),
			}, nil
		}
	case decision.Selected == "":
		if len(active) > 1 {
			return "", conflict, nil
		}
		return current, conditionState{
			v1.ConditionFalse,
			decision.Reason,
			decision.Message,
		}, nil
	}

	target := findMember(members, decision.Selected)
	if target == nil || !target.available {
		if len(active) > 1 {
			return "", conflict, nil
		}
		return current, conditionState{
			v1.ConditionFalse,
			"AwaitingSecret",
			fmt.Sprintf("selected certificate %q has no Secret yet", decision.Selected),
		}, nil
	}

	if err := r.activate(ctx, cs, members, target); err != nil {
		return current, conditionState{}, err
	}
	if current != target.target.Name {
		r.recordSwitch(cs, current, target, decision)
	}
	return target.target.Name, conditionState{
		v1.ConditionTrue,
		decision.Reason,
		decision.Message,
	}, nil
}

// activate makes target the only active Secret. Others are deactivated first so that the set never has
// two active Secrets at the same time.
func (r *CertificateSetReconciler) activate(ctx context.Context, cs *apiv1.CertificateSet, members []member, target *member) error {
	for i := range members {
		m := &members[i]
		if m.secret == nil || m.target.Name == target.target.Name || !isActive(m.secret) {
			continue
		}
		if err := r.patchAnnotations(ctx, m.secret, nil, apiv1.CertificateSetActiveAnnotation); err != nil {
			return fmt.Errorf("failed to deactivate Secret %q: %w", m.target.Name, err)
		}
	}
	// The identity annotations are normally set through the Certificate's secretTemplate. Setting them
	// here as well means activation never depends on cert-manager having propagated them yet.
	set := map[string]string{
		apiv1.CertificateSetActiveAnnotation:   "true",
		apiv1.CertificateSetNameAnnotation:     cs.Name,
		apiv1.CertificateSetPriorityAnnotation: string(target.target.Priority),
	}
	if err := r.patchAnnotations(ctx, target.secret, set); err != nil {
		return fmt.Errorf("failed to activate Secret %q: %w", target.target.Name, err)
	}
	return nil
}

func (r *CertificateSetReconciler) patchAnnotations(ctx context.Context, secret *corev1.Secret, set map[string]string, unset ...string) error {
	orig := secret.DeepCopy()
	if secret.Annotations == nil {
		secret.Annotations = map[string]string{}
	}
	maps.Copy(secret.Annotations, set)
	for _, k := range unset {
		delete(secret.Annotations, k)
	}
	if maps.Equal(orig.Annotations, secret.Annotations) {
		return nil
	}
	return r.Patch(ctx, secret, client.MergeFrom(orig))
}

func (r *CertificateSetReconciler) recordSwitch(cs *apiv1.CertificateSet, from string, to *member, decision selection.Decision) {
	switch {
	case from == "":
		r.Recorder.Eventf(cs, nil, corev1.EventTypeNormal, "Activated", "Activation", "Activated %q: %s", to.target.Name, decision.Message)
	case to.target.Priority == apiv1.CertificatePriorityPrimary:
		r.Recorder.Eventf(cs, nil, corev1.EventTypeNormal, "FailedBack", "Activation", "Switched from %q back to the primary %q: %s", from, to.target.Name, decision.Message)
	default:
		r.Recorder.Eventf(cs, nil, corev1.EventTypeWarning, "FailedOver", "Activation", "Switched from %q to %q: %s", from, to.target.Name, decision.Message)
	}
}

// canonicalState reports whether the canonical Secret reflects the active Secret. The canonical Secret is
// written by the Secret controller, this controller only observes it.
func (r *CertificateSetReconciler) canonicalState(ctx context.Context, cs *apiv1.CertificateSet, members []member, effective string) (conditionState, error) {
	if effective == "" {
		return conditionState{
			v1.ConditionFalse,
			"NoActiveSecret",
			"no certificate is active",
		}, nil
	}
	source := findMember(members, effective)
	if source == nil || source.secret == nil {
		return conditionState{
			v1.ConditionFalse,
			"SourceUnavailable",
			fmt.Sprintf("Secret %q does not exist", effective),
		}, nil
	}

	canonical := &corev1.Secret{}
	err := r.Get(ctx, client.ObjectKey{Name: cs.Name, Namespace: cs.Namespace}, canonical)
	if apierrors.IsNotFound(err) {
		return conditionState{
			v1.ConditionFalse,
			"CanonicalSecretPending",
			fmt.Sprintf("canonical Secret %q does not exist yet", cs.Name),
		}, nil
	}
	if err != nil {
		return conditionState{}, err
	}
	if !v1.IsControlledBy(canonical, cs) {
		return conditionState{
			v1.ConditionFalse,
			"CanonicalSecretNotOwned",
			fmt.Sprintf("canonical Secret %q found but it is not owned by this CertificateSet", cs.Name),
		}, nil
	}

	isInSync := canonical.Annotations[apiv1.CertificateSetSourceSecretAnnotation] == effective &&
		equality.Semantic.DeepEqual(canonical.Data, source.secret.Data)
	if !isInSync {
		return conditionState{
			v1.ConditionFalse,
			"CanonicalSecretOutOfSync",
			fmt.Sprintf("canonical Secret %q is not in sync with the active Secret %q", cs.Name, effective),
		}, nil
	}
	return conditionState{
		v1.ConditionTrue,
		"Synced",
		fmt.Sprintf("Secret %q synced from %q", cs.Name, effective),
	}, nil
}

func (r *CertificateSetReconciler) setCertificatesReadyCondition(cs *apiv1.CertificateSet, members []member) {
	var notReady []string
	for _, m := range members {
		if !m.ready {
			notReady = append(notReady, m.target.Name)
		}
	}
	if len(notReady) == 0 {
		setCondition(cs, apiv1.CertificateSetConditionTypeCertificatesReady, v1.ConditionTrue, "AllCertificatesReady", "all Certificates are ready")
		return
	}
	setCondition(cs, apiv1.CertificateSetConditionTypeCertificatesReady, v1.ConditionFalse, "CertificatesNotReady", fmt.Sprintf("the following Certificates are not ready: %s", strings.Join(notReady, ", ")))
}

func secretTemplateFor(cst *cmapi.CertificateSecretTemplate, cs *apiv1.CertificateSet, t apiv1.CertificateTarget) *cmapi.CertificateSecretTemplate {
	tpl := &cmapi.CertificateSecretTemplate{Annotations: map[string]string{}}
	if cst != nil {
		maps.Copy(tpl.Annotations, cst.Annotations)
		tpl.Labels = maps.Clone(cst.Labels)
	}
	delete(tpl.Annotations, apiv1.CertificateSetActiveAnnotation)
	tpl.Annotations[apiv1.CertificateSetNameAnnotation] = cs.Name
	tpl.Annotations[apiv1.CertificateSetPriorityAnnotation] = string(t.Priority)
	return tpl
}

func activeNames(members []member) []string {
	var names []string
	for _, m := range members {
		if m.secret != nil && isActive(m.secret) {
			names = append(names, m.target.Name)
		}
	}
	return names
}

func certificateReady(cert *cmapi.Certificate) bool {
	for _, c := range cert.Status.Conditions {
		if c.Type == cmapi.CertificateConditionReady {
			return c.Status == cmmeta.ConditionTrue
		}
	}
	return false
}

func findMember(members []member, name string) *member {
	for i := range members {
		if members[i].target.Name == name {
			return &members[i]
		}
	}
	return nil
}

func nextEvaluationTime(cs *apiv1.CertificateSet, lastEval time.Time) time.Duration {
	interval := defaultEvaluationInterval
	if cs.Spec.EvaluationInterval != nil && cs.Spec.EvaluationInterval.Duration > 0 {
		interval = cs.Spec.EvaluationInterval.Duration
	}
	if cs.Status.LastEvaluationTime == nil {
		return interval
	}
	remaining := cs.Status.LastEvaluationTime.Add(interval).Sub(lastEval)
	if remaining < time.Second {
		return interval
	}
	return remaining
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertificateSetReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	err := mgr.GetFieldIndexer().IndexField(ctx, &cmapi.Certificate{}, certificateOwnerKey, func(rawObj client.Object) []string {
		owner := controllingCertificateSetName(rawObj)
		if owner == "" {
			return nil
		}
		return []string{owner}
	})
	if err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&apiv1.CertificateSet{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Named("certificateset").
		Owns(&cmapi.Certificate{}).
		Owns(&corev1.Secret{}).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.findCertificateSetForSecret)).
		Complete(r)
}

func (r *CertificateSetReconciler) findCertificateSetForSecret(_ context.Context, secret client.Object) []reconcile.Request {
	name := secret.GetAnnotations()[apiv1.CertificateSetNameAnnotation]
	if name == "" {
		return nil
	}
	return []reconcile.Request{
		{
			NamespacedName: client.ObjectKey{
				Name:      name,
				Namespace: secret.GetNamespace(),
			},
		},
	}
}
