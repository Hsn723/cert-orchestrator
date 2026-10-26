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
	"sync"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	apiv1 "github.com/hsn723/cert-orchestrator/api/v1"
	"github.com/hsn723/cert-orchestrator/pkg/health"
	"github.com/hsn723/cert-orchestrator/pkg/selection"
)

// fakeEvaluator stands in for the network: Secrets are eligible unless a test says otherwise.
type fakeEvaluator struct {
	mu      sync.Mutex
	results map[string]health.Result
	calls   map[string]int
}

var _ SecretEvaluator = &fakeEvaluator{}

func newFakeEvaluator() *fakeEvaluator {
	return &fakeEvaluator{results: map[string]health.Result{}, calls: map[string]int{}}
}

func (f *fakeEvaluator) Evaluate(_ context.Context, secret *corev1.Secret, _ health.Policy, _ time.Time) health.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[secret.Name]++
	if res, ok := f.results[secret.Name]; ok {
		return res
	}
	return health.Result{Format: "fake", Parsed: true}
}

func (f *fakeEvaluator) setProblem(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.results[name] = health.Result{Format: "fake", Parsed: true, Problems: []string{"expired"}}
}

func (f *fakeEvaluator) setEligible(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.results, name)
}

func (f *fakeEvaluator) callCount(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[name]
}

func waitForCertificate(ctx context.Context, name, namespace string) *cmapi.Certificate {
	GinkgoHelper()
	cert := &cmapi.Certificate{}
	Eventually(k8sClient.Get).WithArguments(ctx, client.ObjectKey{Name: name, Namespace: namespace}, cert).
		WithTimeout(eventuallyTimeout).Should(Succeed())
	return cert
}

func updateSecret(ctx context.Context, namespace, name string, mutate func(*corev1.Secret)) {
	GinkgoHelper()
	Eventually(func() error {
		s, err := getSecret(ctx, name, namespace)
		if err != nil {
			return err
		}
		mutate(s)
		return k8sClient.Update(ctx, s)
	}).WithTimeout(eventuallyTimeout).Should(Succeed())
}

// createMembers creates the Secrets of the primary and the fallback of the set, as cert-manager would.
func createMembers(ctx context.Context, cs *apiv1.CertificateSet) (primary, fallback *corev1.Secret) {
	GinkgoHelper()
	targets := cs.Targets()
	primary = createTLSSecret(ctx, cs.Namespace, targets[0].Name, memberAnnotations(cs.Name))
	fallback = createTLSSecret(ctx, cs.Namespace, targets[1].Name, memberAnnotations(cs.Name))
	return primary, fallback
}

func expectCondition(ctx context.Context, cs *apiv1.CertificateSet, condType string, status metav1.ConditionStatus, reason string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		got := &apiv1.CertificateSet{}
		g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cs), got)).To(Succeed())
		cond := meta.FindStatusCondition(got.Status.Conditions, condType)
		g.Expect(cond).NotTo(BeNil())
		g.Expect(cond.Status).To(Equal(status))
		g.Expect(cond.Reason).To(Equal(reason))
	}).WithTimeout(eventuallyTimeout).Should(Succeed())
}

func expectActive(ctx context.Context, cs *apiv1.CertificateSet, name string) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		got := &apiv1.CertificateSet{}
		g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cs), got)).To(Succeed())
		g.Expect(got.Status.ActiveCertificate).To(Equal(name))
		for _, target := range cs.Targets() {
			s, err := getSecret(ctx, target.Name, cs.Namespace)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(isActive(s)).To(Equal(target.Name == name), target.Name)
		}
	}).WithTimeout(eventuallyTimeout).Should(Succeed())
}

var _ = Describe("CertificateSet controller", func() {
	ctx := context.Background()
	var stopFunc func()
	var events *fakeRecorder
	var evaluator *fakeEvaluator

	BeforeEach(func() {
		mgr, err := ctrl.NewManager(cfg, ctrl.Options{
			Scheme:         scheme.Scheme,
			LeaderElection: false,
			Metrics:        metricsserver.Options{BindAddress: "0"},
			Controller: config.Controller{
				SkipNameValidation: ptr.To(true),
			},
		})
		Expect(err).NotTo(HaveOccurred())
		events = &fakeRecorder{}
		evaluator = newFakeEvaluator()
		certificateSetReconciler := &CertificateSetReconciler{
			Client:     mgr.GetClient(),
			Scheme:     mgr.GetScheme(),
			Recorder:   events,
			Evaluator:  evaluator,
			Algorithms: selection.DefaultRegistry(),
		}
		Expect(certificateSetReconciler.SetupWithManager(ctx, mgr)).To(Succeed())
		// the Secret controller copies the active Secret, which is what makes a set Ready
		secretReconciler := &SecretReconciler{
			Client:   mgr.GetClient(),
			Scheme:   mgr.GetScheme(),
			Recorder: events,
		}
		Expect(secretReconciler.SetupWithManager(ctx, mgr)).To(Succeed())

		mgrCtx, cancel := context.WithCancel(ctx)
		stopFunc = cancel
		go func() {
			err := mgr.Start(mgrCtx)
			if err != nil {
				panic(err)
			}
		}()
		time.Sleep(100 * time.Millisecond)
	})

	AfterEach(func() {
		stopFunc()
		time.Sleep(100 * time.Millisecond)
	})

	// newSet creates a CertificateSet with one fallback in a new namespace, evaluated every second.
	newSet := func(algorithm apiv1.SelectionAlgorithm) (cs *apiv1.CertificateSet, primary, fallback string) {
		namespace := createTestNamespace(ctx)
		cs = buildCertificateSet(uuid.NewString(), namespace, algorithm, "fallback")
		cs.Spec.EvaluationInterval = &metav1.Duration{Duration: time.Second}
		Expect(k8sClient.Create(ctx, cs)).To(Succeed())
		targets := cs.Targets()
		return cs, targets[0].Name, targets[1].Name
	}

	It("should generate a Certificate per issuer from the template", func() {
		namespace := createTestNamespace(ctx)
		cs := buildCertificateSet(uuid.NewString(), namespace, apiv1.SelectionAlgorithmManual, "fallback")
		cs.Spec.Template.Spec.SecretTemplate = &cmapi.CertificateSecretTemplate{
			// the active annotation is managed by the controller and must never come from the template
			Annotations: map[string]string{"custom": "value", apiv1.CertificateSetActiveAnnotation: "true"},
			Labels:      map[string]string{"team": "a"},
		}
		Expect(k8sClient.Create(ctx, cs)).To(Succeed())

		for _, target := range cs.Targets() {
			cert := waitForCertificate(ctx, target.Name, namespace)
			Expect(cert.Spec.SecretName).To(Equal(target.Name))
			Expect(cert.Spec.IssuerRef.Name).To(Equal(target.IssuerRef.Name))
			Expect(cert.Spec.DNSNames).To(Equal([]string{"example.com"}))
			Expect(metav1.IsControlledBy(cert, cs)).To(BeTrue())
			Expect(cert.Spec.SecretTemplate).NotTo(BeNil())
			Expect(cert.Spec.SecretTemplate.Annotations).To(And(
				HaveKeyWithValue(apiv1.CertificateSetNameAnnotation, cs.Name),
				HaveKeyWithValue(apiv1.CertificateSetPriorityAnnotation, string(target.Priority)),
				HaveKeyWithValue("custom", "value"),
				Not(HaveKey(apiv1.CertificateSetActiveAnnotation)),
			))
			Expect(cert.Spec.SecretTemplate.Labels).To(HaveKeyWithValue("team", "a"))
		}
	})

	It("should apply template changes and remove the Certificates of removed issuers", func() {
		cs, primary, fallback := newSet(apiv1.SelectionAlgorithmManual)
		waitForCertificate(ctx, primary, cs.Namespace)
		waitForCertificate(ctx, fallback, cs.Namespace)

		By("replacing the fallback issuer and changing the template")
		Eventually(func() error {
			if err := k8sClient.Get(ctx, client.ObjectKeyFromObject(cs), cs); err != nil {
				return err
			}
			cs.Spec.Issuers.Fallbacks = []cmmeta.IssuerReference{{Name: "other"}}
			cs.Spec.Template.Spec.DNSNames = []string{"example.org"}
			return k8sClient.Update(ctx, cs)
		}).WithTimeout(eventuallyTimeout).Should(Succeed())

		other := waitForCertificate(ctx, cs.Targets()[1].Name, cs.Namespace)
		Expect(other.Spec.IssuerRef.Name).To(Equal("other"))
		Eventually(func(g Gomega) {
			err := k8sClient.Get(ctx, client.ObjectKey{Name: fallback, Namespace: cs.Namespace}, &cmapi.Certificate{})
			g.Expect(apierrors.IsNotFound(err)).To(BeTrue())
			cert := &cmapi.Certificate{}
			g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: primary, Namespace: cs.Namespace}, cert)).To(Succeed())
			g.Expect(cert.Spec.DNSNames).To(Equal([]string{"example.org"}))
		}).WithTimeout(eventuallyTimeout).Should(Succeed())
	})

	It("should report the readiness of the Certificates", func() {
		cs, _, _ := newSet(apiv1.SelectionAlgorithmManual)
		expectCondition(ctx, cs, apiv1.CertificateSetConditionTypeCertificatesReady, metav1.ConditionFalse, "CertificatesNotReady")

		By("marking the Certificates as ready, as cert-manager would")
		for _, target := range cs.Targets() {
			waitForCertificate(ctx, target.Name, cs.Namespace)
			Eventually(func(g Gomega) {
				cert := &cmapi.Certificate{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKey{Name: target.Name, Namespace: cs.Namespace}, cert)).To(Succeed())
				cert.Status.Conditions = []cmapi.CertificateCondition{
					{Type: cmapi.CertificateConditionReady, Status: cmmeta.ConditionTrue},
				}
				g.Expect(k8sClient.Status().Update(ctx, cert)).To(Succeed())
			}).WithTimeout(eventuallyTimeout).Should(Succeed())
		}
		expectCondition(ctx, cs, apiv1.CertificateSetConditionTypeCertificatesReady, metav1.ConditionTrue, "AllCertificatesReady")
	})

	It("should leave the selection of a Manual set to the user", func() {
		cs, primary, fallback := newSet(apiv1.SelectionAlgorithmManual)
		_, f := createMembers(ctx, cs)

		By("waiting for the controller to report that nothing is selected")
		expectCondition(ctx, cs, apiv1.CertificateSetConditionTypeSelected, metav1.ConditionFalse, "NoActiveSecret")
		expectActive(ctx, cs, "")
		expectNoCanonical(ctx, cs)
		got := &apiv1.CertificateSet{}
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cs), got)).To(Succeed())
		Expect(got.Status.ObservedGeneration).To(Equal(got.Generation))
		Expect(evaluator.callCount(primary)).To(BeZero())

		By("activating a Secret manually")
		updateSecret(ctx, cs.Namespace, fallback, func(s *corev1.Secret) { s.Annotations = activeAnnotations(cs.Name) })
		expectCondition(ctx, cs, apiv1.CertificateSetConditionTypeSelected, metav1.ConditionTrue, selection.ReasonManualSelection)
		expectActive(ctx, cs, fallback)
		expectCanonicalData(ctx, cs, f.Data)
		expectCondition(ctx, cs, apiv1.CertificateSetConditionTypeReady, metav1.ConditionTrue, "Synced")
		Expect(evaluator.callCount(fallback)).To(BeZero())
	})

	It("should refuse to pick between multiple active Secrets", func() {
		cs, primary, fallback := newSet(apiv1.SelectionAlgorithmManual)
		targets := cs.Targets()
		p := createTLSSecret(ctx, cs.Namespace, targets[0].Name, activeAnnotations(cs.Name))
		createTLSSecret(ctx, cs.Namespace, targets[1].Name, activeAnnotations(cs.Name))

		expectCondition(ctx, cs, apiv1.CertificateSetConditionTypeSelected, metav1.ConditionFalse, "MultipleActiveSecrets")
		Eventually(events.has).WithTimeout(eventuallyTimeout).
			WithArguments(corev1.EventTypeWarning, "MultipleActiveSecrets").Should(BeTrue())
		expectNoCanonical(ctx, cs)

		By("deactivating one of them")
		updateSecret(ctx, cs.Namespace, fallback, func(s *corev1.Secret) { s.Annotations = memberAnnotations(cs.Name) })
		expectCondition(ctx, cs, apiv1.CertificateSetConditionTypeSelected, metav1.ConditionTrue, selection.ReasonManualSelection)
		expectActive(ctx, cs, primary)
		expectCanonicalData(ctx, cs, p.Data)
	})

	It("should always select the primary of a ForcePrimary set", func() {
		cs, primary, _ := newSet(apiv1.SelectionAlgorithmForcePrimary)

		By("waiting for the primary Secret")
		expectCondition(ctx, cs, apiv1.CertificateSetConditionTypeSelected, metav1.ConditionFalse, "AwaitingSecret")

		By("creating the Secrets")
		p, _ := createMembers(ctx, cs)
		expectActive(ctx, cs, primary)
		expectCanonicalData(ctx, cs, p.Data)
		expectCondition(ctx, cs, apiv1.CertificateSetConditionTypeSelected, metav1.ConditionTrue, selection.ReasonForcedPrimary)
		expectCondition(ctx, cs, apiv1.CertificateSetConditionTypeReady, metav1.ConditionTrue, "Synced")
		Eventually(events.has).WithTimeout(eventuallyTimeout).
			WithArguments(corev1.EventTypeNormal, "Activated").Should(BeTrue())

		By("checking that the controller labelled the active Secret and never evaluated it")
		active, err := getSecret(ctx, primary, cs.Namespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(active.Annotations).To(And(
			HaveKeyWithValue(apiv1.CertificateSetNameAnnotation, cs.Name),
			HaveKeyWithValue(apiv1.CertificateSetPriorityAnnotation, string(apiv1.CertificatePriorityPrimary)),
		))
		got := &apiv1.CertificateSet{}
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cs), got)).To(Succeed())
		Expect(got.Status.LastEvaluationTime).To(BeNil())
		Expect(evaluator.callCount(primary)).To(BeZero())
	})

	It("should fail over and back with a Strict set", func() {
		cs, primary, fallback := newSet(apiv1.SelectionAlgorithmStrict)
		p, f := createMembers(ctx, cs)

		By("selecting the primary while it is eligible")
		expectActive(ctx, cs, primary)
		expectCanonicalData(ctx, cs, p.Data)
		expectCondition(ctx, cs, apiv1.CertificateSetConditionTypeReady, metav1.ConditionTrue, "Synced")

		By("failing over when the primary stops being eligible")
		evaluator.setProblem(primary)
		expectActive(ctx, cs, fallback)
		expectCanonicalData(ctx, cs, f.Data)
		Eventually(events.has).WithTimeout(eventuallyTimeout).
			WithArguments(corev1.EventTypeWarning, "FailedOver").Should(BeTrue())

		By("failing back when the primary is eligible again")
		evaluator.setEligible(primary)
		expectActive(ctx, cs, primary)
		expectCanonicalData(ctx, cs, p.Data)
		expectCondition(ctx, cs, apiv1.CertificateSetConditionTypeReady, metav1.ConditionTrue, "Synced")
		Eventually(events.has).WithTimeout(eventuallyTimeout).
			WithArguments(corev1.EventTypeNormal, "FailedBack").Should(BeTrue())
	})

	It("should select nothing in a Strict set without eligible certificate, and keep evaluating", func() {
		cs, primary, fallback := newSet(apiv1.SelectionAlgorithmStrict)
		evaluator.setProblem(primary)
		evaluator.setProblem(fallback)
		createMembers(ctx, cs)

		expectCondition(ctx, cs, apiv1.CertificateSetConditionTypeSelected, metav1.ConditionFalse, selection.ReasonNoEligibleCertificate)
		expectActive(ctx, cs, "")
		expectNoCanonical(ctx, cs)

		By("evaluating again after the evaluation interval")
		var first metav1.Time
		Eventually(func(g Gomega) {
			got := &apiv1.CertificateSet{}
			g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cs), got)).To(Succeed())
			g.Expect(got.Status.LastEvaluationTime).NotTo(BeNil())
			first = *got.Status.LastEvaluationTime
		}).WithTimeout(eventuallyTimeout).Should(Succeed())
		Eventually(func(g Gomega) {
			got := &apiv1.CertificateSet{}
			g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(cs), got)).To(Succeed())
			g.Expect(got.Status.LastEvaluationTime.After(first.Time)).To(BeTrue())
		}).WithTimeout(eventuallyTimeout).Should(Succeed())
	})

	It("should fall back to the primary of a PrimaryIfNone set", func() {
		cs, primary, fallback := newSet(apiv1.SelectionAlgorithmPrimaryIfNone)
		evaluator.setProblem(primary)
		evaluator.setProblem(fallback)
		p, f := createMembers(ctx, cs)

		By("selecting the primary although nothing is eligible")
		expectActive(ctx, cs, primary)
		expectCanonicalData(ctx, cs, p.Data)
		expectCondition(ctx, cs, apiv1.CertificateSetConditionTypeSelected, metav1.ConditionTrue, selection.ReasonPrimaryFallback)

		By("moving to the fallback as soon as it is eligible")
		evaluator.setEligible(fallback)
		expectActive(ctx, cs, fallback)
		expectCanonicalData(ctx, cs, f.Data)
		expectCondition(ctx, cs, apiv1.CertificateSetConditionTypeSelected, metav1.ConditionTrue, selection.ReasonEligible)
	})

	It("should report a canonical Secret it does not own", func() {
		cs, primary, _ := newSet(apiv1.SelectionAlgorithmForcePrimary)
		existing := createTLSSecret(ctx, cs.Namespace, cs.Name, nil)
		createMembers(ctx, cs)

		expectActive(ctx, cs, primary)
		expectCondition(ctx, cs, apiv1.CertificateSetConditionTypeReady, metav1.ConditionFalse, "CanonicalSecretNotOwned")
		Eventually(events.has).WithTimeout(eventuallyTimeout).
			WithArguments(corev1.EventTypeWarning, "CanonicalConflict").Should(BeTrue())
		canonical, err := getSecret(ctx, cs.Name, cs.Namespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(canonical.Data).To(Equal(existing.Data))
	})
})
