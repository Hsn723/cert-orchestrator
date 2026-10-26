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
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	apiv1 "github.com/hsn723/cert-orchestrator/api/v1"
)

func expectCanonicalData(ctx context.Context, cs *apiv1.CertificateSet, data map[string][]byte) {
	GinkgoHelper()
	Eventually(func(g Gomega) {
		canonical, err := getSecret(ctx, cs.Name, cs.Namespace)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(canonical.Data).To(Equal(data))
	}).WithTimeout(eventuallyTimeout).Should(Succeed())
}

func expectNoCanonical(ctx context.Context, cs *apiv1.CertificateSet) {
	GinkgoHelper()
	Consistently(func() error {
		_, err := getSecret(ctx, cs.Name, cs.Namespace)
		return err
	}).WithTimeout(consistentlyDuration).ShouldNot(Succeed())
}

var _ = Describe("Secret Controller", func() {
	ctx := context.Background()
	var stopFunc func()
	var events *fakeRecorder
	var mgrClient client.Client

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
		mgrClient = mgr.GetClient()
		reconciler := &SecretReconciler{
			Client:   mgr.GetClient(),
			Scheme:   mgr.GetScheme(),
			Recorder: events,
		}
		Expect(reconciler.SetupWithManager(ctx, mgr)).To(Succeed())

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

	// newSet creates a CertificateSet with one fallback in a new namespace, and returns the names of the
	// Secrets of its primary and fallback members. The controller never retries a Secret whose set it cannot
	// find, so the set must be visible in its cache before any Secret is created.
	newSet := func() (cs *apiv1.CertificateSet, primary, fallback string) {
		namespace := createTestNamespace(ctx)
		cs = createCertificateSet(ctx, uuid.NewString(), namespace, "fallback")
		Eventually(mgrClient.Get).WithArguments(ctx, client.ObjectKeyFromObject(cs), &apiv1.CertificateSet{}).
			WithTimeout(eventuallyTimeout).Should(Succeed())
		targets := cs.Targets()
		return cs, targets[0].Name, targets[1].Name
	}

	It("should copy the active Secret to the canonical Secret", func() {
		cs, primary, _ := newSet()

		By("activating a Secret of the set")
		src := createTLSSecret(ctx, cs.Namespace, primary, activeAnnotations(cs.Name))

		expectCanonicalData(ctx, cs, src.Data)
		canonical, err := getSecret(ctx, cs.Name, cs.Namespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(canonical.Type).To(Equal(corev1.SecretTypeTLS))
		Expect(canonical.Labels).To(HaveKeyWithValue(managedByLabel, managedByValue))
		Expect(canonical.Annotations).To(HaveKeyWithValue(apiv1.CertificateSetSourceSecretAnnotation, primary))
		Expect(metav1.IsControlledBy(canonical, cs)).To(BeTrue())
		Eventually(events.has).WithTimeout(eventuallyTimeout).
			WithArguments(corev1.EventTypeNormal, "Synced").Should(BeTrue())

		By("leaving the source Secret alone")
		source, err := getSecret(ctx, primary, cs.Namespace)
		Expect(err).NotTo(HaveOccurred())
		Expect(source.Data).To(Equal(src.Data))
		Expect(source.Annotations).To(Equal(activeAnnotations(cs.Name)))
	})

	DescribeTable("should not sync",
		func(annotate func(setName string) map[string]string) {
			cs, primary, _ := newSet()
			createTLSSecret(ctx, cs.Namespace, primary, annotate(cs.Name))
			expectNoCanonical(ctx, cs)
		},
		Entry("a Secret without annotations", func(string) map[string]string { return nil }),
		Entry("a Secret that is not active", memberAnnotations),
		Entry("a Secret whose active annotation is not true", func(setName string) map[string]string {
			a := memberAnnotations(setName)
			a[apiv1.CertificateSetActiveAnnotation] = "false"
			return a
		}),
		Entry("an active Secret of an unknown CertificateSet", func(string) map[string]string {
			return activeAnnotations("unknown")
		}),
	)

	It("should not sync an active Secret that is not generated by the set", func() {
		cs, _, _ := newSet()

		By("annotating an unrelated Secret as active for the set")
		createTLSSecret(ctx, cs.Namespace, "unrelated", activeAnnotations(cs.Name))

		Eventually(events.has).WithTimeout(eventuallyTimeout).
			WithArguments(corev1.EventTypeWarning, "ForeignActiveSecret").Should(BeTrue())
		expectNoCanonical(ctx, cs)
	})

	It("should ignore active Secrets of a CertificateSet that is being deleted", func() {
		cs, primary, _ := newSet()

		By("deleting the CertificateSet, held back by a finalizer")
		controllerutil.AddFinalizer(cs, "test.atelierhsn.com/hold")
		Expect(k8sClient.Update(ctx, cs)).To(Succeed())
		Expect(k8sClient.Delete(ctx, cs)).To(Succeed())
		Eventually(func(g Gomega) {
			cached := &apiv1.CertificateSet{}
			g.Expect(mgrClient.Get(ctx, client.ObjectKeyFromObject(cs), cached)).To(Succeed())
			g.Expect(cached.DeletionTimestamp.IsZero()).To(BeFalse())
		}).WithTimeout(eventuallyTimeout).Should(Succeed())

		createTLSSecret(ctx, cs.Namespace, primary, activeAnnotations(cs.Name))
		expectNoCanonical(ctx, cs)
	})

	It("should follow changes of the active Secret", func() {
		cs, primary, fallback := newSet()
		src := createTLSSecret(ctx, cs.Namespace, primary, activeAnnotations(cs.Name))
		other := createTLSSecret(ctx, cs.Namespace, fallback, memberAnnotations(cs.Name))
		expectCanonicalData(ctx, cs, src.Data)

		By("updating the data of the active Secret")
		src.Data = tlsData("renewed")
		Expect(k8sClient.Update(ctx, src)).To(Succeed())
		expectCanonicalData(ctx, cs, src.Data)

		By("switching the active Secret")
		src.Annotations = memberAnnotations(cs.Name)
		Expect(k8sClient.Update(ctx, src)).To(Succeed())
		other.Annotations = activeAnnotations(cs.Name)
		Expect(k8sClient.Update(ctx, other)).To(Succeed())
		expectCanonicalData(ctx, cs, other.Data)
	})

	It("should not sync while multiple Secrets are active", func() {
		cs, primary, fallback := newSet()
		first := createTLSSecret(ctx, cs.Namespace, primary, activeAnnotations(cs.Name))
		expectCanonicalData(ctx, cs, first.Data)

		By("activating a second Secret")
		second := createTLSSecret(ctx, cs.Namespace, fallback, activeAnnotations(cs.Name))
		Eventually(events.has).WithTimeout(eventuallyTimeout).
			WithArguments(corev1.EventTypeWarning, "MultipleActiveSecrets").Should(BeTrue())
		Consistently(func() map[string][]byte {
			canonical, err := getSecret(ctx, cs.Name, cs.Namespace)
			Expect(err).NotTo(HaveOccurred())
			return canonical.Data
		}).WithTimeout(consistentlyDuration).Should(Equal(first.Data))

		By("deactivating the first Secret")
		first.Annotations = memberAnnotations(cs.Name)
		Expect(k8sClient.Update(ctx, first)).To(Succeed())
		expectCanonicalData(ctx, cs, second.Data)
	})

	It("should restore the canonical Secret when it is modified or deleted", func() {
		cs, primary, _ := newSet()
		src := createTLSSecret(ctx, cs.Namespace, primary, activeAnnotations(cs.Name))
		expectCanonicalData(ctx, cs, src.Data)

		By("modifying the canonical Secret")
		canonical, err := getSecret(ctx, cs.Name, cs.Namespace)
		Expect(err).NotTo(HaveOccurred())
		canonical.Data = tlsData("tampered")
		Expect(k8sClient.Update(ctx, canonical)).To(Succeed())
		expectCanonicalData(ctx, cs, src.Data)

		By("deleting the canonical Secret")
		Expect(k8sClient.Delete(ctx, canonical)).To(Succeed())
		expectCanonicalData(ctx, cs, src.Data)
	})

	It("should not overwrite a Secret it does not own", func() {
		cs, primary, _ := newSet()

		By("creating a Secret with the name of the canonical Secret")
		existing := createTLSSecret(ctx, cs.Namespace, cs.Name, nil)

		By("activating a Secret of the set")
		createTLSSecret(ctx, cs.Namespace, primary, activeAnnotations(cs.Name))

		Eventually(events.has).WithTimeout(eventuallyTimeout).
			WithArguments(corev1.EventTypeWarning, "CanonicalConflict").Should(BeTrue())
		Consistently(func() map[string][]byte {
			canonical, err := getSecret(ctx, cs.Name, cs.Namespace)
			Expect(err).NotTo(HaveOccurred())
			return canonical.Data
		}).WithTimeout(consistentlyDuration).Should(Equal(existing.Data))
	})
})
