package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	apiv1 "github.com/hsn723/cert-orchestrator/api/v1"
)

const (
	eventuallyTimeout    = 10 * time.Second
	consistentlyDuration = 1500 * time.Millisecond
)

type recordedEvent struct {
	eventType string
	reason    string
	note      string
}

type fakeRecorder struct {
	mu     sync.Mutex
	events []recordedEvent
}

func (f *fakeRecorder) Eventf(_ runtime.Object, _ runtime.Object, eventType, reason, _, note string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, recordedEvent{eventType: eventType, reason: reason, note: fmt.Sprintf(note, args...)})
}

func (f *fakeRecorder) AnnotatedEventf(_ runtime.Object, _ runtime.Object, _ map[string]string, eventType, reason, _, note string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, recordedEvent{eventType: eventType, reason: reason, note: fmt.Sprintf(note, args...)})
}

func (f *fakeRecorder) has(eventType, reason string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.events {
		if e.eventType == eventType && e.reason == reason {
			return true
		}
	}
	return false
}

func createTestNamespace(ctx context.Context) string {
	GinkgoHelper()
	By("creating namespace")
	namespace := uuid.NewString()
	Expect(k8sClient.Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespace},
	})).To(Succeed())
	return namespace
}

// buildCertificateSet returns a CertificateSet with the issuer "primary" and one fallback issuer per name.
// The Secrets generated for it are named after cs.Targets().
func buildCertificateSet(name, namespace string, algorithm apiv1.SelectionAlgorithm, fallbacks ...string) *apiv1.CertificateSet {
	cs := &apiv1.CertificateSet{}
	cs.SetName(name)
	cs.SetNamespace(namespace)
	cs.Spec = apiv1.CertificateSetSpec{
		Template: apiv1.CertificateTemplate{
			Spec: cmapi.CertificateSpec{DNSNames: []string{"example.com"}},
		},
		Issuers:            apiv1.Issuers{Primary: cmmeta.IssuerReference{Name: "primary"}},
		SelectionAlgorithm: algorithm,
	}
	for _, f := range fallbacks {
		cs.Spec.Issuers.Fallbacks = append(cs.Spec.Issuers.Fallbacks, cmmeta.IssuerReference{Name: f})
	}
	return cs
}

// createCertificateSet creates a Manual CertificateSet, which never changes the selection by itself.
func createCertificateSet(ctx context.Context, name, namespace string, fallbacks ...string) *apiv1.CertificateSet {
	GinkgoHelper()
	cs := buildCertificateSet(name, namespace, apiv1.SelectionAlgorithmManual, fallbacks...)
	Expect(k8sClient.Create(ctx, cs)).To(Succeed())
	return cs
}

// tlsData returns a TLS Secret payload holding a fresh self-signed certificate.
func tlsData(_ string) map[string][]byte {
	GinkgoHelper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	Expect(err).NotTo(HaveOccurred())
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	Expect(err).NotTo(HaveOccurred())
	return map[string][]byte{
		corev1.TLSCertKey:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		corev1.TLSPrivateKeyKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}
}

func createTLSSecret(ctx context.Context, namespace, name string, annotations map[string]string) *corev1.Secret {
	GinkgoHelper()
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Annotations: annotations},
		Type:       corev1.SecretTypeTLS,
		Data:       tlsData(name),
	}
	Expect(k8sClient.Create(ctx, secret)).To(Succeed())
	return secret
}

func memberAnnotations(setName string) map[string]string {
	return map[string]string{apiv1.CertificateSetNameAnnotation: setName}
}

func activeAnnotations(setName string) map[string]string {
	return map[string]string{
		apiv1.CertificateSetNameAnnotation:   setName,
		apiv1.CertificateSetActiveAnnotation: "true",
	}
}

func getSecret(ctx context.Context, name, namespace string) (*corev1.Secret, error) {
	s := &corev1.Secret{}
	err := k8sClient.Get(ctx, client.ObjectKey{Name: name, Namespace: namespace}, s)
	return s, err
}
