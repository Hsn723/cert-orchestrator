package controller

import (
	"context"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	apiv1 "github.com/hsn723/cert-orchestrator/api/v1"
)

func rawCertificateSet(namespace string, fallbacks ...string) *unstructured.Unstructured {
	fb := []any{}
	for _, f := range fallbacks {
		fb = append(fb, map[string]any{"name": f})
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": apiv1.SchemeGroupVersion.String(),
		"kind":       apiv1.CertificateSetKind,
		"metadata":   map[string]any{"name": uuid.NewString(), "namespace": namespace},
		"spec": map[string]any{
			// no secretName and no issuerRef: they are optional in the template
			"template": map[string]any{"spec": map[string]any{"dnsNames": []any{"example.com"}}},
			"issuers":  map[string]any{"primary": map[string]any{"name": "primary"}, "fallbacks": fb},
		},
	}}
}

var _ = Describe("CertificateSet CRD", func() {
	ctx := context.Background()

	It("should accept a template without secretName and issuerRef", func() {
		namespace := createTestNamespace(ctx)
		Expect(k8sClient.Create(ctx, rawCertificateSet(namespace, "fallback"))).To(Succeed())
	})

	DescribeTable("should reject duplicate issuer names",
		func(fallbacks ...string) {
			namespace := createTestNamespace(ctx)
			err := k8sClient.Create(ctx, rawCertificateSet(namespace, fallbacks...))
			Expect(apierrors.IsInvalid(err)).To(BeTrue(), "unexpected error: %v", err)
		},
		Entry("a fallback with the name of the primary", "primary"),
		Entry("two fallbacks with the same name", "dup", "dup"),
	)
})
