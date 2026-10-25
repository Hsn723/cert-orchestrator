package controller

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	apiv1 "github.com/hsn723/cert-orchestrator/api/v1"
)

const (
	managedByLabel = "app.kubernetes.io/managed-by"
	managedByValue = "cert-orchestrator"
)

func isActive(secret *corev1.Secret) bool {
	return secret.Annotations[apiv1.CertificateSetActiveAnnotation] == "true"
}

func controllingCertificateSetName(obj client.Object) string {
	ref := v1.GetControllerOf(obj)
	if ref == nil || ref.Kind != apiv1.CertificateSetKind {
		return ""
	}
	gv, err := schema.ParseGroupVersion(ref.APIVersion)
	if err != nil || gv.Group != apiv1.GroupVersion.Group {
		return ""
	}
	return ref.Name
}

func certificateSetNameFor(obj client.Object) string {
	if name := obj.GetAnnotations()[apiv1.CertificateSetNameAnnotation]; name != "" {
		return name
	}
	return controllingCertificateSetName(obj)
}

func setCondition(cs *apiv1.CertificateSet, condType string, status v1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&cs.Status.Conditions, v1.Condition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: cs.Generation,
	})
}
