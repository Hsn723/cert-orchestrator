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

package v1

import (
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	// CertificateSetNameAnnotation is set on the Secrets of a CertificateSet to indicate which CertificateSet they belong to.
	CertificateSetNameAnnotation = "cert-orchestrator.atelierhsn.com/certificate-set"
	// CertificateSetPriorityAnnotation is set on the Secrets of a CertificateSet to "primary" or "fallback".
	CertificateSetPriorityAnnotation = "cert-orchestrator.atelierhsn.com/priority"
	// CertificateSetActiveAnnotation marks the Secret that is copied to the canonical Secret.
	CertificateSetActiveAnnotation = "cert-orchestrator.atelierhsn.com/active"
	// CertificateSetSourceSecretAnnotation records on the canonical Secret which Secret it was copied from.
	CertificateSetSourceSecretAnnotation = "cert-orchestrator.atelierhsn.com/source-secret"

	// CertificateSetNameSeparator separates the CertificateSet name and the issuer name in generated names.
	CertificateSetNameSeparator = "."

	// CertificateSetConditionTypeReady is True when the canonical Secret is in sync with the active Secret.
	CertificateSetConditionTypeReady = "Ready"
	// CertificateSetConditionTypeSelected is True when a certificate is selected for the canonical Secret.
	CertificateSetConditionTypeSelected = "Selected"
	// CertificateSetConditionTypeCertificatesReady is True when cert-manager reports every Certificate as Ready.
	CertificateSetConditionTypeCertificatesReady = "CertificatesReady"
)

// SelectionAlgorithm selects the preset used to choose the certificate served through the canonical Secret.
// +kubebuilder:validation:Enum=ForcePrimary;Strict;PrimaryIfNone;Manual
type SelectionAlgorithm string

const (
	// SelectionAlgorithmForcePrimary always selects the primary, regardless of its health.
	SelectionAlgorithmForcePrimary SelectionAlgorithm = "ForcePrimary"
	// SelectionAlgorithmStrict only considers certificates that clear all health checks.
	SelectionAlgorithmStrict SelectionAlgorithm = "Strict"
	// SelectionAlgorithmPrimaryIfNone behaves like Strict, but selects the primary if no certificate is eligible.
	SelectionAlgorithmPrimaryIfNone SelectionAlgorithm = "PrimaryIfNone"
	// SelectionAlgorithmManual never changes the selection. The active Secret is chosen by annotating it.
	SelectionAlgorithmManual SelectionAlgorithm = "Manual"
)

// CertificatePriority tells whether a certificate comes from the primary or a fallback issuer.
type CertificatePriority string

const (
	CertificatePriorityPrimary  CertificatePriority = "primary"
	CertificatePriorityFallback CertificatePriority = "fallback"
)

// CertificateTemplate is the template of the generated Certificates.
type CertificateTemplate struct {
	// Spec is a cert-manager Certificate spec. issuerRef is ignored and secretName is overridden for
	// every generated Certificate.
	Spec cmapi.CertificateSpec `json:"spec"`
}

// Issuers lists the issuers to request certificates from.
type Issuers struct {
	// Primary is the preferred issuer.
	// +required
	Primary cmmeta.IssuerReference `json:"primary"`

	// Fallbacks are the fallback issuers, in priority order.
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=8
	// +optional
	Fallbacks []cmmeta.IssuerReference `json:"fallbacks,omitempty"`
}

// CertificateSetSpec defines the desired state of CertificateSet.
// +kubebuilder:validation:XValidation:rule="!has(self.issuers.fallbacks) || self.issuers.fallbacks.all(f, f.name != self.issuers.primary.name)",message="issuer names must be unique within a CertificateSet"
type CertificateSetSpec struct {
	// Template is the template for the generated Certificates. It is used for all issuers.
	// +required
	Template CertificateTemplate `json:"template"`

	// Issuers lists the issuers to request certificates from.
	// +required
	Issuers Issuers `json:"issuers"`

	// SelectionAlgorithm selects the preset used to choose the certificate served through the canonical Secret.
	// +kubebuilder:default=ForcePrimary
	// +optional
	SelectionAlgorithm SelectionAlgorithm `json:"selectionAlgorithm,omitempty"`

	// Evaluation interval is the maximum time between evaluations of the CertificateSet. The controller will check the health of the certificates and update the canonical Secret at least this often.
	// +kubebuilder:default="1m"
	// +optional
	EvaluationInterval *metav1.Duration `json:"evaluationInterval,omitempty"`
}

// CertificateSetStatus defines the observed state of CertificateSet.
type CertificateSetStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// ActiveCertificate is the name of the Secret whose certificate is currently served through the canonical Secret. It is empty if no certificate is selected.
	// +optional
	ActiveCertificate string `json:"activeCertificate,omitempty"`

	// LastEvaluationTime is the time of the last evaluation loop.
	// +optional
	LastEvaluationTime *metav1.Time `json:"lastEvaluationTime,omitempty"`

	// Conditions represent the current state of the CertificateSet resource.
	// Each condition has a unique type and reflects the status of a specific aspect of the resource.
	//
	// Standard condition types include:
	// - "Available": the resource is fully functional
	// - "Progressing": the resource is being created or updated
	// - "Degraded": the resource failed to reach or maintain its desired state
	//
	// The status of each condition is one of True, False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +patchStrategy=merge
	// +patchMergeKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Algorithm",type=string,JSONPath=`.spec.selectionAlgorithm`
// +kubebuilder:printcolumn:name="Active",type=string,JSONPath=`.status.activeCertificate`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// CertificateSet is the Schema for the certificatesets API
type CertificateSet struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of CertificateSet
	// +required
	Spec CertificateSetSpec `json:"spec"`

	// status defines the observed state of CertificateSet
	// +optional
	Status CertificateSetStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// CertificateSetList contains a list of CertificateSet
type CertificateSetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []CertificateSet `json:"items"`
}

// CertificateTarget describes one Certificate generated for a CertificateSet.
type CertificateTarget struct {
	// Name is the name of both the Certificate and its Secret.
	Name      string
	Priority  CertificatePriority
	IssuerRef cmmeta.IssuerReference
}

// Targets returns the Certificates generated for the set, primary first, then fallbacks in order.
func (cs *CertificateSet) Targets() []CertificateTarget {
	targets := make([]CertificateTarget, 0, len(cs.Spec.Issuers.Fallbacks)+1)
	targets = append(targets, CertificateTarget{
		Name:      cs.certificateName(cs.Spec.Issuers.Primary.Name),
		Priority:  CertificatePriorityPrimary,
		IssuerRef: cs.Spec.Issuers.Primary,
	})
	for _, issuer := range cs.Spec.Issuers.Fallbacks {
		targets = append(targets, CertificateTarget{
			Name:      cs.certificateName(issuer.Name),
			Priority:  CertificatePriorityFallback,
			IssuerRef: issuer,
		})
	}
	return targets
}

func (cs *CertificateSet) certificateName(issuerName string) string {
	return cs.Name + CertificateSetNameSeparator + issuerName
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &CertificateSet{}, &CertificateSetList{})
		return nil
	})
}
