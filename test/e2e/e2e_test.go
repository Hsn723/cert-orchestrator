//go:build e2e
// +build e2e

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

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"uuid"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"

	apiv1 "github.com/hsn723/cert-orchestrator/api/v1"
	"github.com/hsn723/cert-orchestrator/test/utils"
)

// namespace where the project is deployed in
const namespace = "cert-orchestrator-system"

// serviceAccountName created for the project
const serviceAccountName = "cert-orchestrator-controller-manager"

// metricsServiceName is the name of the metrics service of the project
const metricsServiceName = "cert-orchestrator-controller-manager-metrics-service"

// metricsRoleBindingName is the name of the RBAC that will be created to allow get the metrics data
const metricsRoleBindingName = "cert-orchestrator-metrics-binding"

var _ = Describe("Manager", Ordered, func() {
	var controllerPodName string

	// Before running the tests, set up the environment by creating the namespace,
	// enforce the restricted security policy to the namespace, installing CRDs,
	// and deploying the controller.
	BeforeAll(func() {
		By("creating manager namespace")
		cmd := exec.Command("kubectl", "create", "ns", namespace)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create namespace")

		By("labeling the namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label namespace with restricted policy")

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", managerImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")
	})

	// After all tests have been executed, clean up by undeploying the controller, uninstalling CRDs,
	// and deleting the namespace.
	AfterAll(func() {
		By("cleaning up the curl pod for metrics")
		cmd := exec.Command("kubectl", "delete", "pod", "curl-metrics", "-n", namespace)
		_, _ = utils.Run(cmd)

		By("undeploying the controller-manager")
		cmd = exec.Command("make", "undeploy")
		_, _ = utils.Run(cmd)

		By("uninstalling CRDs")
		cmd = exec.Command("make", "uninstall")
		_, _ = utils.Run(cmd)

		By("removing manager namespace")
		cmd = exec.Command("kubectl", "delete", "ns", namespace)
		_, _ = utils.Run(cmd)
	})

	// After each test, check for failures and collect logs, events,
	// and pod descriptions for debugging.
	AfterEach(func() {
		specReport := CurrentSpecReport()
		if specReport.Failed() {
			By("Fetching controller manager pod logs")
			cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
			controllerLogs, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Controller logs:\n %s", controllerLogs)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Controller logs: %s", err)
			}

			By("Fetching Kubernetes events")
			cmd = exec.Command("kubectl", "get", "events", "-n", namespace, "--sort-by=.lastTimestamp")
			eventsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Kubernetes events:\n%s", eventsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Kubernetes events: %s", err)
			}

			By("Fetching curl-metrics logs")
			cmd = exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
			metricsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Metrics logs:\n %s", metricsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get curl-metrics logs: %s", err)
			}

			By("Fetching controller manager pod description")
			cmd = exec.Command("kubectl", "describe", "pod", controllerPodName, "-n", namespace)
			podDescription, err := utils.Run(cmd)
			if err == nil {
				fmt.Println("Pod description:\n", podDescription)
			} else {
				fmt.Println("Failed to describe controller pod")
			}
		}
	})

	SetDefaultEventuallyTimeout(2 * time.Minute)
	SetDefaultEventuallyPollingInterval(time.Second)

	Context("Manager", func() {
		It("should run successfully", func() {
			By("validating that the controller-manager pod is running as expected")
			verifyControllerUp := func(g Gomega) {
				By("getting the name of the controller-manager pod")
				cmd := exec.Command("kubectl", "get",
					"pods", "-l", "control-plane=controller-manager",
					"-o", "go-template={{ range .items }}"+
						"{{ if not .metadata.deletionTimestamp }}"+
						"{{ .metadata.name }}"+
						"{{ \"\\n\" }}{{ end }}{{ end }}",
					"-n", namespace,
				)

				podOutput, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve controller-manager pod information")
				podNames := utils.GetNonEmptyLines(podOutput)
				g.Expect(podNames).To(HaveLen(1), "expected 1 controller pod running")
				controllerPodName = podNames[0]
				g.Expect(controllerPodName).To(ContainSubstring("controller-manager"))

				By("validating the pod's status")
				cmd = exec.Command("kubectl", "get",
					"pods", controllerPodName, "-o", "jsonpath={.status.phase}",
					"-n", namespace,
				)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "Incorrect controller-manager pod status")
			}
			Eventually(verifyControllerUp).Should(Succeed())
		})

		It("should ensure the metrics endpoint is serving metrics", func() {
			By("creating a ClusterRoleBinding for the service account to allow access to metrics")
			cmd := exec.Command("kubectl", "create", "clusterrolebinding", metricsRoleBindingName,
				"--clusterrole=cert-orchestrator-metrics-reader",
				fmt.Sprintf("--serviceaccount=%s:%s", namespace, serviceAccountName),
			)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create ClusterRoleBinding")

			By("validating that the metrics service is available")
			cmd = exec.Command("kubectl", "get", "service", metricsServiceName, "-n", namespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Metrics service should exist")

			By("getting the service account token")
			token, err := serviceAccountToken()
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeEmpty())

			By("ensuring the controller pod is ready")
			verifyControllerPodReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", controllerPodName, "-n", namespace,
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("True"), "Controller pod not ready")
			}
			Eventually(verifyControllerPodReady, 3*time.Minute, time.Second).Should(Succeed())

			By("verifying that the controller manager is serving the metrics server")
			verifyMetricsServerStarted := func(g Gomega) {
				cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("Serving metrics server"),
					"Metrics server not yet started")
			}
			Eventually(verifyMetricsServerStarted, 3*time.Minute, time.Second).Should(Succeed())

			// +kubebuilder:scaffold:e2e-metrics-webhooks-readiness

			By("creating the curl-metrics pod to access the metrics endpoint")
			cmd = exec.Command("kubectl", "run", "curl-metrics", "--restart=Never",
				"--namespace", namespace,
				"--image=curlimages/curl:latest",
				"--overrides",
				fmt.Sprintf(`{
					"spec": {
						"containers": [{
							"name": "curl",
							"image": "curlimages/curl:latest",
							"command": ["/bin/sh", "-c"],
							"args": [
								"for i in $(seq 1 30); do curl -v -k -H 'Authorization: Bearer %s' https://%s.%s.svc.cluster.local:8443/metrics && exit 0 || sleep 2; done; exit 1"
							],
							"securityContext": {
								"readOnlyRootFilesystem": true,
								"allowPrivilegeEscalation": false,
								"capabilities": {
									"drop": ["ALL"]
								},
								"runAsNonRoot": true,
								"runAsUser": 1000,
								"seccompProfile": {
									"type": "RuntimeDefault"
								}
							}
						}],
						"serviceAccountName": "%s"
					}
				}`, token, metricsServiceName, namespace, serviceAccountName))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create curl-metrics pod")

			By("waiting for the curl-metrics pod to complete.")
			verifyCurlUp := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pods", "curl-metrics",
					"-o", "jsonpath={.status.phase}",
					"-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Succeeded"), "curl pod in wrong status")
			}
			Eventually(verifyCurlUp, 5*time.Minute).Should(Succeed())

			By("getting the metrics by checking curl-metrics logs")
			verifyMetricsAvailable := func(g Gomega) {
				metricsOutput, err := getMetricsOutput()
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve logs from curl pod")
				g.Expect(metricsOutput).NotTo(BeEmpty())
				g.Expect(metricsOutput).To(ContainSubstring("< HTTP/1.1 200 OK"))
			}
			Eventually(verifyMetricsAvailable, 2*time.Minute).Should(Succeed())
		})

		// +kubebuilder:scaffold:e2e-webhooks-checks
	})

	Context("CertificateSet", func() {
		const (
			setName        = "web"
			primaryIssuer  = "primary-issuer"
			fallbackIssuer = "other-issuer"
		)
		var testNamespace, primary, fallback string

		BeforeEach(func() {
			testNamespace = "e2e-" + uuid.New().String()[:8]
			primary = setName + apiv1.CertificateSetNameSeparator + primaryIssuer
			fallback = setName + apiv1.CertificateSetNameSeparator + fallbackIssuer

			By("creating a test namespace")
			_, err := kubectl("create", "ns", testNamespace)
			Expect(err).NotTo(HaveOccurred(), "Failed to create test namespace")
			DeferCleanup(func() { _, _ = kubectl("delete", "ns", testNamespace) })
		})

		AfterEach(func() {
			if !CurrentSpecReport().Failed() {
				return
			}
			for _, args := range [][]string{
				{"describe", "certificatesets.cert-orchestrator.atelierhsn.com,certificates", "-n", testNamespace},
				{"get", "secrets,events", "-n", testNamespace},
			} {
				out, _ := kubectl(args...)
				_, _ = fmt.Fprintf(GinkgoWriter, "--- kubectl %s\n%s\n", strings.Join(args, " "), out)
			}
		})

		createSet := func(alg apiv1.SelectionAlgorithm) {
			By("creating the Issuers and CertificateSet")
			Eventually(func() error {
				return kubectlApply(certificateSetManifest(testNamespace, setName, primaryIssuer, fallbackIssuer, alg))
			}).Should(Succeed())
		}

		expectCanonical := func(source string) {
			GinkgoHelper()
			Eventually(func(g Gomega) {
				canonical := getSecret(g, testNamespace, setName)
				g.Expect(canonical.Type).To(Equal(corev1.SecretTypeTLS))
				g.Expect(canonical.Data[corev1.TLSCertKey]).To(Equal(getSecret(g, testNamespace, source).Data[corev1.TLSCertKey]))
				g.Expect(canonical.Annotations).To(HaveKeyWithValue(apiv1.CertificateSetSourceSecretAnnotation, source))
				cs := getCertificateSet(g, testNamespace, setName)
				g.Expect(cs.Status.ActiveCertificate).To(Equal(source))
				g.Expect(meta.IsStatusConditionTrue(cs.Status.Conditions, apiv1.CertificateSetConditionTypeReady)).To(BeTrue())
			}).Should(Succeed())
		}

		It("should serve the certificate of the primary with ForcePrimary", func() {
			createSet(apiv1.SelectionAlgorithmForcePrimary)

			By("checking that the generated Secrets inherited their annotations from the Certificates")
			Eventually(func(g Gomega) {
				p := getSecret(g, testNamespace, primary)
				g.Expect(p.Annotations).To(HaveKeyWithValue(apiv1.CertificateSetNameAnnotation, setName))
				g.Expect(p.Annotations).To(HaveKeyWithValue(apiv1.CertificateSetPriorityAnnotation, "primary"))
				f := getSecret(g, testNamespace, fallback)
				g.Expect(f.Annotations).To(HaveKeyWithValue(apiv1.CertificateSetNameAnnotation, setName))
				g.Expect(f.Annotations).To(HaveKeyWithValue(apiv1.CertificateSetPriorityAnnotation, "fallback"))
			}).Should(Succeed())

			By("checking that the primary is active and copied to the canonical Secret")
			expectCanonical(primary)
			Eventually(func(g Gomega) {
				g.Expect(getSecret(g, testNamespace, primary).Annotations).To(HaveKeyWithValue(apiv1.CertificateSetActiveAnnotation, "true"))
				g.Expect(getSecret(g, testNamespace, fallback).Annotations).NotTo(HaveKey(apiv1.CertificateSetActiveAnnotation))
				g.Expect(getSecret(g, testNamespace, setName).Data[corev1.TLSCertKey]).
					NotTo(Equal(getSecret(g, testNamespace, fallback).Data[corev1.TLSCertKey]))
			}).Should(Succeed())
		})

		It("should leave the selection to the user with Manual", func() {
			createSet(apiv1.SelectionAlgorithmManual)

			By("checking that nothing is selected and no canonical Secret exists")
			Eventually(func(g Gomega) {
				set := getCertificateSet(g, testNamespace, setName)
				cond := meta.FindStatusCondition(set.Status.Conditions, apiv1.CertificateSetConditionTypeSelected)
				g.Expect(cond).NotTo(BeNil())
				g.Expect(cond.Reason).To(Equal("NoActiveSecret"))
			}).Should(Succeed())
			Consistently(func() error {
				_, err := kubectl("get", "secret/"+setName, "-n", testNamespace)
				return err
			}).WithTimeout(10 * time.Second).ShouldNot(Succeed())

			By("activating the fallback")
			_, err := kubectl("annotate", "secret/"+fallback, "-n", testNamespace, apiv1.CertificateSetActiveAnnotation+"=true")
			Expect(err).NotTo(HaveOccurred())
			expectCanonical(fallback)

			By("switching to the primary")
			_, err = kubectl("annotate", "secret/"+fallback, "-n", testNamespace, apiv1.CertificateSetActiveAnnotation+"-")
			Expect(err).NotTo(HaveOccurred())
			_, err = kubectl("annotate", "secret/"+primary, "-n", testNamespace, apiv1.CertificateSetActiveAnnotation+"=true")
			Expect(err).NotTo(HaveOccurred())
			expectCanonical(primary)
		})

		It("should remove its Certificates and the canonical Secret with the CertificateSet", func() {
			createSet(apiv1.SelectionAlgorithmForcePrimary)
			expectCanonical(primary)

			By("deleting the CertificateSet")
			_, err := kubectl("delete", "certificatesets.cert-orchestrator.atelierhsn.com/"+setName, "-n", testNamespace)
			Expect(err).NotTo(HaveOccurred())

			Eventually(func(g Gomega) {
				out, err := kubectl("get", "certificates", "-n", testNamespace, "-o", "name")
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(out).To(BeEmpty())
				_, err = kubectl("get", "secret/"+setName, "-n", testNamespace)
				g.Expect(err).To(HaveOccurred())
			}).Should(Succeed())
		})
	})
})

// serviceAccountToken returns a token for the specified service account in the given namespace.
// It uses the Kubernetes TokenRequest API to generate a token by directly sending a request
// and parsing the resulting token from the API response.
func serviceAccountToken() (string, error) {
	const tokenRequestRawString = `{
		"apiVersion": "authentication.k8s.io/v1",
		"kind": "TokenRequest"
	}`

	By("creating temporary file to store the token request")
	secretName := fmt.Sprintf("%s-token-request", serviceAccountName)
	tokenRequestFile := filepath.Join("/tmp", secretName)
	err := os.WriteFile(tokenRequestFile, []byte(tokenRequestRawString), os.FileMode(0o644))
	if err != nil {
		return "", err
	}

	var out string
	verifyTokenCreation := func(g Gomega) {
		By("executing kubectl command to create the token")
		cmd := exec.Command("kubectl", "create", "--raw", fmt.Sprintf(
			"/api/v1/namespaces/%s/serviceaccounts/%s/token",
			namespace,
			serviceAccountName,
		), "-f", tokenRequestFile)

		output, err := cmd.CombinedOutput()
		g.Expect(err).NotTo(HaveOccurred())

		By("parsing the JSON output to extract the token")
		var token tokenRequest
		err = json.Unmarshal(output, &token)
		g.Expect(err).NotTo(HaveOccurred())

		out = token.Status.Token
	}
	Eventually(verifyTokenCreation).Should(Succeed())

	return out, err
}

// getMetricsOutput retrieves and returns the logs from the curl pod used to access the metrics endpoint.
func getMetricsOutput() (string, error) {
	By("getting the curl-metrics logs")
	cmd := exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
	return utils.Run(cmd)
}

// tokenRequest is a simplified representation of the Kubernetes TokenRequest API response,
// containing only the token field that we need to extract.
type tokenRequest struct {
	Status struct {
		Token string `json:"token"`
	} `json:"status"`
}

func kubectl(args ...string) (string, error) {
	out, err := utils.Run(exec.Command("kubectl", args...))
	return strings.TrimSpace(out), err
}

func kubectlApply(manifest string) error {
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	_, err := utils.Run(cmd)
	return err
}

func getJSON(g Gomega, ns, resource string, obj any) {
	GinkgoHelper()
	out, err := exec.Command("kubectl", "get", resource, "-n", ns, "-o", "json").Output()
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(json.Unmarshal(out, obj)).To(Succeed())
}

func getSecret(g Gomega, ns, name string) *corev1.Secret {
	GinkgoHelper()
	s := &corev1.Secret{}
	getJSON(g, ns, "secret/"+name, s)
	return s
}

func getCertificateSet(g Gomega, ns, name string) *apiv1.CertificateSet {
	GinkgoHelper()
	cs := &apiv1.CertificateSet{}
	getJSON(g, ns, "certificatesets.cert-orchestrator.atelierhsn.com/"+name, cs)
	return cs
}

func certificateSetManifest(ns, name, primaryIssuer, fallbackIssuer string, algorithm apiv1.SelectionAlgorithm) string {
	return fmt.Sprintf(`apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: %[3]s
  namespace: %[1]s
spec:
  selfSigned: {}
---
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: %[4]s
  namespace: %[1]s
spec:
  selfSigned: {}
---
apiVersion: cert-orchestrator.atelierhsn.com/v1
kind: CertificateSet
metadata:
  name: %[2]s
  namespace: %[1]s
spec:
  selectionAlgorithm: %[5]s
  template:
    spec:
      dnsNames:
        - example.com
      privateKey:
        algorithm: ECDSA
        size: 256
  issuers:
    primary:
      name: %[3]s
      kind: Issuer
      group: cert-manager.io
    fallbacks:
      - name: %[4]s
        kind: Issuer
        group: cert-manager.io
`, ns, name, primaryIssuer, fallbackIssuer, algorithm)
}
