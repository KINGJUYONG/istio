// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"context"
	"fmt"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"istio.io/istio/pkg/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"strings"

	meshconfig "istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/networking"
	"istio.io/istio/pilot/pkg/networking/util"
	authn_model "istio.io/istio/pilot/pkg/security/model"
	protovalue "istio.io/istio/pkg/proto"
)

// SupportedCiphers for server side TLS configuration.
var SupportedCiphers = []string{
	"ECDHE-ECDSA-AES256-GCM-SHA384",
	"ECDHE-RSA-AES256-GCM-SHA384",
	"ECDHE-ECDSA-AES128-GCM-SHA256",
	"ECDHE-RSA-AES128-GCM-SHA256",
	"AES256-GCM-SHA384",
	"AES128-GCM-SHA256",
}

// BuildInboundTLS returns the TLS context corresponding to the mTLS mode.
func BuildInboundTLS(mTLSMode model.MutualTLSMode, node *model.Proxy,
	protocol networking.ListenerProtocol, trustDomainAliases []string, minTLSVersion tls.TlsParameters_TlsProtocol,
	mc *meshconfig.MeshConfig,
) *tls.DownstreamTlsContext {
	if mTLSMode == model.MTLSDisable || mTLSMode == model.MTLSUnknown {
		return nil
	}
	ctx := &tls.DownstreamTlsContext{
		CommonTlsContext:         &tls.CommonTlsContext{},
		RequireClientCertificate: protovalue.BoolTrue,
	}
	if protocol == networking.ListenerProtocolTCP && features.MetadataExchange {
		// For TCP with mTLS, we advertise "istio-peer-exchange" from client and
		// expect the same from server. This  is so that secure metadata exchange
		// transfer can take place between sidecars for TCP with mTLS.
		if features.DisableMxALPN {
			ctx.CommonTlsContext.AlpnProtocols = util.ALPNDownstream
		} else {
			ctx.CommonTlsContext.AlpnProtocols = util.ALPNDownstreamWithMxc
		}
	} else {
		// Note that in the PERMISSIVE mode, we match filter chain on "istio" ALPN,
		// which is used to differentiate between service mesh and legacy traffic.
		//
		// Client sidecar outbound cluster's TLSContext.ALPN must include "istio".
		//
		// Server sidecar filter chain's FilterChainMatch.ApplicationProtocols must
		// include "istio" for the secure traffic, but its TLSContext.ALPN must not
		// include "istio", which would interfere with negotiation of the underlying
		// protocol, e.g. HTTP/2.
		ctx.CommonTlsContext.AlpnProtocols = util.ALPNHttp
	}

	ciphers := SupportedCiphers
	log.Info("TLS Default Called")
	if mc != nil && mc.MeshMTLS != nil && mc.MeshMTLS.CipherSuites != nil {
		ciphers = mc.MeshMTLS.CipherSuites
	}

	// Fetching the 'cipherSuites' annotation from pods and namespaces
	// The namespace annotation has priority over the pod annotation
	// when the function returns cipher suites from these annotations
	annoCipher, err := getCiphersuitesFromAnnoation(node)
	if err != nil || annoCipher == nil {
		log.Debug("No Annotation Cipher Detected")
	} else {
		log.Info("Annotation Overriding Triggered")
		ciphers = annoCipher
	}

	// Set Minimum TLS version to match the default client version and allowed strong cipher suites for sidecars.
	// Set Max TLS version to TLS 1.2
	ctx.CommonTlsContext.TlsParams = &tls.TlsParameters{
		CipherSuites:              ciphers,
		TlsMinimumProtocolVersion: minTLSVersion,
		TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
	}

	log.Infof("TLS Params: %+v", ctx.CommonTlsContext.TlsParams)

	authn_model.ApplyToCommonTLSContext(ctx.CommonTlsContext, node, []string{}, /*subjectAltNames*/
		trustDomainAliases, ctx.RequireClientCertificate.Value)
	return ctx
}

func getCiphersuitesFromAnnoation(node *model.Proxy) ([]string, error) {
	var err error
	// Configure the ciphersuites from pod annotation by querying to k8s API Server
	k8sConfig, err := rest.InClusterConfig()

	if err != nil {
		return nil, fmt.Errorf("error triggered when fetching k8s config file")
	}

	clientset, err := kubernetes.NewForConfig(k8sConfig)

	parsedPodID := strings.Split(node.ID, ".")

	podName := parsedPodID[0]
	namespaceName := parsedPodID[1]

	pod, err := clientset.CoreV1().Pods(namespaceName).Get(context.TODO(), podName, metav1.GetOptions{})
	namespace, err := clientset.CoreV1().Namespaces().Get(context.TODO(), namespaceName, metav1.GetOptions{})
	// annotation can contain ciphersuites at once
	// if you consider to use multiple ciphersuites, then special format (json, concatenated strings) would be needed
	var cipherSuitesFromPodAnnos []string
	var ciphersuitesFromNSAnnos []string
	for key, values := range pod.Annotations {
		if key == "cipherSuites" {
			cipherSuitesFromPodAnnos = append(cipherSuitesFromPodAnnos, values)
		}
		log.Infof("%s, %s", key, values)
	}
	for key, values := range namespace.Annotations {
		if key == "cipherSuites" {
			ciphersuitesFromNSAnnos = append(ciphersuitesFromNSAnnos, values)
		}
		log.Infof("%s, %s", key, values)
	}

	// this function doesn't validate ciphersuites, if it needs, then use FilterCiphersuites()
	var ret []string
	if cipherSuitesFromPodAnnos != nil {
		log.Infof("ret = podAnnos")
		ret = cipherSuitesFromPodAnnos
	}
	if ciphersuitesFromNSAnnos != nil {
		log.Infof("ret = NSAnnos")
		ret = ciphersuitesFromNSAnnos
	}

	log.Infof("getCipherSuitesFromAnnos ret: %+v", ret)
	return ret, err
}

// GetMinTLSVersion returns the minimum TLS version for workloads based on the mesh config.
// this function return whatever TLS version set
func GetMinTLSVersion(ver meshconfig.MeshConfig_TLSConfig_TLSProtocol) tls.TlsParameters_TlsProtocol {
	switch ver {
	case meshconfig.MeshConfig_TLSConfig_TLSV1_3:
		return tls.TlsParameters_TLSv1_3
	default:
		return tls.TlsParameters_TLSv1_2
	}
}