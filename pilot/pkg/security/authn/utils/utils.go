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
	"strings"

	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"istio.io/istio/pkg/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	meshconfig "istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/networking"
	"istio.io/istio/pilot/pkg/networking/util"
	"istio.io/istio/pilot/pkg/security/controller/ciphersuites"
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

var (
    cipherController *ciphersuites.Controller
    // Indicates if the CipherController is initialized
	controllerInitialized bool  
)

func InitializeCipherController(client kubernetes.Interface) {
    log.Info("Starting to initialize CipherController")
    if cipherController != nil {
        log.Info("CipherController already initialized")
        return
    }
    
    config, err := rest.InClusterConfig()
    if err != nil {
        log.Errorf("Failed to get cluster config: %v", err)
        return
    }
    
    cipherController = ciphersuites.NewController(client, config)
    controllerInitialized = true
    log.Info("CipherController initialization completed successfully")
}

func IsCipherControllerInitialized() bool {
    return controllerInitialized
}

// BuildInboundTLS returns the TLS context corresponding to the mTLS mode.
func BuildInboundTLS(mTLSMode model.MutualTLSMode, node *model.Proxy,
	protocol networking.ListenerProtocol, trustDomainAliases []string, minTLSVersion tls.TlsParameters_TlsProtocol,
	mc *meshconfig.MeshConfig,) *tls.DownstreamTlsContext {

	if mTLSMode == model.MTLSDisable || mTLSMode == model.MTLSUnknown {
		return nil
	}

    // Re-initialize the controller if needed
	// if !IsCipherControllerInitialized() {
    //     log.Error("CipherController is not initialized - attempting re-initialization")
    //     return nil
    // }
	
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

    // CipherSuites configuration
    ciphers := SupportedCiphers
	log.Infof("Initial ciphers: %v", ciphers) 

    var usedCustomCiphers bool
    
    log.Infof("Checking CipherSuites configuration for namespace: %s", node.Metadata.Namespace)

    // 1. First check controller and cache
    if cipherController != nil {
        log.Info("CipherController is available")
        if cachedCiphers, exists := cipherController.GetCipherSuites(node.Metadata.Namespace); exists {
            log.Infof("Found cached CipherSuites for namespace %s: %v", 
                node.Metadata.Namespace, cachedCiphers)
            ciphers = cachedCiphers
            usedCustomCiphers = true
        } else {
            log.Infof("No cached CipherSuites found for namespace %s", node.Metadata.Namespace)
            // Try getting from annotation
            annoCipher, err := getCiphersuitesFromAnnotation(node)
            if err == nil && len(annoCipher) > 0 {
                log.Infof("Found annotation CipherSuites: %v", annoCipher)
                ciphers = annoCipher
                usedCustomCiphers = true
                // Update cache
                cipherController.UpdateCache(node.Metadata.Namespace, annoCipher)
            } else {
                log.Info("No valid annotation CipherSuites found")
            }
        }
    } else {
        log.Warn("CipherController is not initialized")
    }

    // 2. If no custom ciphers, use meshConfig or default
    if !usedCustomCiphers {
        if mc != nil && mc.MeshMTLS != nil && mc.MeshMTLS.CipherSuites != nil {
            log.Info("Using MeshConfig CipherSuites")
            ciphers = mc.MeshMTLS.CipherSuites
        } else {
            log.Info("Using default SupportedCiphers")
            ciphers = SupportedCiphers
        }
    }

    log.Infof("Final CipherSuites selection - Source: %s, Ciphers: %v", 
        map[bool]string{true: "Custom", false: "MeshConfig/Default"}[usedCustomCiphers],
        ciphers)
	
	// Set Minimum TLS version to match the default client version and allowed strong cipher suites for sidecars.
	// Set Max TLS version to TLS 1.2
	ctx.CommonTlsContext.TlsParams = &tls.TlsParameters{
		CipherSuites:              ciphers,
		TlsMinimumProtocolVersion: minTLSVersion,
		TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
	}

	log.Infof("Final TLS Params: %+v", ctx.CommonTlsContext.TlsParams)

	authn_model.ApplyToCommonTLSContext(ctx.CommonTlsContext, node, []string{}, /*subjectAltNames*/
		trustDomainAliases, ctx.RequireClientCertificate.Value)
	return ctx
}

// Deprecated function
// func getCiphersuitesFromAnnotation(node *model.Proxy) ([]string, error) {
// 	var err error

//     if cipherController != nil {
//         // cipherController.cipherCache.Get 대신 GetCipherSuites 메서드 사용
//         if ciphers, exists := cipherController.GetCipherSuites(node.Metadata.Namespace); exists {
//             return ciphers, nil
//         }
//     }

// 	// Configure the ciphersuites from pod annotation by querying to k8s API Server
// 	k8sConfig, err := rest.InClusterConfig()
// 	if err != nil {
// 		return nil, fmt.Errorf("error triggered when fetching k8s config file")
// 	}

// 	clientset, err := kubernetes.NewForConfig(k8sConfig)

// 	parsedPodID := strings.Split(node.ID, ".")

// 	podName := parsedPodID[0]
// 	namespaceName := parsedPodID[1]

// 	pod, err := clientset.CoreV1().Pods(namespaceName).Get(context.TODO(), podName, metav1.GetOptions{})
// 	namespace, err := clientset.CoreV1().Namespaces().Get(context.TODO(), namespaceName, metav1.GetOptions{})
// 	// annotation can contain ciphersuites at once
// 	// if you consider to use multiple ciphersuites, then special format (json, concatenated strings) would be needed
// 	var cipherSuitesFromPodAnnos []string
// 	var ciphersuitesFromNSAnnos []string
// 	for key, values := range pod.Annotations {
// 		if key == "cipherSuites" {
// 			cipherSuitesFromPodAnnos = append(cipherSuitesFromPodAnnos, values)
// 		}
// 	}
// 	for key, values := range namespace.Annotations {
// 		if key == "cipherSuites" {
// 			ciphersuitesFromNSAnnos = append(ciphersuitesFromNSAnnos, values)
// 		}
// 	}

// 	// this function doesn't validate ciphersuites, if it needs, then use FilterCiphersuites()
// 	var ret []string
// 	if cipherSuitesFromPodAnnos != nil {
// 		ret = cipherSuitesFromPodAnnos
// 	}
// 	if ciphersuitesFromNSAnnos != nil {
// 		ret = ciphersuitesFromNSAnnos
// 	}

// 	return ret, err
// }

func getCiphersuitesFromAnnotation(node *model.Proxy) ([]string, error) {
    // Skip cache check here since it's already done in BuildInboundTLS
    k8sConfig, err := rest.InClusterConfig()
    if err != nil {
        return nil, fmt.Errorf("error triggered when fetching k8s config file")
    }

    clientset, err := kubernetes.NewForConfig(k8sConfig)
    if err != nil {
        return nil, err
    }

    parsedPodID := strings.Split(node.ID, ".")
    podName := parsedPodID[0]
    namespaceName := parsedPodID[1]

    namespace, err := clientset.CoreV1().Namespaces().Get(context.TODO(), namespaceName, metav1.GetOptions{})
    if err != nil {
        return nil, err
    }

    if cipherSuite, exists := namespace.Annotations["cipherSuites"]; exists {
        log.Infof("Found namespace annotation CipherSuite: %s", cipherSuite)
        return []string{cipherSuite}, nil
    }

    pod, err := clientset.CoreV1().Pods(namespaceName).Get(context.TODO(), podName, metav1.GetOptions{})
    if err != nil {
        return nil, err
    }

    if cipherSuite, exists := pod.Annotations["cipherSuites"]; exists {
        log.Infof("Found pod annotation CipherSuite: %s", cipherSuite)
        return []string{cipherSuite}, nil
    }

    return nil, nil
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