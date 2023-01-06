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

package controller

import (
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"

	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/model"
	kubesr "istio.io/istio/pilot/pkg/serviceregistry/kube"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/config/host"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/informer"
	"istio.io/istio/pkg/kube/mcs"
)

type exportedService struct {
	namespacedName  types.NamespacedName
	discoverability map[host.Name]string
}

// serviceExportCache reads Kubernetes Multi-Cluster Services (MCS) ServiceExport resources in the
// cluster and generates discoverability policies for the endpoints.
type serviceExportCache interface {
	// EndpointDiscoverabilityPolicy returns the policy for Service endpoints residing within the current cluster.
	EndpointDiscoverabilityPolicy(svc *model.Service) model.EndpointDiscoverabilityPolicy

	// ExportedServices returns the list of services that are exported in this cluster. Used for debugging.
	ExportedServices() []exportedService

	// HasSynced indicates whether the kube createClient has synced for the watched resources.
	HasSynced() bool
}

// newServiceExportCache creates a new serviceExportCache that observes the given cluster.
func newServiceExportCache(c *Controller) serviceExportCache {
	if features.EnableMCSServiceDiscovery {
		dInformer := c.client.DynamicInformer().ForResource(mcs.ServiceExportGVR)
		_ = dInformer.Informer().SetTransform(kube.StripUnusedFields)
		ec := &serviceExportCacheImpl{
			Controller: c,
		}
		if c.opts.DiscoveryNamespacesFilter != nil {
			ec.filteredInformer = informer.NewFilteredSharedIndexInformer(c.opts.DiscoveryNamespacesFilter.Filter, dInformer.Informer())
		} else {
			ec.filteredInformer = informer.NewFilteredSharedIndexInformer(nil, dInformer.Informer())
		}

		// Set the discoverability policy for the clusterset.local host.
		ec.clusterSetLocalPolicySelector = func(svc *model.Service) (policy model.EndpointDiscoverabilityPolicy) {
			// If the service is exported in this cluster, allow the endpoints in this cluster to be discoverable
			// anywhere in the mesh.
			if ec.isExported(namespacedNameForService(svc)) {
				return model.AlwaysDiscoverable
			}

			// Otherwise, endpoints are only discoverable from within the same cluster.
			return model.DiscoverableFromSameCluster
		}

		// Set the discoverability policy for the cluster.local host.
		if features.EnableMCSClusterLocal {
			// MCS cluster.local mode is enabled. Allow endpoints for the cluster.local host to be
			// discoverable only from within the same cluster.
			ec.clusterLocalPolicySelector = func(svc *model.Service) (policy model.EndpointDiscoverabilityPolicy) {
				return model.DiscoverableFromSameCluster
			}
		} else {
			// MCS cluster.local mode is not enabled, so requests to the cluster.local host are not confined
			// to the same cluster. Use the same discoverability policy as for clusterset.local.
			ec.clusterLocalPolicySelector = ec.clusterSetLocalPolicySelector
		}

		// Register callbacks for events.
		c.registerHandlers(ec.filteredInformer, "ServiceExports", ec.onServiceExportEvent, nil)
		return ec
	}

	// MCS Service discovery is disabled. Use a placeholder cache.
	return disabledServiceExportCache{}
}

type discoverabilityPolicySelector func(*model.Service) model.EndpointDiscoverabilityPolicy

// serviceExportCache reads ServiceExport resources for a single cluster.
type serviceExportCacheImpl struct {
	*Controller

	filteredInformer informer.FilteredSharedIndexInformer

	// clusterLocalPolicySelector selects an appropriate EndpointDiscoverabilityPolicy for the cluster.local host.
	clusterLocalPolicySelector discoverabilityPolicySelector

	// clusterSetLocalPolicySelector selects an appropriate EndpointDiscoverabilityPolicy for the clusterset.local host.
	clusterSetLocalPolicySelector discoverabilityPolicySelector
}

func (ec *serviceExportCacheImpl) onServiceExportEvent(obj any, event model.Event) error {
	se := controllers.Extract[*unstructured.Unstructured](obj)
	if se == nil {
		return nil
	}

	switch event {
	case model.EventAdd, model.EventDelete:
		ec.updateXDS(se)
	default:
		// Don't care about updates.
	}
	return nil
}

func (ec *serviceExportCacheImpl) updateXDS(se metav1.Object) {
	for _, svc := range ec.servicesForNamespacedName(kubesr.NamespacedNameForK8sObject(se)) {
		// Re-build the endpoints for this service with a new discoverability policy.
		// Also update any internal caching.
		endpoints := ec.buildEndpointsForService(svc, true)
		shard := model.ShardKeyFromRegistry(ec)
		ec.opts.XDSUpdater.EDSUpdate(shard, svc.Hostname.String(), se.GetNamespace(), endpoints)
	}
}

func (ec *serviceExportCacheImpl) EndpointDiscoverabilityPolicy(svc *model.Service) model.EndpointDiscoverabilityPolicy {
	if svc == nil {
		// Default policy when the service doesn't exist.
		return model.DiscoverableFromSameCluster
	}

	if strings.HasSuffix(svc.Hostname.String(), "."+constants.DefaultClusterSetLocalDomain) {
		return ec.clusterSetLocalPolicySelector(svc)
	}

	return ec.clusterLocalPolicySelector(svc)
}

func (ec *serviceExportCacheImpl) isExported(name types.NamespacedName) bool {
	item, _, _ := ec.filteredInformer.GetIndexer().GetByKey(name.String())
	return item != nil
}

func (ec *serviceExportCacheImpl) ExportedServices() []exportedService {
	// List all exports in this cluster.
	exports, err := ec.filteredInformer.List("")
	if err != nil {
		return make([]exportedService, 0)
	}

	ec.RLock()

	out := make([]exportedService, 0, len(exports))
	for _, export := range exports {
		uExport := export.(*unstructured.Unstructured)
		es := exportedService{
			namespacedName:  kubesr.NamespacedNameForK8sObject(uExport),
			discoverability: make(map[host.Name]string),
		}

		// Generate the map of all hosts for this service to their discoverability policies.
		clusterLocalHost := kubesr.ServiceHostname(uExport.GetName(), uExport.GetNamespace(), ec.opts.DomainSuffix)
		clusterSetLocalHost := serviceClusterSetLocalHostname(es.namespacedName)
		for _, hostName := range []host.Name{clusterLocalHost, clusterSetLocalHost} {
			if svc := ec.servicesMap[hostName]; svc != nil {
				es.discoverability[hostName] = ec.EndpointDiscoverabilityPolicy(svc).String()
			}
		}

		out = append(out, es)
	}

	ec.RUnlock()

	return out
}

func (ec *serviceExportCacheImpl) HasSynced() bool {
	return ec.filteredInformer.HasSynced()
}

type disabledServiceExportCache struct{}

var _ serviceExportCache = disabledServiceExportCache{}

func (c disabledServiceExportCache) EndpointDiscoverabilityPolicy(*model.Service) model.EndpointDiscoverabilityPolicy {
	return model.AlwaysDiscoverable
}

func (c disabledServiceExportCache) HasSynced() bool {
	return true
}

func (c disabledServiceExportCache) ExportedServices() []exportedService {
	// MCS is disabled - returning `nil`, which is semantically different here than an empty list.
	return nil
}
