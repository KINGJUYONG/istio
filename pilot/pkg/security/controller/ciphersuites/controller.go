package ciphersuites

import (
	"time"

    "k8s.io/api/core/v1"
    "k8s.io/client-go/informers"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/tools/cache"
    "k8s.io/client-go/rest"
    "istio.io/istio/pkg/log"
)

type Controller struct {
    client          kubernetes.Interface
    config          *rest.Config
    informerFactory informers.SharedInformerFactory
    nsInformer     cache.SharedIndexInformer
    cipherCache    *CipherSuiteCache
}

func NewController(client kubernetes.Interface, config *rest.Config) *Controller {
    factory := informers.NewSharedInformerFactory(client, 0)
    nsInformer := factory.Core().V1().Namespaces().Informer()
    
    controller := &Controller{
        client:          client,
        config:          config,
        informerFactory: factory,
        nsInformer:     nsInformer,
        cipherCache:    NewCipherSuiteCache(),
    }

    nsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
        AddFunc: func(obj interface{}) {
            ns := obj.(*v1.Namespace)
            log.Infof("Namespace added: %s", ns.Name)
        },
        UpdateFunc: controller.handleNamespaceUpdate,
        DeleteFunc: func(obj interface{}) {
            ns := obj.(*v1.Namespace)
            log.Infof("Namespace deleted: %s", ns.Name)
        },
    })

    // Start informer factory
    go factory.Start(make(chan struct{}))

    return controller
}

func (c *Controller) logCacheState() {
    c.cipherCache.RLock()
    defer c.cipherCache.RUnlock()
    
    log.Info("Current CipherSuite Cache State:")
    for namespace, ciphers := range c.cipherCache.store {
        log.Infof("Namespace: %s, Ciphers: %v", namespace, ciphers)
    }
}

func (c *Controller) handleNamespaceUpdate(old, new interface{}) {
    oldNS := old.(*v1.Namespace)
    newNS := new.(*v1.Namespace)

    // Debugging
    log.Infof("handleNamespaceUpdate called for namespace: %s", newNS.Name)
    log.Infof("All annotations: %v", newNS.Annotations)

    log.Infof("Namespace update event received - Namespace: %s", newNS.Name)
    log.Infof("Old annotation: %s", oldNS.Annotations["cipherSuites"])
    log.Infof("New annotation: %s", newNS.Annotations["cipherSuites"])

    if oldNS.Annotations["cipherSuites"] != newNS.Annotations["cipherSuites"] {
        log.Infof("CipherSuite change detected for namespace %s: %s -> %s",
            newNS.Name,
            oldNS.Annotations["cipherSuites"],
            newNS.Annotations["cipherSuites"])
		
		log.Info("Cache state before update:")
		c.logCacheState()

        newCiphers := []string{newNS.Annotations["cipherSuites"]}
        
        c.cipherCache.Set(newNS.Name, []string{newNS.Annotations["cipherSuites"]})

        log.Info("Cache state after update:")
        c.logCacheState()

        // Wait for cache to update
        time.Sleep(time.Second *  2)
        
        if err := c.triggerReconfiguration(newNS.Name); err != nil {
            log.Errorf("Failed to reconfigure namespace %s: %v", newNS.Name, err)
        }

        log.Infof("Completed reconfiguration for namespace %s with new ciphers: %v", newNS.Name, newCiphers)
    } else {
        log.Info("No CipherSuite annotation change detected")
    }
}

func (c *Controller) Run(stopCh chan struct{}) {    
    log.Info("Starting CipherSuite controller")
    defer log.Info("Shutting down CipherSuite controller")
    
    // Start informer
    go c.nsInformer.Run(stopCh)
    
    // Wait for cache sync
    if !cache.WaitForCacheSync(stopCh, c.nsInformer.HasSynced) {
        log.Error("Failed to sync informer cache")
        return
    }
    
    // Wait for stop signal
    <-stopCh
}

// GetCipherSuites returns cipher suites for a namespace
func (c *Controller) GetCipherSuites(namespace string) ([]string, bool) {
    return c.cipherCache.Get(namespace)
}

// UpdateCache updates cipher suites for a namespace
func (c *Controller) UpdateCache(namespace string, ciphers []string) {
    c.cipherCache.Set(namespace, ciphers)
}