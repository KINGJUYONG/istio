package ciphersuites

import (
    "sync"
)

type CipherSuiteCache struct {
    sync.RWMutex
    store map[string][]string
}

func NewCipherSuiteCache() *CipherSuiteCache {
    return &CipherSuiteCache{
        store: make(map[string][]string),
    }
}

func (c *CipherSuiteCache) Set(namespace string, ciphers []string) {
    c.Lock()
    defer c.Unlock()
    c.store[namespace] = ciphers
}

func (c *CipherSuiteCache) Get(namespace string) ([]string, bool) {
    c.RLock()
    defer c.RUnlock()
    ciphers, exists := c.store[namespace]
    return ciphers, exists
}