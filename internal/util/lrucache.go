package util

import (
	"container/list"
	"sync"
	"time"
)

type CacheEntry[V any] struct {
	Value      V
	Key        string
	AccessTime time.Time
}

type LRUCache[V any] struct {
	mu         sync.RWMutex
	entries    map[string]*list.Element
	list       *list.List
	maxEntries int
	onEvict    func(V)
}

func NewLRUCache[V any](maxEntries int) *LRUCache[V] {
	if maxEntries <= 0 {
		maxEntries = 50
	}
	return &LRUCache[V]{
		entries:    make(map[string]*list.Element),
		list:       list.New(),
		maxEntries: maxEntries,
	}
}

func NewLRUCacheWithEvict[V any](maxEntries int, onEvict func(V)) *LRUCache[V] {
	c := NewLRUCache[V](maxEntries)
	c.onEvict = onEvict
	return c
}

func (c *LRUCache[V]) Get(key string) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.entries[key]; ok {
		c.list.MoveToFront(elem)
		return elem.Value.(*CacheEntry[V]).Value, true
	}
	var zero V
	return zero, false
}

func (c *LRUCache[V]) Set(key string, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.entries[key]; ok {
		c.list.MoveToFront(elem)
		elem.Value.(*CacheEntry[V]).Value = value
		elem.Value.(*CacheEntry[V]).AccessTime = time.Now()
		return
	}

	entry := &CacheEntry[V]{
		Value:      value,
		Key:        key,
		AccessTime: time.Now(),
	}
	elem := c.list.PushFront(entry)
	c.entries[key] = elem

	for c.list.Len() > c.maxEntries {
		oldestElem := c.list.Back()
		if oldestElem != nil {
			oldest := oldestElem.Value.(*CacheEntry[V])
			delete(c.entries, oldest.Key)
			c.list.Remove(oldestElem)
			if c.onEvict != nil {
				c.onEvict(oldest.Value)
			}
		}
	}
}

func (c *LRUCache[V]) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.entries[key]; ok {
		delete(c.entries, key)
		c.list.Remove(elem)
	}
}

func (c *LRUCache[V]) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.list.Len()
}

func (c *LRUCache[V]) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*list.Element)
	c.list.Init()
}
