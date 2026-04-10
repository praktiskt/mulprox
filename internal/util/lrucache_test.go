package util

import (
	"fmt"
	"testing"
)

func TestLRUCache_SetAndGet(t *testing.T) {
	cache := NewLRUCache[string](3)

	cache.Set("a", "value-a")
	cache.Set("b", "value-b")
	cache.Set("c", "value-c")

	if v, ok := cache.Get("a"); !ok || v != "value-a" {
		t.Errorf("expected value-a, got %v", v)
	}
	if v, ok := cache.Get("b"); !ok || v != "value-b" {
		t.Errorf("expected value-b, got %v", v)
	}
	if v, ok := cache.Get("c"); !ok || v != "value-c" {
		t.Errorf("expected value-c, got %v", v)
	}
}

func TestLRUCache_Eviction(t *testing.T) {
	cache := NewLRUCache[string](3)

	cache.Set("a", "value-a")
	cache.Set("b", "value-b")
	cache.Set("c", "value-c")

	cache.Set("d", "value-d")

	if _, ok := cache.Get("a"); ok {
		t.Error("expected 'a' to be evicted")
	}
	if _, ok := cache.Get("d"); !ok {
		t.Error("expected 'd' to exist")
	}
}

func TestLRUCache_UpdateExisting(t *testing.T) {
	cache := NewLRUCache[string](3)

	cache.Set("a", "value-a")
	cache.Set("a", "value-a-updated")

	if v, ok := cache.Get("a"); !ok || v != "value-a-updated" {
		t.Errorf("expected value-a-updated, got %v", v)
	}
	if cache.Len() != 1 {
		t.Errorf("expected length 1, got %d", cache.Len())
	}
}

func TestLRUCache_Delete(t *testing.T) {
	cache := NewLRUCache[string](3)

	cache.Set("a", "value-a")
	cache.Delete("a")

	if _, ok := cache.Get("a"); ok {
		t.Error("expected 'a' to be deleted")
	}
	if cache.Len() != 0 {
		t.Errorf("expected length 0, got %d", cache.Len())
	}
}

func TestLRUCache_Clear(t *testing.T) {
	cache := NewLRUCache[string](3)

	cache.Set("a", "value-a")
	cache.Set("b", "value-b")
	cache.Clear()

	if cache.Len() != 0 {
		t.Errorf("expected length 0, got %d", cache.Len())
	}
}

func TestLRUCache_GetNotFound(t *testing.T) {
	cache := NewLRUCache[string](3)

	if _, ok := cache.Get("nonexistent"); ok {
		t.Error("expected not found")
	}
}

func TestLRUCache_EvictionBeyondDefault(t *testing.T) {
	cache := NewLRUCache[string](0)

	for i := 0; i < 55; i++ {
		key := string(rune(i + 'a'))
		val := fmt.Sprintf("value-%d", i)
		cache.Set(key, val)
	}

	if cache.Len() != 50 {
		t.Errorf("expected 50 entries after adding 55, got %d", cache.Len())
	}

	if _, ok := cache.Get("a"); ok {
		t.Error("expected 'a' to be evicted after 55 insertions")
	}

	if v, ok := cache.Get("z"); !ok || v != "value-25" {
		t.Errorf("expected 'z' to still exist, got %v", v)
	}
}
