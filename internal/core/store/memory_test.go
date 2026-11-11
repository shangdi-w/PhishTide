package store

import (
	"path/filepath"
	"testing"
)

func TestAgentMemoryUpsertSearchDelete(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "mem.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.UpsertAgentMemory("发件邮箱", "ops@example.com", "preference"); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertAgentMemory("语气", "正式", "preference"); err != nil {
		t.Fatal(err)
	}
	// Upsert must replace, not duplicate.
	if err := s.UpsertAgentMemory("发件邮箱", "security@example.com", "preference"); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.CountAgentMemories(); n != 2 {
		t.Fatalf("count = %d", n)
	}
	all, err := s.ListAgentMemories(10)
	if err != nil || len(all) != 2 {
		t.Fatalf("list = %+v, err = %v", all, err)
	}
	found := false
	for _, m := range all {
		if m.Key == "发件邮箱" && m.Value == "security@example.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("upsert did not replace: %+v", all)
	}

	hits, err := s.SearchAgentMemories("example.com", 10)
	if err != nil || len(hits) != 1 || hits[0].Key != "发件邮箱" {
		t.Fatalf("search = %+v, err = %v", hits, err)
	}
	hits, _ = s.SearchAgentMemories("语气", 10)
	if len(hits) != 1 || hits[0].Value != "正式" {
		t.Fatalf("key search = %+v", hits)
	}

	ok, err := s.DeleteAgentMemory("语气")
	if err != nil || !ok {
		t.Fatalf("delete = %v, err = %v", ok, err)
	}
	if ok, _ := s.DeleteAgentMemory("语气"); ok {
		t.Fatal("deleted a missing memory")
	}
	if n, _ := s.CountAgentMemories(); n != 1 {
		t.Fatalf("count after delete = %d", n)
	}
}
