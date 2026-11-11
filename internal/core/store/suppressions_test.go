package store

import (
	"path/filepath"
	"testing"
)

func TestSuppressionStore(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "sup.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.UpsertSuppression("Alice@Example.com", "hard_bounce", "550"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSuppression("bob@example.com", "manual", ""); err != nil {
		t.Fatal(err)
	}
	list, err := st.ListSuppressions(10)
	if err != nil || len(list) != 2 {
		t.Fatalf("list = %+v err=%v", list, err)
	}
	set, _ := st.SuppressionSet()
	if !set["alice@example.com"] || !set["bob@example.com"] {
		t.Fatalf("set = %+v", set)
	}
	if ok, _ := st.DeleteSuppression("ALICE@example.com"); !ok {
		t.Fatal("delete failed")
	}
	if ok, _ := st.DeleteSuppression("alice@example.com"); ok {
		t.Fatal("double delete should report false")
	}
	if list, _ := st.ListSuppressions(10); len(list) != 1 {
		t.Fatalf("after delete = %+v", list)
	}
}
