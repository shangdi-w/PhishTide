package store

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestPayloadAttachmentEncryptedRoundTrip(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "att.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	st.SetSecretKey(key)

	plain := []byte("MZ\x90\x00fake-payload-bytes")
	id, err := st.AddPayloadAttachment(PayloadAttachment{Name: "sample.zip", ContentType: "application/zip", Note: "演练样本"}, plain)
	if err != nil {
		t.Fatal(err)
	}

	// The bytes on disk must not equal the plaintext when a key is configured.
	var raw []byte
	if err := st.db.QueryRow(`SELECT body FROM payload_attachments WHERE id = ?`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(raw, plain) {
		t.Fatal("payload stored in plaintext")
	}

	list, err := st.ListPayloadAttachments()
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %+v err=%v", list, err)
	}
	if list[0].Name != "sample.zip" || list[0].SizeBytes != int64(len(plain)) || list[0].SHA256 == "" {
		t.Fatalf("metadata = %+v", list[0])
	}

	a, body, err := st.GetPayloadAttachment(id)
	if err != nil || a.Name != "sample.zip" {
		t.Fatalf("get = %+v err=%v", a, err)
	}
	if !bytes.Equal(body, plain) {
		t.Fatalf("decrypted bytes differ: %q", body)
	}

	if err := st.DeletePayloadAttachment(id); err != nil {
		t.Fatal(err)
	}
	if list, _ := st.ListPayloadAttachments(); len(list) != 0 {
		t.Fatalf("delete left rows: %+v", list)
	}
}
