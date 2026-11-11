package pdftext

import (
	"bytes"
	"compress/zlib"
	"strings"
	"testing"
)

func TestExtractPlainStream(t *testing.T) {
	pdf := []byte("%PDF-1.4\n1 0 obj << /Length 44 >> stream\nBT /F1 12 Tf 72 720 Td (Hello PDF) Tj ET\nendstream endobj\n%%EOF")
	got := Extract(pdf, 1000)
	if !strings.Contains(got, "Hello PDF") {
		t.Fatalf("extract = %q", got)
	}
}

func TestExtractFlateStreamAndArray(t *testing.T) {
	content := "BT /F1 12 Tf 72 720 Td [(Flate) -250 (PDF)] TJ ET"
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	_, _ = zw.Write([]byte(content))
	_ = zw.Close()
	pdf := append([]byte("%PDF-1.4\n1 0 obj << /Filter /FlateDecode >> stream\n"), z.Bytes()...)
	pdf = append(pdf, []byte("\nendstream endobj")...)
	got := Extract(pdf, 1000)
	if !strings.Contains(got, "Flate") || !strings.Contains(got, "PDF") {
		t.Fatalf("extract = %q", got)
	}
}

func TestExtractEncryptedReturnsEmpty(t *testing.T) {
	pdf := []byte("%PDF-1.4\n1 0 obj << /Encrypt 2 0 R >> stream\n(secret) Tj\nendstream")
	if got := Extract(pdf, 1000); got != "" {
		t.Fatalf("encrypted pdf extracted %q", got)
	}
}

func TestExtractTruncates(t *testing.T) {
	pdf := []byte("%PDF-1.4\nstream\n(" + strings.Repeat("x", 5000) + ") Tj\nendstream")
	got := Extract(pdf, 100)
	if len([]rune(got)) != 100 {
		t.Fatalf("len = %d", len([]rune(got)))
	}
}
