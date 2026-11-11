package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"phishsim/internal/core/store"
)

func TestDeleteSendingProfile(t *testing.T) {
	s := newSettingsTestServer(t)
	id, err := s.Store.UpsertSendingProfile(store.SendingProfile{
		Name: "qq", Host: "smtp.qq.com", Port: 465, Username: "a@qq.com",
		TLSMode: "ssl", FromEmail: "a@qq.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodDelete, "/__admin/api/profiles/"+itoa64(id), nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	list, err := s.Store.ListSendingProfiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("profile still present: %+v", list)
	}
	// Deleting a missing profile reports a clean error.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/__admin/api/profiles/"+itoa64(id), nil)
	req.Header.Set("Authorization", "Bearer test-key")
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("second delete: %d", rec.Code)
	}
}
