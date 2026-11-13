package hibp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHIBP(t *testing.T) {
	// SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8.
	var gotPath, gotPadding string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotPadding = r.URL.Path, r.Header.Get("Add-Padding")
		_, _ = w.Write([]byte("0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\r\n"))
	}))
	defer srv.Close()
	h := &Client{HTTP: srv.Client(), Base: srv.URL + "/range/"}
	n, err := h.Count(context.Background(), []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 42 {
		t.Errorf("count = %d", n)
	}
	if gotPath != "/range/5BAA6" {
		t.Errorf("sent %q: only the 5-character prefix may leave", gotPath)
	}
	if gotPadding != "true" {
		t.Error("padding not requested")
	}
	if n, err := h.Count(context.Background(), []byte("not in the list at all")); err != nil || n != 0 {
		t.Errorf("clean password: %d %v", n, err)
	}
}

func TestHIBPFailureHidesPassword(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	h := &Client{HTTP: srv.Client(), Base: srv.URL + "/"}
	_, err := h.Count(context.Background(), []byte("hunter2hunter2"))
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("err = %v", err)
	}
	if New().Base != hibpBase {
		t.Error("default base changed")
	}
}
