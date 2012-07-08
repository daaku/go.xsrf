package xsrf_test

import (
	"github.com/daaku/go.xsrf"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	serverURL = "http://example.com/"
	bitUno    = "bitUno"
)

func TestToken(t *testing.T) {
	w := httptest.NewRecorder()
	req, err := http.NewRequest("GET", serverURL, nil)
	if err != nil {
		t.Fatalf("Unexpected error creating new request: %s", err)
	}
	token1 := xsrf.Token(w, req)
	if token1 == "" {
		t.Fatalf("Was expecting non empty token1.")
	}
	token2 := xsrf.Token(w, req, bitUno)
	if token2 == "" {
		t.Fatalf("Was expecting non empty token2.")
	}
	if token1 == token2 {
		t.Fatalf("Was expecting different tokens.")
	}
	if !xsrf.Validate(token1, w, req) {
		t.Fatalf("Failed to validate token1.")
	}
	if !xsrf.Validate(token2, w, req, bitUno) {
		t.Fatalf("Failed to validate token2.")
	}
	if xsrf.Validate("", w, req) {
		t.Fatalf("Empty token should not be valid.")
	}
	if xsrf.Validate(token1, w, req, "foo") {
		t.Fatalf("Token should not be valid for foo.")
	}
}
