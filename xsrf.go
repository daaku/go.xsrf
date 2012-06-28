package xsrf

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/nshah/go.browserid"
	"log"
	"net/http"
	"strconv"
	"time"
)

var (
	maxAge = flag.Duration(
		"xsrf.max-age", 24*time.Hour, "Max age for tokens.")
	sumLen = flag.Int(
		"xsrf.sum-len", 10, "Number of bytes from sum to use.")
	maxUint64Len = len(fmt.Sprintf("%d", uint64(1<<63)))
)

// Get a token for the given request. Optional additional "bits" may
// be specified to generate unique tokens for actions.
func Token(w http.ResponseWriter, r *http.Request, bits ...string) string {
	return genToken(browserid.Get(w, r), time.Now(), bits...)
}

// Validate a token.
func Validate(token string, w http.ResponseWriter, r *http.Request, bits ...string) bool {
	if token == "" {
		return false
	}
	pair, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return false
	}
	unixNano, err := strconv.ParseInt(string(pair[*sumLen:]), 10, 64)
	if err != nil {
		return false
	}
	issueTime := time.Unix(0, unixNano)
	if time.Now().Sub(issueTime) >= *maxAge {
		return false
	}
	expected := genToken(browserid.Get(w, r), issueTime, bits...)
	return token == expected
}

func genToken(key string, t time.Time, bits ...string) string {
	h := hmac.New(sha1.New, []byte(key))
	for _, bit := range bits {
		fmt.Fprint(h, bit)
	}
	fmt.Fprint(h, t)
	out := bytes.NewBuffer(make([]byte, 0, *sumLen+maxUint64Len+1))
	_, err := fmt.Fprintf(out, "%s%d", h.Sum(nil)[:*sumLen], t.UnixNano())
	if err != nil {
		log.Fatalf("Failed to create token: %s", err)
	}
	return base64.URLEncoding.EncodeToString(out.Bytes())
}
