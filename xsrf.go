package xsrf

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/daaku/go.browserid"
)

var (
	DefaultMaxAge = 24 * time.Hour
	DefaultSumLen = uint(10)
	maxUint64Len  = uint(len(fmt.Sprintf("%d", uint64(1<<63))))
)

// The Provider issues and validates tokens.
type Provider struct {
	MaxAge    time.Duration     // Max-Age for tokens
	SumLen    uint              // Amount of characters from the sum to use
	BrowserID *browserid.Cookie // Browser ID cookie accessor
}

// Get a token for the given request. Optional additional "bits" may
// be specified to generate unique tokens for actions. This may issue
// a cookie if necessary.
func (p *Provider) Token(w http.ResponseWriter, r *http.Request, bits ...string) string {
	return p.genToken(p.BrowserID.Get(w, r), time.Now(), bits...)
}

// Validate a token.
func (p *Provider) Validate(token string, w http.ResponseWriter, r *http.Request, bits ...string) bool {
	if token == "" {
		return false
	}
	pair, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return false
	}
	if uint(len(pair)) < p.SumLen {
		return false
	}
	unixNano, err := strconv.ParseInt(string(pair[p.SumLen:]), 10, 64)
	if err != nil {
		return false
	}
	issueTime := time.Unix(0, unixNano)
	if time.Now().Sub(issueTime) >= p.MaxAge {
		return false
	}
	expected := p.genToken(p.BrowserID.Get(w, r), issueTime, bits...)
	return token == expected
}

func (p *Provider) genToken(key string, t time.Time, bits ...string) string {
	h := hmac.New(sha1.New, []byte(key))
	for _, bit := range bits {
		fmt.Fprint(h, bit)
	}
	fmt.Fprint(h, t)
	out := bytes.NewBuffer(make([]byte, 0, p.SumLen+maxUint64Len+1))
	_, err := fmt.Fprintf(out, "%s%d", h.Sum(nil)[:p.SumLen], t.UnixNano())
	if err != nil {
		log.Fatalf("Failed to create token: %s", err)
	}
	return base64.URLEncoding.EncodeToString(out.Bytes())
}

// Provider defined by flags.
func ProviderFlag(name string) *Provider {
	p := &Provider{}
	flag.DurationVar(
		&p.MaxAge,
		name+".max-age",
		DefaultMaxAge,
		name+" max age for tokens.",
	)
	flag.UintVar(
		&p.SumLen,
		name+".sum-len",
		DefaultSumLen,
		name+" number of bytes from sum to use.",
	)
	return p
}
