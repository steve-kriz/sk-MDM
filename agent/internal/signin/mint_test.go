package signin

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/officehq/sk-mdm/agent/internal/platform/fake"
)

type poster func() (*http.Response, error)

func (p poster) PostPublicBearer(string, []byte, string) (*http.Response, error) { return p() }

func TestMintEnrollmentToken(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		want    string
		refused bool
		failed  bool
		code    string
	}{
		{name: "created", status: 201, body: `{"tokenId":"a","token":" tok.en ","expiresAt":"x"}`, want: "tok.en"},
		{name: "no token", status: 201, body: `{"tokenId":"a"}`, failed: true},
		{name: "missing bearer", status: 401, body: `{"error":"user_token_missing"}`, refused: true, code: "user_token_missing"},
		{name: "invalid", status: 401, body: `{"error":"invalid_user_token"}`, refused: true, code: "invalid_user_token"},
		{name: "jwks", status: 503, body: `{"error":"jwks_unavailable"}`, failed: true, code: "jwks_unavailable"},
		{name: "not configured", status: 500, body: `{"error":"not_configured"}`, failed: true, code: "not_configured"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := MintEnrollmentToken(poster(func() (*http.Response, error) {
				return fake.Response(tc.status, tc.body), nil
			}), "ACCESS")
			if tc.want != "" {
				if err != nil || got != tc.want {
					t.Fatalf("got %q, %v", got, err)
				}
				return
			}
			if err == nil {
				t.Fatal("want an error")
			}
			if errors.Is(err, ErrMintRefused) != tc.refused {
				t.Errorf("refused = %v, want %v (%v)", errors.Is(err, ErrMintRefused), tc.refused, err)
			}
			if tc.code != "" && !strings.Contains(err.Error(), tc.code) {
				t.Errorf("error %q lacks %q", err, tc.code)
			}
		})
	}

	_, err := MintEnrollmentToken(poster(func() (*http.Response, error) { return nil, errors.New("reset") }), "ACCESS")
	if err == nil || errors.Is(err, ErrMintRefused) {
		t.Errorf("transport failure: %v", err)
	}
}
