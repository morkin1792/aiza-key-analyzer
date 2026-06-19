package analyzer

import (
	"strings"
	"testing"
)

// TestRewriteSignupPoCForPassword verifies that an anonymous-signup PoC line is
// rewritten to the email/password equivalent (so PoCs reproduce findings that
// were confirmed with a registered session), and that PoCs without a signup
// line are left untouched.
func TestRewriteSignupPoCForPassword(t *testing.T) {
	anon := `TOKEN=$(curl -s -X POST 'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=AIzaXXX' -H 'Content-Type: application/json' -d '{"returnSecureToken":true}' | jq -r .idToken)
curl -s "https://proj.firebaseio.com/.json?auth=${TOKEN}"`

	got := rewriteSignupPoCForPassword(anon)
	if !strings.Contains(got, `"email":"aiza-poc@no.invalid"`) || !strings.Contains(got, `"password":"AizaPoc1!"`) {
		t.Fatalf("expected email/password signup payload, got:\n%s", got)
	}
	if strings.Contains(got, anonSignupPayload) {
		t.Fatalf("anonymous payload should be gone, got:\n%s", got)
	}

	// No signup line → unchanged.
	noSignup := `curl -s 'https://proj.firebaseio.com/.json'`
	if rewriteSignupPoCForPassword(noSignup) != noSignup {
		t.Fatalf("expected no-op on PoC without a signup line")
	}
}
