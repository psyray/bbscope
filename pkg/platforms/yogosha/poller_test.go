package yogosha

import (
	"testing"

	"github.com/sw33tLie/bbscope/v2/pkg/scope"
)

func TestClassifyYogoshaScope(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   string
	}{
		{"plain URL", "https://www.fdj.fr", "url"},
		{"google play", "https://play.google.com/store/apps/details?id=com.fdj.parionssport&hl=fr&gl=FR", "google_play_app_id"},
		{"apple store", "https://apps.apple.com/fr/app/parions-sport-point-de-vente/id496184783", "apple_store_app_id"},
		{"apple store http", "http://apps.apple.com/fr/app/fdj/id1222993561", "apple_store_app_id"},
		{"subdomain URL", "https://espacepro.groupeadp.fr/default.aspx", "url"},
		{"wildcard", "*.malt.com", "wildcard"},
		{"wildcard subdomain", "*.surfrider.eu", "wildcard"},
		{"generic URL", "https://www.groupefdj.com", "url"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyYogoshaScope(tt.target)
			// Verify the raw category normalizes to the expected unified category.
			normalized := scope.NormalizeCategory(got)
			wantNormalized := scope.NormalizeCategory(tt.want)
			if normalized != wantNormalized {
				t.Errorf("classifyYogoshaScope(%q) = %q (normalized: %q), want normalized: %q",
					tt.target, got, normalized, wantNormalized)
			}
		})
	}
}

func TestExtractCodeFromLocation(t *testing.T) {
	tests := []struct {
		name    string
		loc     string
		want    string
		wantErr bool
	}{
		{
			name: "valid redirect",
			loc:  "https://app.yogosha.com/signin?state=f26ebb61d11549108f9ff2f5e3722ec8&session_state=ir4HtCv8WEbycW5ozc7LQgNk&iss=https%3A%2F%2Fconnect.yogosha.com%2Fauth%2Frealms%2Fresearcher&code=f9374fb6-05ac-6dd4-f60b-8bc7c63cdf4b.ir4HtCv8WEbycW5ozc7LQgNk.ec047d66-8e2a-45de-a6a4-e1929458ae25",
			want: "f9374fb6-05ac-6dd4-f60b-8bc7c63cdf4b.ir4HtCv8WEbycW5ozc7LQgNk.ec047d66-8e2a-45de-a6a4-e1929458ae25",
		},
		{
			name:    "missing code",
			loc:     "https://app.yogosha.com/signin?state=abc&error=access_denied",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractCodeFromLocation(tt.loc)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractCodeFromLocation(%q) error = %v, wantErr %v", tt.loc, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("extractCodeFromLocation(%q) = %q, want %q", tt.loc, got, tt.want)
			}
		})
	}
}

func TestResolveAction(t *testing.T) {
	tests := []struct {
		name   string
		action string
		want   string
	}{
		{"absolute https", "https://connect.yogosha.com/auth/realms/researcher/login-actions/authenticate?x=1", "https://connect.yogosha.com/auth/realms/researcher/login-actions/authenticate?x=1"},
		{"root-relative", "/auth/realms/researcher/login-actions/authenticate?session_code=abc", "https://connect.yogosha.com/auth/realms/researcher/login-actions/authenticate?session_code=abc"},
		{"relative", "login-actions/authenticate", "https://connect.yogosha.com/login-actions/authenticate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveAction(tt.action)
			if got != tt.want {
				t.Errorf("resolveAction(%q) = %q, want %q", tt.action, got, tt.want)
			}
		})
	}
}
