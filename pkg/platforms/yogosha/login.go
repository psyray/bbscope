package yogosha

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/sw33tLie/bbscope/v2/pkg/otp"
	"github.com/sw33tLie/bbscope/v2/pkg/whttp"
	"github.com/tidwall/gjson"
)

const (
	keycloakBase   = "https://connect.yogosha.com"
	keycloakRealm  = "researcher"
	keycloakClient = "app-yogosha"
	redirectURI    = "https://app.yogosha.com/signin"
	oidScope       = "api.read api.write reports.process reports.read reports.write user.info yogosha.internal openid"
)

// login performs the Yogosha OIDC Authorization Code + PKCE flow with TOTP.
// It returns a bearer access token for api-cyber.yogosha.com.
//
// The flow has 3 form POSTs (Yogosha uses a custom Keycloak theme that splits
// username, password, and TOTP into separate steps):
//  1. POST username
//  2. POST password
//  3. POST otp (the 6-digit TOTP code) + login button value
//
// After step 3, Keycloak redirects to redirect_uri with ?code=<authz_code>.
// The code is exchanged at the token endpoint using the PKCE code_verifier.
func login(email, password, otpSecret, proxy string) (string, error) {
	if proxy != "" {
		whttp.SetupProxy(proxy)
	}

	verifier, challenge, err := generatePKCE()
	if err != nil {
		return "", fmt.Errorf("failed to generate PKCE: %w", err)
	}
	state, err := randomHex(16)
	if err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", err
	}

	client := retryablehttp.NewClient()
	client.Logger = log.New(io.Discard, "", 0)
	client.RetryMax = 0
	client.HTTPClient.Jar = jar
	// Stop at the redirect to app.yogosha.com so we can capture the authz code
	// from the Location header. Keycloak-internal redirects are followed.
	client.HTTPClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if strings.HasPrefix(req.URL.String(), redirectURI) {
			return http.ErrUseLastResponse
		}
		return nil
	}

	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			return "", fmt.Errorf("invalid proxy URL: %w", err)
		}
		client.HTTPClient.Transport = &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	// Step 1: GET the authorize endpoint → Keycloak returns the username form.
	authParams := url.Values{}
	authParams.Set("client_id", keycloakClient)
	authParams.Set("redirect_uri", redirectURI)
	authParams.Set("response_type", "code")
	authParams.Set("scope", oidScope)
	authParams.Set("state", state)
	authParams.Set("code_challenge", challenge)
	authParams.Set("code_challenge_method", "S256")
	authURL := fmt.Sprintf("%s/auth/realms/%s/protocol/openid-connect/auth?%s",
		keycloakBase, keycloakRealm, authParams.Encode())

	authRes, err := whttp.SendHTTPRequest(&whttp.WHTTPReq{
		Method:  "GET",
		URL:     authURL,
		Headers: []whttp.WHTTPHeader{{Name: "Accept-Language", Value: "fr"}},
	}, client)
	if err != nil {
		return "", fmt.Errorf("authorize request failed: %w", err)
	}
	if authRes.StatusCode >= 400 {
		return "", fmt.Errorf("authorize endpoint returned status %d", authRes.StatusCode)
	}

	formAction, _, err := scrapeLoginForm(authRes.BodyString)
	if err != nil {
		return "", fmt.Errorf("failed to find username form: %w", err)
	}
	formAction = resolveAction(formAction)

	// Step 2: POST username.
	usernameBody := url.Values{}
	usernameBody.Set("username", email)
	unameRes, err := postForm(formAction, usernameBody.Encode(), client)
	if err != nil {
		return "", fmt.Errorf("username POST failed: %w", err)
	}
	if msg := checkFormError(unameRes.BodyString); msg != "" {
		return "", fmt.Errorf("yogosha login: %s", msg)
	}
	formAction, _, err = scrapeLoginForm(unameRes.BodyString)
	if err != nil {
		return "", fmt.Errorf("failed to find password form: %w", err)
	}
	formAction = resolveAction(formAction)

	// Step 3: POST password.
	passwordBody := url.Values{}
	passwordBody.Set("password", password)
	passRes, err := postForm(formAction, passwordBody.Encode(), client)
	if err != nil {
		return "", fmt.Errorf("password POST failed: %w", err)
	}
	if msg := checkFormError(passRes.BodyString); msg != "" {
		return "", fmt.Errorf("yogosha login: %s", msg)
	}
	formAction, loginBtn, err := scrapeLoginForm(passRes.BodyString)
	if err != nil {
		return "", fmt.Errorf("failed to find TOTP form: %w", err)
	}
	formAction = resolveAction(formAction)

	// Step 4: POST TOTP code.
	code, err := otp.GenerateTOTP(otpSecret, time.Now())
	if err != nil {
		return "", fmt.Errorf("failed to generate TOTP: %w", err)
	}
	otpBody := url.Values{}
	otpBody.Set("otp", code)
	if loginBtn != "" {
		otpBody.Set("login", loginBtn)
	}
	otpRes, err := postForm(formAction, otpBody.Encode(), client)
	if err != nil {
		return "", fmt.Errorf("TOTP POST failed: %w", err)
	}
	if msg := checkFormError(otpRes.BodyString); msg != "" {
		return "", fmt.Errorf("yogosha TOTP: %s", msg)
	}
	if otpRes.StatusCode != 302 {
		return "", fmt.Errorf("TOTP verification did not redirect (status %d); credentials or code may be wrong", otpRes.StatusCode)
	}

	location := otpRes.Headers.Get("Location")
	if location == "" {
		return "", fmt.Errorf("TOTP response missing Location header")
	}
	authzCode, err := extractCodeFromLocation(location)
	if err != nil {
		return "", fmt.Errorf("failed to extract authorization code: %w", err)
	}

	// Step 5: Exchange the authorization code for an access token.
	tokenBody := url.Values{}
	tokenBody.Set("grant_type", "authorization_code")
	tokenBody.Set("redirect_uri", redirectURI)
	tokenBody.Set("code", authzCode)
	tokenBody.Set("code_verifier", verifier)
	tokenBody.Set("client_id", keycloakClient)
	tokenURL := fmt.Sprintf("%s/auth/realms/%s/protocol/openid-connect/token",
		keycloakBase, keycloakRealm)
	tokenRes, err := postForm(tokenURL, tokenBody.Encode(), client)
	if err != nil {
		return "", fmt.Errorf("token exchange failed: %w", err)
	}
	if tokenRes.StatusCode != 200 {
		return "", fmt.Errorf("token endpoint returned status %d: %s", tokenRes.StatusCode, tokenRes.BodyString)
	}

	accessToken := gjson.Get(tokenRes.BodyString, "access_token").String()
	if accessToken == "" {
		return "", fmt.Errorf("access_token not found in token response")
	}
	return accessToken, nil
}

func postForm(targetURL, body string, client *retryablehttp.Client) (*whttp.WHTTPRes, error) {
	return whttp.SendHTTPRequest(&whttp.WHTTPReq{
		Method: "POST",
		URL:    targetURL,
		Headers: []whttp.WHTTPHeader{
			{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
			{Name: "Accept-Language", Value: "fr"},
		},
		Body: body,
	}, client)
}

// scrapeLoginForm parses a Keycloak login HTML page and returns the form
// action URL and, if present, the named submit button's value (used for the
// TOTP step's "login" field).
func scrapeLoginForm(htmlBody string) (action, loginButtonValue string, err error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlBody))
	if err != nil {
		return "", "", fmt.Errorf("failed to parse HTML: %w", err)
	}
	form := doc.Find("form").First()
	if form.Length() == 0 {
		return "", "", fmt.Errorf("no form element found")
	}
	action, exists := form.Attr("action")
	if !exists || action == "" {
		return "", "", fmt.Errorf("form has no action attribute")
	}
	// Look for a submit button/input named "login" (TOTP step).
	btn := doc.Find(`button[name="login"]`).First()
	if btn.Length() == 0 {
		btn = doc.Find(`input[name="login"]`).First()
	}
	if btn.Length() > 0 {
		loginButtonValue, _ = btn.Attr("value")
	}
	return action, loginButtonValue, nil
}

// resolveAction resolves a form action URL that may be relative (Keycloak
// typically returns paths starting with /auth/realms/...).
func resolveAction(action string) string {
	if strings.HasPrefix(action, "http://") || strings.HasPrefix(action, "https://") {
		return action
	}
	if strings.HasPrefix(action, "/") {
		return keycloakBase + action
	}
	return keycloakBase + "/" + action
}

// checkFormError looks for Keycloak error messages in the HTML response.
func checkFormError(htmlBody string) string {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlBody))
	if err != nil {
		return ""
	}
	// Keycloak default theme uses .kc-feedback-error; custom themes may differ.
	sel := doc.Find(".kc-feedback-error, .alert-error, .pf-c-alert--danger, .error-message").First()
	if sel.Length() > 0 {
		return strings.TrimSpace(sel.Text())
	}
	return ""
}

// extractCodeFromLocation parses the redirect Location header and returns the
// OAuth2 authorization code.
func extractCodeFromLocation(loc string) (string, error) {
	u, err := url.Parse(loc)
	if err != nil {
		return "", err
	}
	code := u.Query().Get("code")
	if code == "" {
		return "", fmt.Errorf("no code parameter in redirect URL: %s", loc)
	}
	return code, nil
}

// generatePKCE creates a PKCE code_verifier and its S256 code_challenge.
func generatePKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// randomHex returns n random bytes as a hex string.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
