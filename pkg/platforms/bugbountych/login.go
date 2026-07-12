package bugbountych

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/sw33tLie/bbscope/v2/pkg/otp"
	"github.com/sw33tLie/bbscope/v2/pkg/whttp"
	"github.com/tidwall/gjson"

	"github.com/hashicorp/go-retryablehttp"
)

const (
	userAgent = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0 bbscope"

	b2cTenant      = "bugbountychportal.onmicrosoft.com"
	b2cPolicy      = "B2C_1A_signup_signin_with_totp_BBS_Platform"
	b2cClientID    = "97ead524-47bc-437b-bc15-6f468ddaca7a"
	b2cRedirectURI = "https://app.bugbounty.ch/"
	b2cScope       = "openid profile offline_access"
	apiScope       = "https://bugbountychportal.onmicrosoft.com/97ead524-47bc-437b-bc15-6f468ddaca7a/user_access openid profile offline_access"
)

var (
	csrfRe    = regexp.MustCompile(`"csrf":"([^"]*)"`)
	transIDRe = regexp.MustCompile(`"transId":"([^"]*)"`)
)

// Login performs the Azure AD B2C login flow for BugBounty.ch and returns the
// API access token used to call api-hacker.bugbounty.ch.
//
// The flow is: PKCE + authorize → credentials POST → TOTP POST → confirmed GET
// (302 with #code= fragment) → token exchange (authz_code) → token exchange
// (refresh_token for the API scope).
func Login(email, password, otpSecret, proxy string) (string, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", fmt.Errorf("create cookie jar: %w", err)
	}

	retryClient := retryablehttp.NewClient()
	retryClient.Logger = log.New(io.Discard, "", 0)
	retryClient.RetryMax = 0
	retryClient.CheckRetry = func(_ context.Context, _ *http.Response, _ error) (bool, error) {
		return false, nil
	}
	retryClient.HTTPClient.Jar = jar

	// Stop at the 302 to app.bugbounty.ch so we can capture the Location header
	// containing the #code= fragment. Browsers would drop the fragment when
	// following the redirect, so we must intercept it here.
	retryClient.HTTPClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if strings.HasPrefix(req.URL.String(), b2cRedirectURI) {
			return http.ErrUseLastResponse
		}
		if len(via) >= 20 {
			return errors.New("stopped after 20 redirects")
		}
		return nil
	}

	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			return "", fmt.Errorf("invalid proxy URL: %v", err)
		}
		retryClient.HTTPClient.Transport = &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
		if err := whttp.SetupProxy(proxy); err != nil {
			return "", fmt.Errorf("setup proxy: %w", err)
		}
	}

	// Step 1: PKCE
	codeVerifier, codeChallenge, state, nonce, err := generatePKCE()
	if err != nil {
		return "", fmt.Errorf("generate pkce: %w", err)
	}

	// Step 2: GET authorize
	authorizeURL := fmt.Sprintf(
		"https://bugbountychportal.b2clogin.com/%s/%s/oauth2/v2.0/authorize?client_id=%s&scope=openid+profile+offline_access&redirect_uri=%s&response_mode=fragment&client_info=1&response_type=code&code_challenge=%s&code_challenge_method=S256&state=%s&nonce=%s",
		b2cTenant, b2cPolicy, b2cClientID,
		url.QueryEscape(b2cRedirectURI),
		codeChallenge, state, nonce,
	)

	authorizeRes, err := whttp.SendHTTPRequest(&whttp.WHTTPReq{
		Method: "GET",
		URL:    authorizeURL,
		Headers: []whttp.WHTTPHeader{
			{Name: "User-Agent", Value: userAgent},
			{Name: "Accept", Value: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		},
	}, retryClient)
	if err != nil {
		return "", fmt.Errorf("authorize request: %w", err)
	}
	if authorizeRes.StatusCode != 200 {
		return "", fmt.Errorf("authorize endpoint returned status %d: %s", authorizeRes.StatusCode, previewBody(authorizeRes.BodyString))
	}

	csrf, transID, err := scrapeCSRFAndTransID(authorizeRes.BodyString)
	if err != nil {
		return "", fmt.Errorf("scrape authorize page: %w", err)
	}

	// Step 3: POST credentials
	selfAssertedURL := fmt.Sprintf(
		"https://bugbountychportal.b2clogin.com/%s/%s/SelfAsserted?tx=%s&p=%s",
		b2cTenant, b2cPolicy, url.QueryEscape(transID), b2cPolicy,
	)
	credBody := fmt.Sprintf("request_type=RESPONSE&signInName=%s&password=%s",
		url.QueryEscape(email), url.QueryEscape(password))

	credRes, err := whttp.SendHTTPRequest(&whttp.WHTTPReq{
		Method: "POST",
		URL:    selfAssertedURL,
		Body:   credBody,
		Headers: []whttp.WHTTPHeader{
			{Name: "User-Agent", Value: userAgent},
			{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
			{Name: "Accept", Value: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		},
	}, retryClient)
	if err != nil {
		return "", fmt.Errorf("credentials post: %w", err)
	}
	if credRes.StatusCode != 200 {
		return "", fmt.Errorf("credentials endpoint returned status %d: %s", credRes.StatusCode, previewBody(credRes.BodyString))
	}

	// Scrape new csrf + transId from the TOTP form page
	csrf, transID, err = scrapeCSRFAndTransID(credRes.BodyString)
	if err != nil {
		return "", fmt.Errorf("scrape credentials response: %w", err)
	}

	// Step 4: POST TOTP
	if otpSecret == "" {
		return "", errors.New("otp secret is required for BugBounty.ch login")
	}
	totpCode, err := otp.GenerateTOTP(otpSecret, time.Now())
	if err != nil {
		return "", fmt.Errorf("generate totp: %w", err)
	}

	selfAssertedURL2 := fmt.Sprintf(
		"https://bugbountychportal.b2clogin.com/%s/%s/SelfAsserted?tx=%s&p=%s",
		b2cTenant, b2cPolicy, url.QueryEscape(transID), b2cPolicy,
	)
	totpBody := fmt.Sprintf("request_type=RESPONSE&otp=%s", url.QueryEscape(totpCode))

	totpRes, err := whttp.SendHTTPRequest(&whttp.WHTTPReq{
		Method: "POST",
		URL:    selfAssertedURL2,
		Body:   totpBody,
		Headers: []whttp.WHTTPHeader{
			{Name: "User-Agent", Value: userAgent},
			{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
			{Name: "Accept", Value: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		},
	}, retryClient)
	if err != nil {
		return "", fmt.Errorf("totp post: %w", err)
	}
	if totpRes.StatusCode != 200 {
		return "", fmt.Errorf("totp endpoint returned status %d: %s", totpRes.StatusCode, previewBody(totpRes.BodyString))
	}

	// Scrape csrf + transId again (confirmed endpoint needs fresh values)
	csrf, transID, err = scrapeCSRFAndTransID(totpRes.BodyString)
	if err != nil {
		return "", fmt.Errorf("scrape totp response: %w", err)
	}

	// Step 5: GET confirmed (expect 302 to app.bugbounty.ch/#code=...&state=...)
	confirmedURL := fmt.Sprintf(
		"https://bugbountychportal.b2clogin.com/%s/%s/api/SelfAsserted/confirmed?csrf_token=%s&tx=%s&p=%s",
		b2cTenant, b2cPolicy, url.QueryEscape(csrf), url.QueryEscape(transID), b2cPolicy,
	)

	confirmedRes, err := whttp.SendHTTPRequest(&whttp.WHTTPReq{
		Method: "GET",
		URL:    confirmedURL,
		Headers: []whttp.WHTTPHeader{
			{Name: "User-Agent", Value: userAgent},
			{Name: "Accept", Value: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		},
	}, retryClient)
	if err != nil {
		return "", fmt.Errorf("confirmed request: %w", err)
	}
	if confirmedRes.StatusCode != 302 {
		return "", fmt.Errorf("confirmed endpoint returned status %d (expected 302): %s", confirmedRes.StatusCode, previewBody(confirmedRes.BodyString))
	}

	location := confirmedRes.Headers.Get("Location")
	if location == "" {
		return "", errors.New("confirmed endpoint returned 302 but no Location header")
	}

	// Step 6: Extract authz code from the Location fragment
	authzCode, err := extractAuthzCode(location, state)
	if err != nil {
		return "", fmt.Errorf("extract authz code: %w", err)
	}

	// Step 7: POST token (authorization_code)
	tokenURL := fmt.Sprintf(
		"https://bugbountychportal.b2clogin.com/%s/%s/oauth2/v2.0/token",
		b2cTenant, b2cPolicy,
	)
	tokenBody := fmt.Sprintf(
		"client_id=%s&redirect_uri=%s&scope=%s&code=%s&code_verifier=%s&grant_type=authorization_code&client_info=1",
		b2cClientID, url.QueryEscape(b2cRedirectURI), url.QueryEscape(b2cScope),
		url.QueryEscape(authzCode), url.QueryEscape(codeVerifier),
	)

	tokenRes, err := whttp.SendHTTPRequest(&whttp.WHTTPReq{
		Method: "POST",
		URL:    tokenURL,
		Body:   tokenBody,
		Headers: []whttp.WHTTPHeader{
			{Name: "User-Agent", Value: userAgent},
			{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
			{Name: "Accept", Value: "application/json"},
		},
	}, retryClient)
	if err != nil {
		return "", fmt.Errorf("token exchange (authz_code): %w", err)
	}
	if tokenRes.StatusCode != 200 {
		return "", fmt.Errorf("token endpoint returned status %d: %s", tokenRes.StatusCode, previewBody(tokenRes.BodyString))
	}

	refreshToken := gjson.Get(tokenRes.BodyString, "refresh_token").String()
	if refreshToken == "" {
		return "", fmt.Errorf("no refresh_token in token response: %s", previewBody(tokenRes.BodyString))
	}

	// Step 8: POST token (refresh_token) for the API scope
	refreshBody := fmt.Sprintf(
		"client_id=%s&scope=%s&grant_type=refresh_token&client_info=1&refresh_token=%s",
		b2cClientID, url.QueryEscape(apiScope), url.QueryEscape(refreshToken),
	)

	refreshRes, err := whttp.SendHTTPRequest(&whttp.WHTTPReq{
		Method: "POST",
		URL:    tokenURL,
		Body:   refreshBody,
		Headers: []whttp.WHTTPHeader{
			{Name: "User-Agent", Value: userAgent},
			{Name: "Content-Type", Value: "application/x-www-form-urlencoded"},
			{Name: "Accept", Value: "application/json"},
		},
	}, retryClient)
	if err != nil {
		return "", fmt.Errorf("token exchange (refresh_token): %w", err)
	}
	if refreshRes.StatusCode != 200 {
		return "", fmt.Errorf("refresh token endpoint returned status %d: %s", refreshRes.StatusCode, previewBody(refreshRes.BodyString))
	}

	accessToken := gjson.Get(refreshRes.BodyString, "access_token").String()
	if accessToken == "" {
		return "", fmt.Errorf("no access_token in refresh response: %s", previewBody(refreshRes.BodyString))
	}

	return accessToken, nil
}

// generatePKCE builds the PKCE verifier/challenge pair and random state/nonce
// values used in the authorize request.
func generatePKCE() (verifier, challenge, state, nonce string, err error) {
	verifierBytes := make([]byte, 32)
	if _, err = rand.Read(verifierBytes); err != nil {
		return "", "", "", "", fmt.Errorf("read random verifier: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(verifierBytes)

	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])

	stateBytes := make([]byte, 16)
	if _, err = rand.Read(stateBytes); err != nil {
		return "", "", "", "", fmt.Errorf("read random state: %w", err)
	}
	state = hex.EncodeToString(stateBytes)

	nonceBytes := make([]byte, 16)
	if _, err = rand.Read(nonceBytes); err != nil {
		return "", "", "", "", fmt.Errorf("read random nonce: %w", err)
	}
	nonce = hex.EncodeToString(nonceBytes)

	return verifier, challenge, state, nonce, nil
}

// scrapeCSRFAndTransID extracts the csrf and transId values embedded in a B2C
// SelfAsserted/authorize HTML page. These appear in a JSON settings block.
func scrapeCSRFAndTransID(html string) (csrf, transID string, err error) {
	m := csrfRe.FindStringSubmatch(html)
	if len(m) < 2 {
		return "", "", errors.New("csrf not found in page")
	}
	csrf = m[1]

	m = transIDRe.FindStringSubmatch(html)
	if len(m) < 2 {
		return "", "", errors.New("transId not found in page")
	}
	transID = m[1]

	return csrf, transID, nil
}

// extractAuthzCode parses the redirect Location URL, isolates the fragment
// (after #), and returns the code query parameter. It also verifies that the
// state matches the one we sent in the authorize request.
func extractAuthzCode(location, expectedState string) (string, error) {
	fragIdx := strings.Index(location, "#")
	if fragIdx < 0 {
		return "", fmt.Errorf("no fragment in Location: %s", location)
	}
	fragment := location[fragIdx+1:]

	values, err := url.ParseQuery(fragment)
	if err != nil {
		return "", fmt.Errorf("parse fragment: %w", err)
	}

	code := values.Get("code")
	if code == "" {
		return "", errors.New("no code in fragment")
	}

	if gotState := values.Get("state"); gotState != "" && gotState != expectedState {
		return "", fmt.Errorf("state mismatch: got %s, expected %s", gotState, expectedState)
	}

	return code, nil
}

// previewBody returns a trimmed preview of a response body for error messages.
func previewBody(body string) string {
	const max = 500
	if len(body) > max {
		return body[:max]
	}
	return body
}
