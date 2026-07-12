package bugbountych

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/sw33tLie/bbscope/v2/pkg/platforms"
	"github.com/sw33tLie/bbscope/v2/pkg/scope"
	"github.com/sw33tLie/bbscope/v2/pkg/whttp"
	"github.com/tidwall/gjson"
)

const (
	apiBase       = "https://api-hacker.bugbounty.ch"
	programWebURL = "https://app.bugbounty.ch/engagement/"
)

// ipv4Re matches dotted-quad IPv4 addresses (with optional trailing CIDR
// suffix stripped by the caller). Used to mine out-of-scope IPs from the
// engagement's Quill Delta outOfScope text.
var ipv4Re = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

// Poller implements platforms.PlatformPoller for BugBounty.ch.
type Poller struct {
	token  string
	bbpSet map[string]bool // tracks which engagement IDs are bounty programs
}

// NewPoller returns a BugBounty.ch poller pre-configured with a bearer token.
// Use Authenticate instead when logging in with email/password+TOTP.
func NewPoller(token string) *Poller {
	return &Poller{token: token, bbpSet: map[string]bool{}}
}

func (p *Poller) Name() string { return "bbch" }

// Authenticate configures the poller with either a pre-existing bearer token
// or by performing the Azure B2C login flow.
func (p *Poller) Authenticate(ctx context.Context, cfg platforms.AuthConfig) error {
	if cfg.Token != "" {
		p.token = cfg.Token
		return nil
	}
	if cfg.Email != "" && cfg.Password != "" && cfg.OtpSecret != "" {
		tok, err := Login(cfg.Email, cfg.Password, cfg.OtpSecret, cfg.Proxy)
		if err != nil {
			return err
		}
		p.token = tok
		return nil
	}
	return nil
}

// ListProgramHandles fetches engagement IDs from BugBounty.ch. When
// opts.PrivateOnly is set, it fetches only programs the researcher has been
// invited to; otherwise it fetches all active (state=1) public programs. The
// handle returned for each program is its engagement UUID.
func (p *Poller) ListProgramHandles(ctx context.Context, opts platforms.PollOptions) ([]string, error) {
	p.bbpSet = map[string]bool{}
	var handles []string
	page := 1
	totalPages := 2 // init > page so the loop starts

	for page <= totalPages {
		var url string
		if opts.PrivateOnly {
			url = fmt.Sprintf("%s/engagements/list?pageSize=10&pageNumber=%d&isInvited=true", apiBase, page)
		} else {
			url = fmt.Sprintf("%s/engagements/list?pageSize=10&pageNumber=%d&state=1", apiBase, page)
		}

		res, err := whttp.SendHTTPRequest(&whttp.WHTTPReq{
			Method:  "GET",
			URL:     url,
			Headers: []whttp.WHTTPHeader{{Name: "Authorization", Value: "Bearer " + p.token}},
		}, nil)
		if err != nil {
			return nil, err
		}
		if res.StatusCode == 401 {
			return nil, fmt.Errorf("invalid or expired BugBounty.ch token")
		}

		gjson.Get(res.BodyString, "items").ForEach(func(_, item gjson.Result) bool {
			id := item.Get("id").String()
			if id == "" {
				return true
			}
			engType := int(item.Get("type").Int())
			maxReward := item.Get("maxReward").Int()
			isBBP := engType == 0 && maxReward > 0
			if opts.BountyOnly && !isBBP {
				return true
			}
			handles = append(handles, id)
			if isBBP {
				p.bbpSet[id] = true
			}
			return true
		})

		totalPages = int(gjson.Get(res.BodyString, "paginationData.totalPages").Int())
		page++
	}

	return handles, nil
}

// FetchProgramScope fetches a single engagement's scope and rich metadata.
// The handle is the engagement UUID returned by ListProgramHandles.
//
// For each scope group returned by the scopes/list endpoint, a follow-up XHR
// call is made to scopes/assets?scopeId=<id> to retrieve the individual
// in-scope and out-of-scope assets (hostnames, URLs, IPs). Out-of-scope IPs
// are also mined from the engagement's outOfScope Quill Delta text as a
// fallback.
func (p *Poller) FetchProgramScope(ctx context.Context, handle string, opts platforms.PollOptions) (scope.ProgramData, error) {
	pData := scope.ProgramData{Url: programWebURL + handle}
	authHeaders := []whttp.WHTTPHeader{{Name: "Authorization", Value: "Bearer " + p.token}}

	// Scope groups (per-group bounty grid + assetGroup metadata).
	scopesURL := fmt.Sprintf("%s/engagements/engagement/scopes/list?id=%s", apiBase, handle)
	scopesRes, err := whttp.SendHTTPRequest(&whttp.WHTTPReq{
		Method:  "GET",
		URL:     scopesURL,
		Headers: authHeaders,
	}, nil)
	if err != nil {
		return pData, err
	}
	if scopesRes.StatusCode == 401 {
		return pData, fmt.Errorf("invalid or expired BugBounty.ch token")
	}

	// Engagement detail (rich metadata: rules, vulnerabilities, reward ranges).
	detailURL := fmt.Sprintf("%s/engagements?id=%s", apiBase, handle)
	detailRes, err := whttp.SendHTTPRequest(&whttp.WHTTPReq{
		Method:  "GET",
		URL:     detailURL,
		Headers: authHeaders,
	}, nil)
	if err != nil {
		return pData, err
	}
	if detailRes.StatusCode == 401 {
		return pData, fmt.Errorf("invalid or expired BugBounty.ch token")
	}

	isBBP := p.bbpSet[handle]
	if !isBBP {
		engType := int(gjson.Get(detailRes.BodyString, "type").Int())
		maxReward := gjson.Get(detailRes.BodyString, "maxReward").Int()
		if engType == 0 && maxReward > 0 {
			isBBP = true
		}
	}

	selectedCategories := scope.GetAllStringsForCategories(opts.Categories)

	// For each scope group, fetch the actual assets via XHR.
	gjson.Get(scopesRes.BodyString, "scopes").ForEach(func(_, sg gjson.Result) bool {
		scopeID := sg.Get("id").String()
		if scopeID == "" {
			return true
		}

		assetsURL := fmt.Sprintf("%s/engagements/engagement/scopes/assets?scopeId=%s", apiBase, scopeID)
		assetsRes, err := whttp.SendHTTPRequest(&whttp.WHTTPReq{
			Method:  "GET",
			URL:     assetsURL,
			Headers: authHeaders,
		}, nil)
		if err != nil {
			return true // skip this scope group on error, continue with others
		}
		if assetsRes.StatusCode != 200 {
			return true
		}

		gjson.Get(assetsRes.BodyString, "assets").ForEach(func(_, asset gjson.Result) bool {
			name := asset.Get("name").String()
			if name == "" {
				return true
			}
			label := asset.Get("label").String()
			inScope := asset.Get("inScope").Bool()
			cat := classifyBBCAsset(name, label)

			if selectedCategories != nil {
				match := false
				for _, c := range selectedCategories {
					if c == cat {
						match = true
						break
					}
				}
				if !match {
					return true
				}
			}

			se := scope.ScopeElement{
				Target:   name,
				Category: cat,
				IsBBP:    isBBP,
			}
			if inScope {
				pData.InScope = append(pData.InScope, se)
			} else {
				pData.OutOfScope = append(pData.OutOfScope, se)
			}
			return true
		})
		return true
	})

	// Out-of-scope IPs: also mine from the engagement's outOfScope Quill Delta
	// text as a fallback (some OOS IPs may not be in the structured asset list).
	outOfScopeDelta := gjson.Get(detailRes.BodyString, "outOfScope").String()
	if outOfScopeDelta != "" {
		plainText, _ := parseQuillDelta(outOfScopeDelta)
		for _, ip := range ipv4Re.FindAllString(plainText, -1) {
			pData.OutOfScope = append(pData.OutOfScope, scope.ScopeElement{
				Target:   ip,
				Category: "other",
				IsBBP:    isBBP,
			})
		}
	}

	pData.Metadata = extractBBCMetadata(scopesRes.BodyString, detailRes.BodyString, isBBP)

	return pData, nil
}

// classifyBBCAsset maps a BugBounty.ch asset name + label to a bbscope category
// string that scope.NormalizeCategory understands.
func classifyBBCAsset(name, label string) string {
	// Check by name pattern first
	if strings.HasPrefix(name, "*.") {
		return "wildcard"
	}
	if strings.HasPrefix(name, "http://") || strings.HasPrefix(name, "https://") {
		return "url"
	}
	// Check for IPv4/CIDR
	if ipv4Re.MatchString(name) {
		if strings.Contains(name, "/") {
			return "cidr"
		}
		return "ip_address"
	}
	// Fall back to label-based classification
	switch strings.ToLower(label) {
	case "wildcard":
		return "wildcard"
	case "cidr", "iprange":
		return "cidr"
	case "ip", "ip_address":
		return "ip_address"
	default:
		return "url" // hostnames, URLs, and anything else
	}
}
