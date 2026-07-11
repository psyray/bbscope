package yogosha

import (
	"context"
	"fmt"
	"strings"

	"github.com/sw33tLie/bbscope/v2/pkg/platforms"
	"github.com/sw33tLie/bbscope/v2/pkg/scope"
	"github.com/sw33tLie/bbscope/v2/pkg/whttp"
	"github.com/tidwall/gjson"
)

const (
	apiBase       = "https://api-cyber.yogosha.com/api"
	programWebURL = "https://app.yogosha.com/programs/"
)

// Poller implements platforms.PlatformPoller for Yogosha.
type Poller struct {
	token      string
	bbpSet     map[string]bool   // tracks which program names offer monetary rewards
	handleToID map[string]string // maps program name (handle) → program ID for API calls
}

// NewPoller returns a Yogosha poller pre-configured with a bearer token.
// Use Authenticate instead when logging in with email/password+TOTP.
func NewPoller(token string) *Poller {
	return &Poller{token: token, bbpSet: map[string]bool{}, handleToID: map[string]string{}}
}

func (p *Poller) Name() string { return "yog" }

// Authenticate configures the poller with either a pre-existing bearer token
// or by performing the OIDC + TOTP login flow.
func (p *Poller) Authenticate(ctx context.Context, cfg platforms.AuthConfig) error {
	if cfg.Token != "" {
		p.token = cfg.Token
		return nil
	}
	if cfg.Email != "" && cfg.Password != "" && cfg.OtpSecret != "" {
		tok, err := login(cfg.Email, cfg.Password, cfg.OtpSecret, cfg.Proxy)
		if err != nil {
			return err
		}
		p.token = tok
		return nil
	}
	return nil
}

// ListProgramHandles fetches program IDs from Yogosha. When opts.PrivateOnly
// is set, it returns only the researcher's accepted invitations; otherwise it
// returns all visible (public + open-audience) programs.
func (p *Poller) ListProgramHandles(ctx context.Context, opts platforms.PollOptions) ([]string, error) {
	p.bbpSet = map[string]bool{}
	p.handleToID = map[string]string{}
	if opts.PrivateOnly {
		return p.listInvitedPrograms(opts)
	}
	return p.listPublicPrograms(opts)
}

func (p *Poller) listPublicPrograms(opts platforms.PollOptions) ([]string, error) {
	var handles []string
	page := 1
	totalPages := 2 // init > page so the loop starts

	for page <= totalPages {
		url := fmt.Sprintf("%s/programs?embed=audiences&page=%d&perPage=20&sortBy=startedAt.desc&type=bugbounty%%2Cpentest%%2Cvdp", apiBase, page)
		res, err := whttp.SendHTTPRequest(&whttp.WHTTPReq{
			Method:  "GET",
			URL:     url,
			Headers: []whttp.WHTTPHeader{{Name: "Authorization", Value: "Bearer " + p.token}},
		}, nil)
		if err != nil {
			return nil, err
		}
		if res.StatusCode == 401 {
			return nil, fmt.Errorf("invalid or expired Yogosha token")
		}

		gjson.Get(res.BodyString, "data").ForEach(func(_, prog gjson.Result) bool {
			isBBP := prog.Get("rewardEnabled").Bool() && prog.Get("lowReward.amount").Int() > 0
			if opts.BountyOnly && !isBBP {
				return true
			}
			id := prog.Get("id").String()
			name := prog.Get("name").String()
			if id == "" || name == "" {
				return true
			}
			handles = append(handles, name)
			p.handleToID[name] = id
			if isBBP {
				p.bbpSet[name] = true
			}
			return true
		})

		totalPages = int(gjson.Get(res.BodyString, "pagination.totalPages").Int())
		page++
	}
	return handles, nil
}

func (p *Poller) listInvitedPrograms(opts platforms.PollOptions) ([]string, error) {
	var handles []string
	page := 1
	totalPages := 2

	for page <= totalPages {
		url := fmt.Sprintf("%s/program-invites?page=%d&perPage=20&sortBy=createdAt.desc", apiBase, page)
		res, err := whttp.SendHTTPRequest(&whttp.WHTTPReq{
			Method:  "GET",
			URL:     url,
			Headers: []whttp.WHTTPHeader{{Name: "Authorization", Value: "Bearer " + p.token}},
		}, nil)
		if err != nil {
			return nil, err
		}
		if res.StatusCode == 401 {
			return nil, fmt.Errorf("invalid or expired Yogosha token")
		}

		gjson.Get(res.BodyString, "data").ForEach(func(_, invite gjson.Result) bool {
			if invite.Get("status").String() != "accepted" {
				return true
			}
			id := invite.Get("program.id").String()
			name := invite.Get("program.name").String()
			if id == "" || name == "" {
				return true
			}
			// Invite payload lacks reward info; include all accepted invites.
			// BountyOnly filtering happens in FetchProgramScope via the detail body.
			handles = append(handles, name)
			p.handleToID[name] = id
			return true
		})

		totalPages = int(gjson.Get(res.BodyString, "pagination.totalPages").Int())
		page++
	}
	return handles, nil
}

// FetchProgramScope fetches a single program's scope. The handle is the program
// name (human-readable); the opaque ID is looked up from the handleToID cache
// populated by ListProgramHandles.
func (p *Poller) FetchProgramScope(ctx context.Context, handle string, opts platforms.PollOptions) (scope.ProgramData, error) {
	id := p.handleToID[handle]
	if id == "" {
		return scope.ProgramData{}, fmt.Errorf("yogosha: no ID cached for handle %q", handle)
	}
	programAPIURL := fmt.Sprintf("%s/programs/%s?embed=content%%2Caudiences", apiBase, id)
	pData := scope.ProgramData{Url: programWebURL + id}

	res, err := whttp.SendHTTPRequest(&whttp.WHTTPReq{
		Method:  "GET",
		URL:     programAPIURL,
		Headers: []whttp.WHTTPHeader{{Name: "Authorization", Value: "Bearer " + p.token}},
	}, nil)
	if err != nil {
		return pData, err
	}
	if res.StatusCode == 401 {
		return pData, fmt.Errorf("invalid or expired Yogosha token")
	}
	if res.StatusCode == 404 {
		return pData, fmt.Errorf("yogosha program not found: %s", id)
	}

	body := res.BodyString
	selectedCategories := scope.GetAllStringsForCategories(opts.Categories)
	isBBP := p.bbpSet[handle]
	if !isBBP {
		// Derive from detail body when not cached (e.g. private programs from invites)
		isBBP = gjson.Get(body, "rewardEnabled").Bool() && gjson.Get(body, "lowReward.amount").Int() > 0
	}

	// In-scope targets
	gjson.Get(body, "scope").ForEach(func(_, target gjson.Result) bool {
		t := target.String()
		if t == "" {
			return true
		}
		cat := classifyYogoshaScope(t)
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
		pData.InScope = append(pData.InScope, scope.ScopeElement{
			Target:   t,
			Category: cat,
			IsBBP:    isBBP,
		})
		return true
	})

	// Out-of-scope targets
	gjson.Get(body, "outOfScopes").ForEach(func(_, target gjson.Result) bool {
		t := target.String()
		if t == "" {
			return true
		}
		pData.OutOfScope = append(pData.OutOfScope, scope.ScopeElement{
			Target:   t,
			Category: "other",
			IsBBP:    isBBP,
		})
		return true
	})

	return pData, nil
}

// classifyYogoshaScope maps a Yogosha scope URL string to a category that
// scope.NormalizeCategory understands. Yogosha exposes scope entries as plain
// URLs (including app store URLs), not structured asset types.
func classifyYogoshaScope(target string) string {
	if strings.HasPrefix(target, "*.") {
		return "wildcard"
	}
	if strings.Contains(target, "play.google.com/store/apps/details") {
		return "google_play_app_id"
	}
	if strings.HasPrefix(target, "https://apps.apple.com/") || strings.HasPrefix(target, "http://apps.apple.com/") {
		return "apple_store_app_id"
	}
	return "url"
}
