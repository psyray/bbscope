package yogosha

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/sw33tLie/bbscope/v2/pkg/scope"
	"github.com/tidwall/gjson"
)

// extractYogoshaMetadata parses a Yogosha program detail API response body
// (from /api/programs/<id>?embed=content,audiences) and returns program-level
// metadata. It is defensive: missing or zero-valued fields are left nil rather
// than producing zero pointers. The result is never nil.
func extractYogoshaMetadata(body string, isBBP bool) *scope.ProgramMetadata {
	m := &scope.ProgramMetadata{}

	// 1. Classification & Context
	m.Title = gjson.Get(body, "name").String()
	m.Tagline = gjson.Get(body, "asset.title").String()
	m.CompanyName = gjson.Get(body, "organization.name").String()
	m.ProgramType = gjson.Get(body, "type").String() // bugbounty | pentest | vdp

	if v := gjson.Get(body, "state"); v.Exists() && v.String() != "online" {
		m.IsDisabled = boolPtr(true)
	}
	if v := gjson.Get(body, "archivedAt"); v.Exists() && v.Type != gjson.Null {
		m.IsDisabled = boolPtr(true)
	}

	// IsPublic: true if any audience has accessMode "open"
	isPublic := false
	gjson.Get(body, "audiences").ForEach(func(_, aud gjson.Result) bool {
		if aud.Get("accessMode").String() == "open" {
			isPublic = true
			return false
		}
		return true
	})
	m.IsPublic = boolPtr(isPublic)
	m.IsBounty = boolPtr(isBBP)

	// IsVDP: type == "vdp" or all rewards zero with "hack_for_values" tag
	typeStr := gjson.Get(body, "type").String()
	allRewardsZero := rewardAmountToInt(gjson.Get(body, "lowReward.amount").String()) == 0 &&
		rewardAmountToInt(gjson.Get(body, "mediumReward.amount").String()) == 0 &&
		rewardAmountToInt(gjson.Get(body, "highReward.amount").String()) == 0 &&
		rewardAmountToInt(gjson.Get(body, "criticalReward.amount").String()) == 0
	if typeStr == "vdp" || (allRewardsZero && hasTag(body, "hack_for_values")) {
		m.IsVDP = boolPtr(true)
	}

	// 2. Rewards
	m.Currency = gjson.Get(body, "organization.currency").String()
	if m.Currency == "" {
		m.Currency = gjson.Get(body, "lowReward.currency").String()
	}
	if v := rewardAmountToInt(gjson.Get(body, "lowReward.amount").String()); v > 0 {
		m.BountyRewardMin = intPtr(v)
	}
	if v := rewardAmountToInt(gjson.Get(body, "criticalReward.amount").String()); v > 0 {
		m.BountyRewardMax = intPtr(v)
	}

	// Yogosha exposes one reward grid per program with 4 severity levels.
	// We normalize it as a single RewardGrid with Dimension "default".
	low := rewardAmountToInt(gjson.Get(body, "lowReward.amount").String())
	medium := rewardAmountToInt(gjson.Get(body, "mediumReward.amount").String())
	high := rewardAmountToInt(gjson.Get(body, "highReward.amount").String())
	critical := rewardAmountToInt(gjson.Get(body, "criticalReward.amount").String())
	if low != 0 || medium != 0 || high != 0 || critical != 0 {
		rg := scope.RewardGrid{Dimension: "default"}
		if low != 0 {
			rg.BountyLowMin = intPtr(low)
			rg.BountyLowMax = intPtr(low)
		}
		if medium != 0 {
			rg.BountyMediumMin = intPtr(medium)
			rg.BountyMediumMax = intPtr(medium)
		}
		if high != 0 {
			rg.BountyHighMin = intPtr(high)
			rg.BountyHighMax = intPtr(high)
		}
		if critical != 0 {
			rg.BountyCriticalMin = intPtr(critical)
			rg.BountyCriticalMax = intPtr(critical)
		}
		m.RewardGrids = append(m.RewardGrids, rg)
	}

	// 3. Scope Rules
	mission := gjson.Get(body, "content.mission").String()
	if mission != "" {
		m.Rules = mission
		m.RulesFormat = "markdown"
	}

	// Qualifying vulnerabilities: parse the markdown list after
	// "Qualifying vulnerabilities" heading in the mission text.
	if mission != "" {
		m.QualifyingVulnerabilities = extractMarkdownList(mission, "Qualifying vulnerabilities")
	}

	// Non-qualifying vulnerabilities and out-of-scope summary from content.outOfScope
	outOfScope := gjson.Get(body, "content.outOfScope").String()
	if outOfScope != "" {
		m.OutOfScopeSummary = []string{outOfScope}
		m.NonQualifyingVulnerabilities = extractMarkdownList(outOfScope, "outside the scope")
	}

	// 4. Testing Instructions
	if v := gjson.Get(body, "vpnRequired"); v.Exists() {
		m.VPNRequired = boolPtr(v.Bool())
	} else if v := gjson.Get(body, "monitoring.type"); v.Exists() && v.String() == "vpn" {
		m.VPNRequired = boolPtr(true)
	}
	m.VNPIPs = gjsonSlice(body, "vpnIpAdresses")

	// Parse testing instructions from content.terms (X-Bug-Bounty header, rate limit)
	terms := gjson.Get(body, "content.terms").String()
	if terms != "" {
		if strings.Contains(terms, "X-Bug-Bounty") {
			m.RequestHeader = "X-Bug-Bounty"
		}
		if limit := extractRateLimit(terms); limit > 0 {
			m.AutomatedToolingLimit = intPtr(limit)
		}
	}

	// 5. Account Setup
	if v := gjson.Get(body, "testAccountsEnabled"); v.Exists() && v.Bool() {
		m.CanCreateTestAccount = boolPtr(true)
	}
	if v := gjson.Get(body, "testAccounts.instructions"); v.Exists() && v.String() != "" {
		m.AccountAccess = v.String()
	}

	// 6. Program Stats
	if v := gjson.Get(body, "scope.#").Int(); v > 0 {
		m.ScopesCount = intPtr(int(v))
	}
	if tags := gjsonSlice(body, "tags"); len(tags) > 0 {
		m.Tags = tags
	}

	return m
}

// hasTag reports whether the program's tags array contains the given tag.
func hasTag(body, tag string) bool {
	found := false
	gjson.Get(body, "tags").ForEach(func(_, t gjson.Result) bool {
		if t.String() == tag {
			found = true
			return false
		}
		return true
	})
	return found
}

// extractMarkdownList finds a heading (case-insensitive) in a markdown text and
// returns the bullet list items that follow it until the next heading. Handles
// both "- " and "* " list markers.
func extractMarkdownList(text, heading string) []string {
	lines := strings.Split(text, "\n")
	headingLower := strings.ToLower(heading)
	collecting := false
	var items []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Detect headings (lines starting with #)
		if strings.HasPrefix(trimmed, "#") {
			if collecting {
				break // next heading ends the list
			}
			if strings.Contains(strings.ToLower(trimmed), headingLower) {
				collecting = true
			}
			continue
		}

		// Also detect non-heading section markers (bold text like **Heading**)
		if !collecting && strings.HasPrefix(trimmed, "**") && strings.Contains(strings.ToLower(trimmed), headingLower) {
			collecting = true
			continue
		}

		if !collecting {
			continue
		}

		// Extract bullet items: "- text" or "* text"
		if strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "* ") {
			item := strings.TrimSpace(trimmed[2:])
			if item != "" {
				items = append(items, item)
			}
		}
	}

	return items
}

// rateLimitRe matches "max. 5 per sec" or "max 5 per sec" in testing terms.
var rateLimitRe = regexp.MustCompile(`max\.?\s+(\d+)\s+per\s+sec`)

// extractRateLimit parses a rate limit like "max. 5 per sec" from the terms text
// and returns the number of requests per second, or 0 if not found.
func extractRateLimit(terms string) int {
	matches := rateLimitRe.FindStringSubmatch(terms)
	if len(matches) < 2 {
		return 0
	}
	limit, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0
	}
	return limit
}

// rewardAmountToInt parses a Yogosha reward amount string (e.g. "10000")
// and divides by 100 to convert from centimes to whole currency units.
func rewardAmountToInt(s string) int {
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return v / 100
}

// intPtr returns a pointer to v. Local helper for building metadata.
func intPtr(v int) *int { return &v }

// boolPtr returns a pointer to v. Local helper for building metadata.
func boolPtr(v bool) *bool { return &v }

// gjsonSlice returns the string elements of the array at path in body, or nil
// if the path does not exist or is not an array.
func gjsonSlice(body, path string) []string {
	arr := gjson.Get(body, path).Array()
	if len(arr) == 0 {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, a := range arr {
		out = append(out, a.String())
	}
	return out
}
