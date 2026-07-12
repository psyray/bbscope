package bugbountych

import (
	"regexp"
	"strings"

	"github.com/sw33tLie/bbscope/v2/pkg/scope"
	"github.com/tidwall/gjson"
)

// extractBBCMetadata parses the BugBounty.ch scope-groups response body (from
// /engagements/engagement/scopes/list?id=...) and engagement-detail body (from
// /engagements?id=...) and returns program-level metadata. It is defensive:
// missing or zero-valued fields are left nil rather than producing zero
// pointers. The result is never nil.
func extractBBCMetadata(scopeGroupsBody, engagementBody string, isBBP bool) *scope.ProgramMetadata {
	m := &scope.ProgramMetadata{}

	// 1. Classification & Context
	m.Title = gjson.Get(engagementBody, "title").String()
	m.CompanyName = gjson.Get(engagementBody, "organization.name").String()
	engType := int(gjson.Get(engagementBody, "type").Int())
	state := int(gjson.Get(engagementBody, "state").Int())
	visibility := int(gjson.Get(engagementBody, "visibility").Int())

	switch engType {
	case 0:
		m.ProgramType = "bug-bounty"
	case 10:
		m.ProgramType = "vdp"
	}
	m.IsBounty = boolPtr(isBBP)
	m.IsVDP = boolPtr(engType == 10)
	m.IsPublic = boolPtr(visibility == 0)
	m.IsDisabled = boolPtr(state != 1)

	// 2. Rewards
	// BugBounty.ch is a Swiss platform; rewards are denominated in CHF even
	// though the API does not expose a currency field.
	m.Currency = "CHF"
	if v := gjson.Get(engagementBody, "rewardLow").Int(); v > 0 {
		m.BountyRewardMin = intPtr(int(v))
	}
	if v := gjson.Get(engagementBody, "rewardCritical").Int(); v > 0 {
		m.BountyRewardMax = intPtr(int(v))
	}

	// Reward grids: one per scope group. Each group exposes single bounty
	// values per severity (bountyLow/Medium/High/Critical), which we record as
	// min=max. Groups with all-zero bounties are skipped.
	gjson.Get(scopeGroupsBody, "scopes").ForEach(func(_, sg gjson.Result) bool {
		name := sg.Get("name").String()
		low := int(sg.Get("bountyLow").Int())
		medium := int(sg.Get("bountyMedium").Int())
		high := int(sg.Get("bountyHigh").Int())
		critical := int(sg.Get("bountyCritical").Int())
		if low == 0 && medium == 0 && high == 0 && critical == 0 {
			return true
		}
		rg := scope.RewardGrid{Dimension: name}
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
		return true
	})

	// 3. Scope Rules
	rulesDelta := gjson.Get(engagementBody, "rules").String()
	if rulesDelta != "" {
		rulesText, _ := parseQuillDelta(rulesDelta)
		m.Rules = rulesText
		m.RulesFormat = "markdown"
		if strings.Contains(strings.ToLower(rulesText), "safe harbor") {
			m.SafeHarbor = "full"
		}
	}

	qualifyingDelta := gjson.Get(engagementBody, "qualifyingVulnerabilities").String()
	if qualifyingDelta != "" {
		m.QualifyingVulnerabilities = parseQuillBulletItems(qualifyingDelta)
	}

	nonQualifyingDelta := gjson.Get(engagementBody, "nonQualifyingVulnerabilities").String()
	if nonQualifyingDelta != "" {
		m.NonQualifyingVulnerabilities = parseQuillBulletItems(nonQualifyingDelta)
	}

	outOfScopeDelta := gjson.Get(engagementBody, "outOfScope").String()
	if outOfScopeDelta != "" {
		plainText, _ := parseQuillDelta(outOfScopeDelta)
		for _, line := range strings.Split(plainText, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				m.OutOfScopeSummary = append(m.OutOfScopeSummary, line)
			}
		}
	}

	// 4. Testing Instructions (and 5. Account Setup) — both mined from the
	// engagement "notes" Quill Delta field.
	notesDelta := gjson.Get(engagementBody, "notes").String()
	if notesDelta != "" {
		notesText, _ := parseQuillDelta(notesDelta)
		m.UserAgent = extractUserAgent(notesText)
		m.RequestHeader = extractRequestHeader(notesText)
		notesLower := strings.ToLower(notesText)
		if strings.Contains(notesLower, "self-register") || strings.Contains(notesLower, "test account") {
			m.CanCreateTestAccount = boolPtr(true)
		}
		if acct := extractAccountAccess(notesText); acct != "" {
			m.AccountAccess = acct
		}
	}

	// 6. Program Stats
	if v := gjson.Get(engagementBody, "scopesCount").Int(); v > 0 {
		m.ScopesCount = intPtr(int(v))
	}
	if tags := gjsonSlice(engagementBody, "tags"); len(tags) > 0 {
		m.Tags = tags
	}

	return m
}

// parseQuillDelta parses a Quill Delta JSON string and returns the concatenated
// plain text of all `insert` operations plus the bullet list items. A bullet
// item is the `insert` text of an op immediately followed by an op whose
// attributes.list == "bullet" (the trailing newline of which is stripped).
func parseQuillDelta(deltaJSON string) (plainText string, bulletItems []string) {
	ops := gjson.Get(deltaJSON, "ops").Array()
	for i, op := range ops {
		insert := op.Get("insert").String()
		if insert == "" {
			continue
		}
		if i+1 < len(ops) && ops[i+1].Get("attributes.list").String() == "bullet" {
			item := strings.TrimSuffix(insert, "\n")
			if item != "" {
				bulletItems = append(bulletItems, item)
			}
		}
		plainText += insert
	}
	return plainText, bulletItems
}

// parseQuillBulletItems parses a Quill Delta JSON string and returns only the
// bullet list items (see parseQuillDelta).
func parseQuillBulletItems(deltaJSON string) []string {
	_, items := parseQuillDelta(deltaJSON)
	return items
}

// userAgentRe matches "User-Agent: <token>", "User-Agent <token>",
// or "User Agent <token>" (without hyphen) patterns in the notes text,
// capturing the token value.
var userAgentRe = regexp.MustCompile(`(?i)User[-_]?Agent[:\s]+([A-Za-z0-9_.\-]+)`)

// extractUserAgent scans the notes plain text for a User-Agent mention and
// returns the following token, or "" if not found.
func extractUserAgent(notesText string) string {
	m := userAgentRe.FindStringSubmatch(notesText)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// headerNameRe matches custom HTTP header names like "X-Bug-Bounty" that appear
// in the notes text.
var headerNameRe = regexp.MustCompile(`(?i)\b(X-[A-Za-z][A-Za-z0-9\-]*)\b`)

// extractRequestHeader scans the notes plain text for a custom header name
// (e.g. "X-Bug-Bounty") and returns it, or "" if not found.
func extractRequestHeader(notesText string) string {
	m := headerNameRe.FindStringSubmatch(notesText)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// extractAccountAccess returns the lines of the notes text that mention
// "account" (case-insensitive), joined with " | ", or "" if none match.
func extractAccountAccess(notesText string) string {
	var lines []string
	for _, line := range strings.Split(notesText, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(strings.ToLower(line), "account") {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, " | ")
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
