package bugbountych

import (
	"strings"
	"testing"

	"github.com/sw33tLie/bbscope/v2/pkg/scope"
)

func TestClassifyBBCAsset(t *testing.T) {
	tests := []struct {
		name  string
		asset string
		label string
		want  string
	}{
		{"wildcard by name pattern", "*.example.com", "host", "wildcard"},
		{"https url by name pattern", "https://example.com", "", "url"},
		{"http url by name pattern", "http://example.com", "", "url"},
		{"ipv4 by name pattern", "192.168.1.1", "host", "ip_address"},
		{"cidr by name pattern with slash", "10.0.0.0/24", "", "cidr"},
		{"hostname defaults to url", "connect.jura.ch", "host", "url"},
		{"label wildcard override", "example.ch", "wildcard", "wildcard"},
		{"label cidr override", "10.0.0.0/24", "cidr", "cidr"},
		{"label ip override", "193.246.27.50", "ip", "ip_address"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyBBCAsset(tt.asset, tt.label)
			if got != tt.want {
				t.Errorf("classifyBBCAsset(%q, %q) = %q, want %q", tt.asset, tt.label, got, tt.want)
			}
			// The category must also normalize to itself (it is already a unified
			// category string that scope.NormalizeCategory understands).
			if scope.NormalizeCategory(got) != scope.NormalizeCategory(tt.want) {
				t.Errorf("NormalizeCategory mismatch: got %q, want %q",
					scope.NormalizeCategory(got), scope.NormalizeCategory(tt.want))
			}
		})
	}
}

func TestParseQuillDelta(t *testing.T) {
	const delta = `{"ops":[{"insert":"Remote code execution (RCE)"},{"attributes":{"list":"bullet"},"insert":"\n"},{"insert":"SQL injection"},{"attributes":{"list":"bullet"},"insert":"\n"},{"insert":"Some intro text\n"},{"insert":"Bold text"},{"attributes":{"bold":true},"insert":"\n"}]}`

	plainText, bulletItems := parseQuillDelta(delta)

	for _, want := range []string{
		"Remote code execution (RCE)",
		"SQL injection",
		"Some intro text",
		"Bold text",
	} {
		if !strings.Contains(plainText, want) {
			t.Errorf("plainText missing %q; got: %q", want, plainText)
		}
	}

	wantBullets := []string{"Remote code execution (RCE)", "SQL injection"}
	if len(bulletItems) != len(wantBullets) {
		t.Fatalf("bulletItems len = %d, want %d; got: %v", len(bulletItems), len(wantBullets), bulletItems)
	}
	for i, want := range wantBullets {
		if bulletItems[i] != want {
			t.Errorf("bulletItems[%d] = %q, want %q", i, bulletItems[i], want)
		}
	}
	for _, unwanted := range []string{"Some intro text", "Bold text"} {
		for _, b := range bulletItems {
			if b == unwanted {
				t.Errorf("bulletItems should not contain %q; got: %v", unwanted, bulletItems)
			}
		}
	}
}

func TestParseQuillBulletItems(t *testing.T) {
	// Sample from the BugBounty.ch qualifyingVulnerabilities field.
	const delta = `{"ops":[{"insert":"Remote code execution (RCE)"},{"attributes":{"list":"bullet"},"insert":"\n"},{"insert":"Local files access and manipulation (LFI, RFI, XXE, SSRF, XSPA)"},{"attributes":{"list":"bullet"},"insert":"\n"},{"insert":"Code injections (HTML, JS, SQL, PHP, ...)"},{"attributes":{"list":"bullet"},"insert":"\n"},{"insert":"Cross-Site Scripting (XSS)"},{"attributes":{"list":"bullet"},"insert":"\n"}]}`

	items := parseQuillBulletItems(delta)

	want := []string{
		"Remote code execution (RCE)",
		"Local files access and manipulation (LFI, RFI, XXE, SSRF, XSPA)",
		"Code injections (HTML, JS, SQL, PHP, ...)",
		"Cross-Site Scripting (XSS)",
	}
	if len(items) != len(want) {
		t.Fatalf("bullet items len = %d, want %d; got: %v", len(items), len(want), items)
	}
	for i, w := range want {
		if items[i] != w {
			t.Errorf("bullet item[%d] = %q, want %q", i, items[i], w)
		}
	}
}

func TestParseQuillDelta_Empty(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty string", ""},
		{"empty object", "{}"},
		{"invalid json", "invalid json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plainText, bulletItems := parseQuillDelta(tt.input)
			if plainText != "" {
				t.Errorf("plainText = %q, want empty", plainText)
			}
			if bulletItems != nil {
				t.Errorf("bulletItems = %v, want nil", bulletItems)
			}
		})
	}
}

func TestExtractBBCMetadata_BountyProgram(t *testing.T) {
	const engagementBody = `{
		"id": "4a9ae9d3-0e03-43c6-8bd2-e7ce7df4adb1",
		"title": "Last Line of Defense - Infrastructure",
		"organization": {"id": "ff43a2dc", "name": "Canton du Jura"},
		"type": 0,
		"state": 1,
		"visibility": 2,
		"qualifyingVulnerabilities": "{\"ops\":[{\"insert\":\"Remote code execution (RCE)\"},{\"attributes\":{\"list\":\"bullet\"},\"insert\":\"\\n\"},{\"insert\":\"Code injections (HTML, JS, SQL, PHP, ...)\"},{\"attributes\":{\"list\":\"bullet\"},\"insert\":\"\\n\"}]}",
		"nonQualifyingVulnerabilities": "{\"ops\":[{\"insert\":\"Social Engineering\"},{\"attributes\":{\"list\":\"bullet\"},\"insert\":\"\\n\"},{\"insert\":\"Clickjacking/UI redressing\"},{\"attributes\":{\"list\":\"bullet\"},\"insert\":\"\\n\"}]}",
		"rules": "{\"ops\":[{\"insert\":\"This is a private program\\n\"},{\"attributes\":{\"list\":\"bullet\"},\"insert\":\"\\n\"},{\"insert\":\"You must be the first reporter\\n\"},{\"attributes\":{\"list\":\"bullet\"},\"insert\":\"\\n\"}]}",
		"notes": "{\"ops\":[{\"insert\":\"To help us identify traffic please add the value \\\"CitizenPortalBugBounty58602853\\\" to the User Agent Header in the requests that you send i.e: \\\"User-Agent: CitizenPortalBugBounty58602853\\\"\\n\"}]}",
		"outOfScope": "{\"ops\":[{\"insert\":\"Any (sub-)domain or IP-Address not listed in the scope section.\\nThe following IP addresses are strictly out-of-scope:\\n193.246.27.50\\n\"}]}",
		"description": "{\"ops\":[{\"insert\":\"This is a private Bug Bounty Program run by the Canton du Jura.\\n\"}]}",
		"rewardLow": 100,
		"rewardMedium": 500,
		"rewardHigh": 1000,
		"rewardCritical": 3000,
		"scopesCount": 9,
		"tags": ["Managed by Bug Bounty"]
	}`

	const scopeGroupsBody = `{
		"id": "4a9ae9d3-0e03-43c6-8bd2-e7ce7df4adb1",
		"policyId": "0a936346",
		"scopes": [
			{"id": "scope1", "name": "UVZH", "scopeType": 0, "bountyLow": 100, "bountyMedium": 500, "bountyHigh": 1000, "bountyCritical": 3000, "assetsCount": 2},
			{"id": "scope2", "name": "Alternative mail systems", "scopeType": 0, "bountyLow": 100, "bountyMedium": 500, "bountyHigh": 1000, "bountyCritical": 3000, "assetsCount": 7}
		]
	}`

	m := extractBBCMetadata(scopeGroupsBody, engagementBody, true)

	// 1. Classification & Context
	if m.Title != "Last Line of Defense - Infrastructure" {
		t.Errorf("Title = %q, want %q", m.Title, "Last Line of Defense - Infrastructure")
	}
	if m.CompanyName != "Canton du Jura" {
		t.Errorf("CompanyName = %q, want %q", m.CompanyName, "Canton du Jura")
	}
	if m.ProgramType != "bug-bounty" {
		t.Errorf("ProgramType = %q, want %q", m.ProgramType, "bug-bounty")
	}
	if m.IsBounty == nil || !*m.IsBounty {
		t.Error("IsBounty should be true (isBBP=true)")
	}
	if m.IsVDP != nil && *m.IsVDP {
		t.Error("IsVDP should be false for type=0")
	}
	if m.IsPublic != nil && *m.IsPublic {
		t.Error("IsPublic should be false for visibility=2")
	}
	if m.IsDisabled != nil && *m.IsDisabled {
		t.Error("IsDisabled should be false for state=1")
	}

	// 2. Rewards
	if m.Currency != "CHF" {
		t.Errorf("Currency = %q, want %q", m.Currency, "CHF")
	}
	if m.BountyRewardMin == nil || *m.BountyRewardMin != 100 {
		t.Errorf("BountyRewardMin = %v, want 100", m.BountyRewardMin)
	}
	if m.BountyRewardMax == nil || *m.BountyRewardMax != 3000 {
		t.Errorf("BountyRewardMax = %v, want 3000", m.BountyRewardMax)
	}
	if len(m.RewardGrids) != 2 {
		t.Fatalf("RewardGrids len = %d, want 2", len(m.RewardGrids))
	}
	wantGrids := []struct {
		dimension            string
		low, med, high, crit int
	}{
		{"UVZH", 100, 500, 1000, 3000},
		{"Alternative mail systems", 100, 500, 1000, 3000},
	}
	for i, wg := range wantGrids {
		rg := m.RewardGrids[i]
		if rg.Dimension != wg.dimension {
			t.Errorf("RewardGrid[%d].Dimension = %q, want %q", i, rg.Dimension, wg.dimension)
		}
		if rg.BountyLowMin == nil || *rg.BountyLowMin != wg.low || rg.BountyLowMax == nil || *rg.BountyLowMax != wg.low {
			t.Errorf("RewardGrid[%d].BountyLow = %v/%v, want %d/%d", i, rg.BountyLowMin, rg.BountyLowMax, wg.low, wg.low)
		}
		if rg.BountyMediumMin == nil || *rg.BountyMediumMin != wg.med || rg.BountyMediumMax == nil || *rg.BountyMediumMax != wg.med {
			t.Errorf("RewardGrid[%d].BountyMedium = %v/%v, want %d/%d", i, rg.BountyMediumMin, rg.BountyMediumMax, wg.med, wg.med)
		}
		if rg.BountyHighMin == nil || *rg.BountyHighMin != wg.high || rg.BountyHighMax == nil || *rg.BountyHighMax != wg.high {
			t.Errorf("RewardGrid[%d].BountyHigh = %v/%v, want %d/%d", i, rg.BountyHighMin, rg.BountyHighMax, wg.high, wg.high)
		}
		if rg.BountyCriticalMin == nil || *rg.BountyCriticalMin != wg.crit || rg.BountyCriticalMax == nil || *rg.BountyCriticalMax != wg.crit {
			t.Errorf("RewardGrid[%d].BountyCritical = %v/%v, want %d/%d", i, rg.BountyCriticalMin, rg.BountyCriticalMax, wg.crit, wg.crit)
		}
	}

	// 3. Scope Rules
	if !strings.Contains(m.Rules, "This is a private program") {
		t.Errorf("Rules = %q, want it to contain %q", m.Rules, "This is a private program")
	}
	if m.RulesFormat != "markdown" {
		t.Errorf("RulesFormat = %q, want %q", m.RulesFormat, "markdown")
	}

	// Qualifying vulnerabilities
	wantQual := []string{"Remote code execution (RCE)", "Code injections (HTML, JS, SQL, PHP, ...)"}
	if len(m.QualifyingVulnerabilities) != len(wantQual) {
		t.Fatalf("QualifyingVulnerabilities len = %d, want %d; got: %v",
			len(m.QualifyingVulnerabilities), len(wantQual), m.QualifyingVulnerabilities)
	}
	for i, w := range wantQual {
		if m.QualifyingVulnerabilities[i] != w {
			t.Errorf("QualifyingVulnerabilities[%d] = %q, want %q", i, m.QualifyingVulnerabilities[i], w)
		}
	}

	// Non-qualifying vulnerabilities
	wantNonQual := []string{"Social Engineering", "Clickjacking/UI redressing"}
	if len(m.NonQualifyingVulnerabilities) != len(wantNonQual) {
		t.Fatalf("NonQualifyingVulnerabilities len = %d, want %d; got: %v",
			len(m.NonQualifyingVulnerabilities), len(wantNonQual), m.NonQualifyingVulnerabilities)
	}
	for i, w := range wantNonQual {
		if m.NonQualifyingVulnerabilities[i] != w {
			t.Errorf("NonQualifyingVulnerabilities[%d] = %q, want %q", i, m.NonQualifyingVulnerabilities[i], w)
		}
	}

	// OutOfScopeSummary should include the OOS text lines.
	if len(m.OutOfScopeSummary) == 0 {
		t.Fatal("OutOfScopeSummary should not be empty")
	}
	foundIP := false
	for _, line := range m.OutOfScopeSummary {
		if line == "193.246.27.50" {
			foundIP = true
		}
	}
	if !foundIP {
		t.Errorf("OutOfScopeSummary should contain the OOS IP 193.246.27.50; got: %v", m.OutOfScopeSummary)
	}

	// 4. Testing Instructions
	// The notes mention "User Agent Header" (space, no hyphen). After the regex
	// fix to also match "User Agent" (without hyphen), the token should be extracted.
	if m.UserAgent != "CitizenPortalBugBounty58602853" {
		t.Errorf("UserAgent = %q, want %q", m.UserAgent, "CitizenPortalBugBounty58602853")
	}

	// 6. Program Stats
	if m.ScopesCount == nil || *m.ScopesCount != 9 {
		t.Errorf("ScopesCount = %v, want 9", m.ScopesCount)
	}
	if len(m.Tags) != 1 || m.Tags[0] != "Managed by Bug Bounty" {
		t.Errorf("Tags = %v, want [Managed by Bug Bounty]", m.Tags)
	}
}

func TestExtractBBCMetadata_VDP(t *testing.T) {
	const engagementBody = `{
		"title": "Stadler Rail AG - VDP",
		"organization": {"name": "Stadler Rail AG"},
		"type": 10,
		"state": 1,
		"visibility": 0,
		"qualifyingVulnerabilities": "",
		"nonQualifyingVulnerabilities": "",
		"rules": "",
		"notes": "",
		"outOfScope": "",
		"description": "",
		"rewardLow": 0,
		"rewardMedium": 0,
		"rewardHigh": 0,
		"rewardCritical": 0,
		"scopesCount": 0,
		"tags": []
	}`

	const scopeGroupsBody = `{"scopes":[]}`

	m := extractBBCMetadata(scopeGroupsBody, engagementBody, false)

	if m.Title != "Stadler Rail AG - VDP" {
		t.Errorf("Title = %q, want %q", m.Title, "Stadler Rail AG - VDP")
	}
	if m.CompanyName != "Stadler Rail AG" {
		t.Errorf("CompanyName = %q, want %q", m.CompanyName, "Stadler Rail AG")
	}
	if m.ProgramType != "vdp" {
		t.Errorf("ProgramType = %q, want %q", m.ProgramType, "vdp")
	}
	if m.IsBounty != nil && *m.IsBounty {
		t.Error("IsBounty should be false (isBBP=false)")
	}
	if m.IsVDP == nil || !*m.IsVDP {
		t.Error("IsVDP should be true for type=10")
	}
	if m.IsPublic == nil || !*m.IsPublic {
		t.Error("IsPublic should be true for visibility=0")
	}
	if m.IsDisabled != nil && *m.IsDisabled {
		t.Error("IsDisabled should be false for state=1")
	}
	if len(m.RewardGrids) != 0 {
		t.Errorf("RewardGrids len = %d, want 0", len(m.RewardGrids))
	}
	if m.BountyRewardMin != nil {
		t.Errorf("BountyRewardMin = %v, want nil", m.BountyRewardMin)
	}
	if m.BountyRewardMax != nil {
		t.Errorf("BountyRewardMax = %v, want nil", m.BountyRewardMax)
	}
	if m.QualifyingVulnerabilities != nil {
		t.Errorf("QualifyingVulnerabilities = %v, want nil", m.QualifyingVulnerabilities)
	}
	if m.NonQualifyingVulnerabilities != nil {
		t.Errorf("NonQualifyingVulnerabilities = %v, want nil", m.NonQualifyingVulnerabilities)
	}
	if m.Rules != "" {
		t.Errorf("Rules = %q, want empty", m.Rules)
	}
	if m.ScopesCount != nil {
		t.Errorf("ScopesCount = %v, want nil (scopesCount=0)", m.ScopesCount)
	}
	if m.Tags != nil {
		t.Errorf("Tags = %v, want nil", m.Tags)
	}
}
