package scope

import (
	"sort"
	"testing"
)

func TestGetAllStringsForCategoriesAliases(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"apple resolves to ios", "apple", unificationMap["ios"]},
		{"device resolves to hardware", "device", unificationMap["hardware"]},
		{"mobile spans android and ios", "mobile", append(append([]string{}, unificationMap["android"]...), unificationMap["ios"]...)},
		{"alias combined with unified name", "device,url", append(append([]string{}, unificationMap["hardware"]...), unificationMap["url"]...)},
		{"unified names still work", "ios", unificationMap["ios"]},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetAllStringsForCategories(tt.input)
			if got == nil {
				t.Fatalf("GetAllStringsForCategories(%q) = nil (no filtering), want %v", tt.input, tt.want)
			}
			sort.Strings(got)
			want := append([]string{}, tt.want...)
			sort.Strings(want)
			if len(got) != len(want) {
				t.Fatalf("GetAllStringsForCategories(%q) = %v, want %v", tt.input, got, want)
			}
			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("GetAllStringsForCategories(%q) = %v, want %v", tt.input, got, want)
				}
			}
		})
	}
}

func TestGetAllStringsForCategoriesInvalid(t *testing.T) {
	for _, input := range []string{"all", "", "nonsense"} {
		if got := GetAllStringsForCategories(input); got != nil {
			t.Errorf("GetAllStringsForCategories(%q) = %v, want nil (no filtering)", input, got)
		}
	}

	if got := GetAllStringsForCategories("nonsense,mobile"); got == nil {
		t.Error(`GetAllStringsForCategories("nonsense,mobile") = nil, want the mobile categories`)
	}
}
