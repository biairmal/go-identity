package password

import (
	_ "embed"
	"strings"
	"sync"
)

// commonListRaw is the embedded common-password list, one password per line.
// It is the top 10,000 of the xato-net 10-million-password corpus as
// published in SecLists, which is what TRD 10 means by "the 10k most common
// passwords". Embedding it keeps the check in-process: no file to mount and
// no service to call on the sign-in path.
//
//go:embed common.txt
var commonListRaw string

// commonSet is the list as a lower-cased lookup set, built once on first use
// so a process that never validates a password never pays for it. Entries
// differing only in case collapse into one, which is what makes the check
// case-insensitive.
var commonSet = sync.OnceValue(func() map[string]struct{} {
	set := make(map[string]struct{}, 10000)
	for line := range strings.SplitSeq(commonListRaw, "\n") {
		if entry := strings.ToLower(strings.TrimSpace(line)); entry != "" {
			set[entry] = struct{}{}
		}
	}
	return set
})

// IsCommon reports whether plain is in the embedded common-password list,
// ignoring case.
func IsCommon(plain string) bool {
	_, found := commonSet()[strings.ToLower(plain)]
	return found
}

// CommonListSize is the number of distinct passwords in the embedded list,
// after case-folding.
func CommonListSize() int { return len(commonSet()) }
