package update

import (
	"strings"

	"golang.org/x/mod/semver"
)

func CompareVersions(current string, latest string) int {
	currentValid := semver.IsValid(current)
	latestValid := semver.IsValid(latest)
	switch {
	case currentValid && latestValid:
		return semver.Compare(current, latest)
	case !currentValid && latestValid:
		return -1
	case currentValid && !latestValid:
		return 1
	default:
		return strings.Compare(current, latest)
	}
}
