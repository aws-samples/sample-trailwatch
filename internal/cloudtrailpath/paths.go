// Package cloudtrailpath centralizes supported CloudTrail S3 layouts.
package cloudtrailpath

import (
	"fmt"
	"path/filepath"
	"time"
)

const MultiAccountMode = "control_tower"

// AccountPrefixes returns every supported account root. Multi-account trails
// exist in several layouts depending on whether they were created directly by
// AWS Organizations, by Control Tower, or by older sample configurations.
func AccountPrefixes(mode, orgID, accountID string) []string {
	if mode == MultiAccountMode && orgID != "" {
		return unique([]string{
			fmt.Sprintf("AWSLogs/%s/%s/", orgID, accountID),
			fmt.Sprintf("%s/AWSLogs/%s/%s/", orgID, orgID, accountID),
			fmt.Sprintf("%s/AWSLogs/%s/", orgID, accountID),
		})
	}
	return []string{fmt.Sprintf("AWSLogs/%s/", accountID)}
}

func CloudTrailPrefixes(mode, orgID, accountID string) []string {
	return appendSuffix(AccountPrefixes(mode, orgID, accountID), "CloudTrail/")
}

func RegionPrefixes(mode, orgID, accountID, region string) []string {
	return appendSuffix(CloudTrailPrefixes(mode, orgID, accountID), region+"/")
}

func DatePrefixes(mode, orgID, accountID, region string, date time.Time) []string {
	return appendSuffix(RegionPrefixes(mode, orgID, accountID, region), date.Format("2006/01/02")+"/")
}

// AccountDiscoveryPrefixes returns the locations where member account IDs may
// appear for a known organization ID.
func AccountDiscoveryPrefixes(orgID string) []string {
	if orgID == "" {
		return []string{"AWSLogs/"}
	}
	return unique([]string{
		fmt.Sprintf("AWSLogs/%s/", orgID),
		fmt.Sprintf("%s/AWSLogs/%s/", orgID, orgID),
		fmt.Sprintf("%s/AWSLogs/", orgID),
	})
}

// LocalRegionDirs mirrors every supported RegionPrefix under the local S3 data
// root. Only the layout that exists in S3 will normally exist on disk.
func LocalRegionDirs(dataDir, bucket, mode, orgID, accountID, region string) []string {
	prefixes := RegionPrefixes(mode, orgID, accountID, region)
	dirs := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		dirs = append(dirs, filepath.Join(dataDir, "s3", bucket, filepath.FromSlash(prefix)))
	}
	return dirs
}

// LocalQueryRoot returns a stable query root. Multi-account downloads may use
// any supported organization layout, so queries start at the bucket mirror and
// rely on account scoping. Single-account paths stay narrow.
func LocalQueryRoot(dataDir, bucket, mode, orgID, accountID, region string) string {
	if mode == MultiAccountMode && orgID != "" {
		return filepath.ToSlash(filepath.Join(dataDir, "s3", bucket)) + "/"
	}
	return filepath.ToSlash(filepath.Join(
		dataDir, "s3", bucket, "AWSLogs", accountID, "CloudTrail", region,
	)) + "/"
}

func appendSuffix(prefixes []string, suffix string) []string {
	out := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		out = append(out, prefix+suffix)
	}
	return out
}

func unique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
