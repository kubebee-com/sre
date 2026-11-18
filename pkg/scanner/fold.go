package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

const maxFoldedAffectedResources = 25

// CategorySummary aggregates raw and folded findings for a single category.
type CategorySummary struct {
	Category        IssueCategory `json:"category"`
	Group           FindingGroup  `json:"group"`
	HighestSeverity Severity      `json:"highest_severity"`
	Count           int           `json:"count"`
	FoldedCount     int           `json:"folded_count"`
	Namespaces      []string      `json:"namespaces,omitempty"`
}

// SeverityRank orders severities from LOW (1) to CRITICAL (4).
func SeverityRank(s Severity) int {
	return severityRank(s)
}

// FoldIssues collapses repeated similar findings (same category, workload owner
// or resource-peer pattern) into deterministic representative issues with
// OccurrenceCount and AffectedResources populated.
func FoldIssues(issues []*Issue) []*Issue {
	if len(issues) == 0 {
		return []*Issue{}
	}
	sorted := make([]*Issue, 0, len(issues))
	for _, raw := range issues {
		if raw == nil {
			continue
		}
		item := cloneIssue(raw)
		normalizeIssue(item, item.DocsURL)
		sorted = append(sorted, item)
	}
	if len(sorted) == 0 {
		return []*Issue{}
	}
	sort.SliceStable(sorted, func(i, j int) bool {
		return issueLess(sorted[i], sorted[j])
	})

	type foldBucket struct {
		key     string
		pattern string
		members []*Issue
	}
	buckets := make(map[string]*foldBucket, len(sorted))
	order := make([]string, 0, len(sorted))

	for _, item := range sorted {
		key, pattern := issueFoldKeyAndPattern(item)
		bucket, exists := buckets[key]
		if !exists {
			bucket = &foldBucket{key: key, pattern: pattern}
			buckets[key] = bucket
			order = append(order, key)
		}
		bucket.members = append(bucket.members, item)
	}

	folded := make([]*Issue, 0, len(order))
	for _, key := range order {
		bucket := buckets[key]
		rep := buildFoldedIssue(bucket.key, bucket.pattern, bucket.members)
		normalizeIssue(rep, rep.DocsURL)
		folded = append(folded, rep)
	}
	sort.SliceStable(folded, func(i, j int) bool {
		leftRank := severityRank(folded[i].Severity)
		rightRank := severityRank(folded[j].Severity)
		if leftRank != rightRank {
			return leftRank > rightRank
		}
		if folded[i].OccurrenceCount != folded[j].OccurrenceCount {
			return folded[i].OccurrenceCount > folded[j].OccurrenceCount
		}
		return issueLess(folded[i], folded[j])
	})
	return folded
}

// FoldSanitizedIssues folds sanitized issues and returns sanitized projections.
func FoldSanitizedIssues(issues []*SanitizedIssue) []*SanitizedIssue {
	if len(issues) == 0 {
		return []*SanitizedIssue{}
	}
	raw := make([]*Issue, 0, len(issues))
	for _, item := range issues {
		if item != nil {
			raw = append(raw, item.AsIssue())
		}
	}
	folded := FoldIssues(raw)
	result := make([]*SanitizedIssue, 0, len(folded))
	for _, item := range folded {
		result = append(result, SanitizeIssue(item))
	}
	return result
}

// SummarizeCategories aggregates findings into category-level summaries ordered
// by severity and raw count.
func SummarizeCategories(issues []*Issue) []CategorySummary {
	if len(issues) == 0 {
		return []CategorySummary{}
	}
	folded := FoldIssues(issues)
	foldedByCategory := make(map[IssueCategory]int, len(folded))
	for _, item := range folded {
		if item != nil {
			foldedByCategory[item.Category]++
		}
	}

	type acc struct {
		summary CategorySummary
		nsSeen  map[string]struct{}
	}
	byCategory := make(map[IssueCategory]*acc)
	for _, item := range issues {
		if item == nil {
			continue
		}
		entry, ok := byCategory[item.Category]
		if !ok {
			group := item.Group
			if group == "" {
				group = ResolveFindingGroup(item.Category)
			}
			entry = &acc{
				summary: CategorySummary{
					Category:        item.Category,
					Group:           group,
					HighestSeverity: item.Severity,
					FoldedCount:     foldedByCategory[item.Category],
				},
				nsSeen: make(map[string]struct{}),
			}
			byCategory[item.Category] = entry
		}
		entry.summary.Count++
		if severityRank(item.Severity) > severityRank(entry.summary.HighestSeverity) {
			entry.summary.HighestSeverity = item.Severity
		}
		if ns := strings.TrimSpace(item.Namespace); ns != "" {
			if _, seen := entry.nsSeen[ns]; !seen {
				entry.nsSeen[ns] = struct{}{}
				entry.summary.Namespaces = append(entry.summary.Namespaces, ns)
			}
		}
	}

	result := make([]CategorySummary, 0, len(byCategory))
	for _, entry := range byCategory {
		sort.Strings(entry.summary.Namespaces)
		if entry.summary.FoldedCount == 0 && entry.summary.Count > 0 {
			entry.summary.FoldedCount = 1
		}
		result = append(result, entry.summary)
	}
	sort.Slice(result, func(i, j int) bool {
		leftRank := severityRank(result[i].HighestSeverity)
		rightRank := severityRank(result[j].HighestSeverity)
		if leftRank != rightRank {
			return leftRank > rightRank
		}
		if result[i].FoldedCount != result[j].FoldedCount {
			return result[i].FoldedCount > result[j].FoldedCount
		}
		if result[i].Count != result[j].Count {
			return result[i].Count > result[j].Count
		}
		return result[i].Category < result[j].Category
	})
	return result
}

func issueFoldKeyAndPattern(issue *Issue) (string, string) {
	if issue == nil {
		return "", ""
	}
	group := issue.Group
	if group == "" {
		group = ResolveFindingGroup(issue.Category)
	}
	ns := strings.TrimSpace(issue.Namespace)
	if ns == "" {
		ns = "_cluster"
	}
	pattern := normalizeFoldPattern(issue)

	var scope string
	switch {
	case issue.Parent != nil && strings.TrimSpace(issue.Parent.Name) != "":
		parentNS := strings.TrimSpace(issue.Parent.Namespace)
		if parentNS == "" {
			parentNS = ns
		}
		parentKind := strings.TrimSpace(issue.Parent.Kind)
		parentName := strings.TrimSpace(issue.Parent.Name)
		if issue.Category == CategorySecurityPrivilege {
			pattern = "security-privilege"
		}
		scope = fmt.Sprintf("owner:%s:%s/%s:%s", parentNS, parentKind, parentName, pattern)
	case categoryFoldsAcrossNamespace(issue.Category):
		scopePattern := pattern
		if issue.Category == CategoryWarningEvent {
			if reason := extractWarningEventReason(issue); reason != "" {
				scopePattern = reason
			}
		}
		scope = fmt.Sprintf("peer:%s:%s:%s", ns, issue.Kind, scopePattern)
	default:
		scope = fmt.Sprintf("resource:%s:%s:%s:%s", ns, issue.Kind, issue.Name, pattern)
	}

	rawKey := fmt.Sprintf("fold/v1|%s|%s|%s", group, issue.Category, scope)
	digest := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(digest[:8]), pattern
}

func categoryFoldsAcrossNamespace(category IssueCategory) bool {
	switch category {
	case CategoryConfigMapUnused,
		CategoryConfigMapEmpty,
		CategoryNetworkPolicyOrphaned,
		CategoryNetworkPolicyWide,
		CategorySecurityClusterBinding,
		CategorySecurityPrivilege,
		CategoryPodVulnerability,
		CategoryWarningEvent:
		return true
	default:
		return false
	}
}

func normalizeFoldPattern(issue *Issue) string {
	if issue == nil {
		return ""
	}
	summary := strings.TrimSpace(issue.Summary)
	if summary == "" {
		return string(issue.Category)
	}
	name := strings.TrimSpace(issue.Name)
	if name != "" {
		if issue.Namespace != "" {
			summary = strings.ReplaceAll(summary, issue.Namespace+"/"+name, "<resource>")
		}
		summary = strings.ReplaceAll(summary, name, "<resource>")
	}
	return summary
}

func extractWarningEventReason(issue *Issue) string {
	if issue == nil {
		return ""
	}
	if strings.HasPrefix(issue.Details, "[") {
		if end := strings.IndexByte(issue.Details, ']'); end > 1 {
			return strings.TrimSpace(issue.Details[1:end])
		}
	}
	const prefix = "Warning event "
	if strings.HasPrefix(issue.Summary, prefix) {
		rest := strings.TrimPrefix(issue.Summary, prefix)
		if space := strings.IndexByte(rest, ' '); space > 0 {
			return strings.TrimSpace(rest[:space])
		}
	}
	return ""
}

func buildFoldedIssue(foldKey, pattern string, members []*Issue) *Issue {
	rep := cloneIssue(members[0])
	if rep == nil {
		return nil
	}
	rep.FoldKey = foldKey
	if existingCount := rep.OccurrenceCount; existingCount <= 1 && len(members) == 1 {
		rep.OccurrenceCount = 1
		if len(rep.AffectedResources) == 0 {
			rep.AffectedResources = []string{formatAffectedResource(rep)}
		}
		return rep
	}

	totalOccurrences := 0
	affectedSeen := make(map[string]struct{}, len(members))
	affected := make([]string, 0, min(len(members), maxFoldedAffectedResources))

	for _, member := range members {
		if member == nil {
			continue
		}
		if member.OccurrenceCount > 1 {
			totalOccurrences += member.OccurrenceCount
		} else {
			totalOccurrences++
		}
		if severityRank(member.Severity) > severityRank(rep.Severity) {
			rep.Severity = member.Severity
		}
		if !member.FirstObserved.IsZero() && (rep.FirstObserved.IsZero() || member.FirstObserved.Before(rep.FirstObserved)) {
			rep.FirstObserved = member.FirstObserved
		}
		if !member.LastObserved.IsZero() && (rep.LastObserved.IsZero() || member.LastObserved.After(rep.LastObserved)) {
			rep.LastObserved = member.LastObserved
		}
		rep.AnalyzerNames = appendUniqueField(rep.AnalyzerNames, member.AnalyzerNames...)
		for _, ev := range member.Events {
			rep.Events = appendUniqueField(rep.Events, ev)
		}
		if rep.LogsSnippet == "" && member.LogsSnippet != "" {
			rep.LogsSnippet = member.LogsSnippet
		}
		if rep.SpecSnippet == "" && member.SpecSnippet != "" {
			rep.SpecSnippet = member.SpecSnippet
		}
		candidates := member.AffectedResources
		if len(candidates) == 0 {
			candidates = []string{formatAffectedResource(member)}
		}
		for _, res := range candidates {
			if _, ok := affectedSeen[res]; ok {
				continue
			}
			affectedSeen[res] = struct{}{}
			if len(affected) < maxFoldedAffectedResources {
				affected = append(affected, res)
			}
		}
	}

	sort.Strings(rep.AnalyzerNames)
	sort.Strings(affected)
	if len(rep.Events) > maxIssueEventCount {
		rep.Events = rep.Events[:maxIssueEventCount]
	}

	rep.OccurrenceCount = totalOccurrences
	rep.AffectedResources = affected
	if len(members) > 1 {
		if rep.Parent != nil && strings.TrimSpace(rep.Parent.Name) != "" {
			rep.Summary = fmt.Sprintf("%s/%s (%d similar %s findings): %s", rep.Parent.Kind, rep.Parent.Name, totalOccurrences, rep.Category, pattern)
		} else {
			rep.Summary = fmt.Sprintf("%d %s resources (%s): %s", totalOccurrences, rep.Kind, rep.Category, pattern)
		}
		if len(affected) > 0 {
			extra := ""
			if totalOccurrences > len(affected) {
				extra = fmt.Sprintf(" (+%d more)", totalOccurrences-len(affected))
			}
			rep.Details = fmt.Sprintf("Folded %d similar findings (%s). Affected: %s%s.\n\nRepresentative detail (%s):\n%s",
				totalOccurrences, rep.Category, strings.Join(affected, ", "), extra, rep.Name, rep.Details)
		}
	}
	return rep
}

func formatAffectedResource(issue *Issue) string {
	if issue == nil {
		return ""
	}
	if issue.Namespace != "" {
		return issue.Namespace + "/" + issue.Name
	}
	return issue.Name
}
