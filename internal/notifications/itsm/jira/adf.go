// Copyright 2026 Kryptkeeper Authors
//
// SPDX-License-Identifier: Apache-2.0

package jira

// adfDoc builds an Atlassian Document Format document with one plain-text
// paragraph per line. Jira Cloud REST v3 rejects string bodies for
// descriptions and comments.
func adfDoc(lines []string) map[string]any {
	content := make([]any, 0, len(lines))
	for _, l := range lines {
		p := map[string]any{"type": "paragraph"}
		if l != "" {
			p["content"] = []any{map[string]any{"type": "text", "text": l}}
		}
		content = append(content, p)
	}
	return map[string]any{"type": "doc", "version": 1, "content": content}
}
