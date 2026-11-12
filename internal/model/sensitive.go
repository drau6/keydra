package model

import "regexp"

var sensitiveName = regexp.MustCompile(`(?i)user|profile|customer|client|order|payment|invoice|message|chat|email|account|token|secret|address|phone|member|patient|student|booking`)

// SeverityForName returns Critical when a table, collection or bucket name
// suggests personal or financial data, otherwise High. It is used when an
// exposed data store is found.
func SeverityForName(name string) Severity {
	if sensitiveName.MatchString(name) {
		return Critical
	}
	return High
}
