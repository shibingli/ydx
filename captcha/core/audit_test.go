package core

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestJSONAuditSinkWritesOneObjectPerLine(t *testing.T) {
	var buf bytes.Buffer
	sink := NewJSONAuditSink(&buf)
	if err := sink.WriteAudit(context.Background(), AuditEvent{Outcome: AuditCreated, IP: "203.0.113.8", Target: "us***@example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := sink.WriteAudit(context.Background(), AuditEvent{Outcome: AuditPassed, Risk: 12}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %d: %q", len(lines), buf.String())
	}
	if !strings.Contains(lines[0], `"outcome":"created"`) || !strings.Contains(lines[0], `"target":"us***@example.com"`) {
		t.Fatalf("unexpected first line: %s", lines[0])
	}
	if !strings.Contains(lines[1], `"outcome":"passed"`) || !strings.Contains(lines[1], `"risk":12`) {
		t.Fatalf("unexpected second line: %s", lines[1])
	}
}
