// Package gumpers is a zero-dependency guardrails engine for LLM I/O — the
// bumpers on the lane. Input rails catch prompt-injection and jailbreak
// attempts before they reach the model; output rails catch system-prompt
// leakage, planted-canary leaks, and secret spillage before a reply goes out.
//
// It is rule-based and deterministic (no model in the loop), so a rail that
// fires is explainable and testable — the defense half of attack-driven
// development. Audit is decoupled behind an Auditor interface identical to
// gledger.AuditLog.Emit, so a *gledger.AuditLog satisfies it as-is. Part of
// the fleet.
package gumpers

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
)

// Action is a rail outcome. Values are ordered so the most severe wins.
type Action int

const (
	Allow  Action = iota // nothing fired
	Flag                 // record it, let it through
	Redact               // mask the matched spans, let it through
	Block                // refuse
)

// String renders an Action for logs.
func (a Action) String() string {
	switch a {
	case Flag:
		return "flag"
	case Redact:
		return "redact"
	case Block:
		return "block"
	default:
		return "allow"
	}
}

// Hit is one rail match.
type Hit struct {
	Rail   string // rail that fired (e.g. "injection")
	Rule   string // sub-rule within the rail (e.g. "ignore-instructions")
	Action Action
	Match  string // bounded, control-char-defanged snippet of what matched
	Start  int    // byte offset in the checked text
	End    int
}

// Rail inspects text and returns zero or more hits.
type Rail interface {
	Name() string
	Check(text string) []Hit
}

// Verdict is the aggregate result of running a stage's rails over some text.
type Verdict struct {
	Action  Action // most severe action across all hits
	Blocked bool   // Action == Block
	Text    string // original text, or redacted copy when Action == Redact
	Hits    []Hit
}

// Reasons returns the unique "rail:rule" keys that fired, for logging/UX.
func (v Verdict) Reasons() []string {
	seen := make(map[string]bool)
	var out []string
	for _, h := range v.Hits {
		key := h.Rail + ":" + h.Rule
		if !seen[key] {
			seen[key] = true
			out = append(out, key)
		}
	}
	return out
}

// Auditor receives structured audit events. *gledger.AuditLog satisfies it as-is.
type Auditor interface {
	Emit(traceID, span, event string, fields map[string]any) string
}

// Engine holds the configured input and output rails.
type Engine struct {
	input   []Rail
	output  []Rail
	auditor Auditor
}

// Option configures an Engine.
type Option func(*Engine)

// WithInputRail adds a rail to the input (pre-model) stage.
func WithInputRail(r Rail) Option { return func(e *Engine) { e.input = append(e.input, r) } }

// WithOutputRail adds a rail to the output (post-model) stage.
func WithOutputRail(r Rail) Option { return func(e *Engine) { e.output = append(e.output, r) } }

// WithAuditor attaches an audit sink (e.g. a *gledger.AuditLog).
func WithAuditor(a Auditor) Option { return func(e *Engine) { e.auditor = a } }

// WithDefaults installs the standard rail set: injection on input; leak and
// secret-redaction on output; plus a canary rail for any supplied canaries.
func WithDefaults(canaries ...string) Option {
	return func(e *Engine) {
		e.input = append(e.input, InjectionRail())
		e.output = append(e.output, LeakRail(), SecretRail(Redact))
		if len(canaries) > 0 {
			e.output = append(e.output, CanaryRail(canaries...))
		}
	}
}

// New builds an Engine from options.
func New(opts ...Option) *Engine {
	e := &Engine{}
	for _, o := range opts {
		o(e)
	}
	return e
}

// CheckInput runs the input rails over user/tool text headed to the model.
func (e *Engine) CheckInput(traceID, text string) Verdict {
	return e.run(traceID, "input", e.input, text)
}

// CheckOutput runs the output rails over a model reply headed to the user.
func (e *Engine) CheckOutput(traceID, text string) Verdict {
	return e.run(traceID, "output", e.output, text)
}

func (e *Engine) run(traceID, stage string, rails []Rail, text string) Verdict {
	var hits []Hit
	eff := Allow
	for _, r := range rails {
		for _, h := range r.Check(text) {
			hits = append(hits, h)
			if h.Action > eff {
				eff = h.Action
			}
		}
	}
	out := text
	if eff == Redact {
		out = redactSpans(text, hits)
	}
	v := Verdict{Action: eff, Blocked: eff == Block, Text: out, Hits: hits}
	if e.auditor != nil && len(hits) > 0 {
		// Log only rule keys and counts — never the matched attacker/secret text.
		e.auditor.Emit(traceID, "gumpers", stage, map[string]any{
			"action":    eff.String(),
			"rails":     v.Reasons(),
			"hit_count": len(hits),
		})
	}
	return v
}

// redactSpans masks only the spans whose hit has Action == Redact.
func redactSpans(text string, hits []Hit) string {
	type span struct{ a, b int }
	var sp []span
	for _, h := range hits {
		if h.Action == Redact && h.End > h.Start && h.Start >= 0 && h.End <= len(text) {
			sp = append(sp, span{h.Start, h.End})
		}
	}
	if len(sp) == 0 {
		return text
	}
	sort.Slice(sp, func(i, j int) bool { return sp[i].a < sp[j].a })
	merged := sp[:1]
	for _, s := range sp[1:] {
		last := &merged[len(merged)-1]
		if s.a <= last.b {
			if s.b > last.b {
				last.b = s.b
			}
		} else {
			merged = append(merged, s)
		}
	}
	var b strings.Builder
	prev := 0
	for _, s := range merged {
		b.WriteString(text[prev:s.a])
		b.WriteString("[REDACTED]")
		prev = s.b
	}
	b.WriteString(text[prev:])
	return b.String()
}

var ctrl = regexp.MustCompile(`[\x00-\x1f\x7f]`)

func snippet(s string, a, b int) string {
	m := s[a:b]
	if len(m) > 120 {
		m = m[:120] + "…"
	}
	return ctrl.ReplaceAllString(m, " ")
}

// NewTraceID returns a random 128-bit hex correlation id.
func NewTraceID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
