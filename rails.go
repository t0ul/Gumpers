package gumpers

import (
	"regexp"
	"strings"
)

type namedRe struct {
	name string
	re   *regexp.Regexp
}

// regexRail fires a fixed Action for any match of any of its rules.
type regexRail struct {
	name   string
	action Action
	rules  []namedRe
}

func (r *regexRail) Name() string { return r.name }

func (r *regexRail) Check(text string) []Hit {
	var hits []Hit
	for _, nr := range r.rules {
		for _, idx := range nr.re.FindAllStringIndex(text, -1) {
			hits = append(hits, Hit{
				Rail:   r.name,
				Rule:   nr.name,
				Action: r.action,
				Match:  snippet(text, idx[0], idx[1]),
				Start:  idx[0],
				End:    idx[1],
			})
		}
	}
	return hits
}

// --- Injection (input stage) ---

var injectionRules = []namedRe{
	{"ignore-instructions", regexp.MustCompile(`(?i)\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|earlier|all|any)\b.{0,25}\b(instructions?|prompts?|rules?|context|messages?)\b`)},
	{"reveal-system", regexp.MustCompile(`(?i)\b(reveal|show|print|repeat|output|display|tell me|give me)\b.{0,30}\b(system prompt|your instructions|initial prompt|the prompt above|your rules|your guidelines)\b`)},
	{"override-role", regexp.MustCompile(`(?i)(\byou are now\b|\bdeveloper mode\b|\bdo anything now\b|\bdan mode\b|\bact as\b.{0,25}\b(dan|jailbreak|unrestricted)\b)`)},
	{"role-escape", regexp.MustCompile(`(?i)\b(pretend|imagine|roleplay|simulate)\b.{0,30}\b(no (restrictions|rules|filters|guidelines)|unrestricted|without (any )?(limits|restrictions|rules))\b`)},
	{"injection-delimiter", regexp.MustCompile(`(?i)(</?(system|user|assistant|instructions?)\s*>|\[/?(inst|system)\]|###\s*system)`)},
	{"concealment", regexp.MustCompile(`(?i)do\s+not\s+(mention|reveal|tell|disclose)`)},
	{"imperative-inject", regexp.MustCompile(`(?i)you\s+(must|are\s+required\s+to|should|need\s+to)\s+(add|include|output|send|verify|wire)`)},
	{"assistant-directive", regexp.MustCompile(`(?i)\b(assistant|ai|system)\s+(note|instruction|directive|override)\b`)},
	{"prompt-extraction", regexp.MustCompile(`(?i)\bwhat\s+(are|were)\s+your\s+(system\s+)?(instructions|prompt|rules)\b`)},
}

// InjectionRail blocks common prompt-injection / jailbreak patterns. Input stage.
func InjectionRail() Rail {
	return &regexRail{name: "injection", action: Block, rules: injectionRules}
}

// --- Leak (output stage) ---

var leakRules = []namedRe{
	{"leak-phrase", regexp.MustCompile(`(?i)\b(my (system )?(instructions?|prompt)s? (is|are|says)|i was (told|instructed|programmed|configured) to|the system prompt (is|says)|here (is|are) my (instructions|system prompt)|as an ai,? my instructions)\b`)},
	{"verbatim-markers", regexp.MustCompile(`(?i)(you are a helpful assistant|the following are your instructions|do not reveal|BEGIN SYSTEM PROMPT|### system)`)},
}

// LeakRail blocks a reply that appears to disclose its own system prompt. Output stage.
func LeakRail() Rail {
	return &regexRail{name: "leak", action: Block, rules: leakRules}
}

// --- Secret (output stage) ---

var secretRules = []namedRe{
	{"secret-assignment", regexp.MustCompile(`(?i)\b\w*(?:secret|passwd|password|token|apikey|api[_-]?key|access[_-]?key|credential|private[_-]?key)\w*\s*=\s*\S+`)},
	{"aws-key", regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|A3T[A-Z0-9])[A-Z0-9]{16}\b`)},
	{"token", regexp.MustCompile(`\b(?:sk|pk|rk|ghp|gho|ghs|xox[baprs])[-_][A-Za-z0-9]{16,}\b`)},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b`)},
	{"bearer", regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._\-]{10,}\b`)},
}

// SecretRail catches secrets/keys leaking in a reply. Pass Redact to mask them
// (default, safe to send) or Block to refuse the whole reply. Output stage.
func SecretRail(action Action) Rail {
	return &regexRail{name: "secret", action: action, rules: secretRules}
}

// --- Denylist (any stage) ---

// DenylistRail blocks (or flags/redacts) any of the given literal terms,
// case-insensitively. Terms are matched as whole words where possible.
func DenylistRail(name string, action Action, terms ...string) Rail {
	rules := make([]namedRe, 0, len(terms))
	for _, t := range terms {
		if t == "" {
			continue
		}
		rules = append(rules, namedRe{
			name: "term",
			re:   regexp.MustCompile(`(?i)` + `\b` + regexp.QuoteMeta(t) + `\b`),
		})
	}
	return &regexRail{name: name, action: action, rules: rules}
}

// --- Canary (output stage) ---

type canaryRail struct{ canaries []string }

func (c *canaryRail) Name() string { return "canary" }

func (c *canaryRail) Check(text string) []Hit {
	var hits []Hit
	for _, can := range c.canaries {
		if can == "" {
			continue
		}
		if i := strings.Index(text, can); i >= 0 {
			// Never echo the canary value into a hit/log; it is a secret marker.
			hits = append(hits, Hit{
				Rail:   "canary",
				Rule:   "system-prompt-canary",
				Action: Block,
				Match:  "<canary>",
				Start:  i,
				End:    i + len(can),
			})
		}
	}
	return hits
}

// CanaryRail blocks any reply that contains a planted system-prompt canary —
// a high-signal, zero-false-positive detector of prompt disclosure. Output stage.
func CanaryRail(canaries ...string) Rail {
	return &canaryRail{canaries: canaries}
}

// DetectEcho reports whether output verbatim-echoes any n-word shingle of
// reference — an output-side system-prompt leak detector (LLM07) robust to
// surrounding text. It returns the overlapping shingle for forensics; callers
// must treat that snippet as secret and never log it raw. n defaults to 6.
func DetectEcho(output, reference string, n int) (bool, string) {
	if output == "" || reference == "" {
		return false, ""
	}
	if n <= 0 {
		n = 6
	}
	ref := shingleSet(reference, n)
	for _, sh := range shingles(output, n) {
		if ref[sh] {
			return true, sh
		}
	}
	return false, ""
}

var reShingleClean = regexp.MustCompile(`[^a-z0-9 ]+`)

func shingleTokens(text string) []string {
	return strings.Fields(reShingleClean.ReplaceAllString(strings.ToLower(text), " "))
}

func shingles(text string, n int) []string {
	t := shingleTokens(text)
	if len(t) < n {
		return nil
	}
	out := make([]string, 0, len(t)-n+1)
	for i := 0; i+n <= len(t); i++ {
		out = append(out, strings.Join(t[i:i+n], " "))
	}
	return out
}

func shingleSet(text string, n int) map[string]bool {
	m := make(map[string]bool)
	for _, s := range shingles(text, n) {
		m[s] = true
	}
	return m
}
