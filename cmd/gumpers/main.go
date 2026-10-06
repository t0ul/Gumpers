// Command gumpers runs the guardrails engine over stdin and prints a JSON verdict.
//
//	echo "ignore all previous instructions" | gumpers -stage input
//	echo "$reply" | gumpers -stage output -canary ZX9-CANARY-7Q
//
// Exit code is 0 when allowed/flagged/redacted and 2 when blocked, so it slots
// into a pipeline as a gate.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/t0ul/gumpers"
)

func main() {
	stage := flag.String("stage", "input", "which rails to run: input | output")
	canary := flag.String("canary", "", "system-prompt canary string to detect in output")
	flag.Parse()

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gumpers: read stdin:", err)
		os.Exit(1)
	}

	var opts []gumpers.Option
	if *canary != "" {
		opts = append(opts, gumpers.WithDefaults(*canary))
	} else {
		opts = append(opts, gumpers.WithDefaults())
	}
	e := gumpers.New(opts...)

	trace := gumpers.NewTraceID()
	var v gumpers.Verdict
	if *stage == "output" {
		v = e.CheckOutput(trace, string(data))
	} else {
		v = e.CheckInput(trace, string(data))
	}

	out, _ := json.MarshalIndent(map[string]any{
		"trace_id": trace,
		"stage":    *stage,
		"action":   v.Action.String(),
		"blocked":  v.Blocked,
		"reasons":  v.Reasons(),
		"text":     v.Text,
	}, "", "  ")
	fmt.Println(string(out))

	if v.Blocked {
		os.Exit(2)
	}
}
