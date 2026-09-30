package mechanics_test

import (
	"context"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/eval"
	"github.com/use-assay/assay/internal/mechanics"
)

// loadSubject rebuilds a Subject from captured fixtures, using the same
// decoders the live fetchers use. The loader lives in internal/eval so this
// package and the eval command share one implementation, and neither touches
// the network. See eval.LoadSubject.
func loadSubject(t *testing.T, dir string) *mechanics.Subject {
	t.Helper()
	s, err := eval.LoadSubject("testdata", dir)
	if err != nil {
		t.Fatalf("load %s: %v", dir, err)
	}
	return s
}

// TestEval is the aggregate judgment eval. Detecting a flag is deterministic
// and uninteresting; what these cases measure is whether the severity model
// separates a trap from a legitimate compliance feature, and whether escalation
// fires only on reputation.
//
// The labels live in eval.Corpus so the aggregate and per-check evals cannot
// describe different runs. See docs/eval.md for the labelling rationale.
func TestEval(t *testing.T) {
	eng := mechanics.NewEngine()
	for _, tc := range eval.Corpus() {
		t.Run(tc.Dir, func(t *testing.T) {
			rep, err := eng.Run(context.Background(), loadSubject(t, tc.Dir))
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if rep.Base != tc.Base {
				t.Errorf("base severity = %v, want %v\nwhy this case exists: %s",
					rep.Base, tc.Base, tc.Why)
			}
			if rep.Severity != tc.Severity {
				t.Errorf("severity = %v, want %v\nwhy this case exists: %s",
					rep.Severity, tc.Severity, tc.Why)
			}
			if rep.Escalated != tc.Escalated {
				t.Errorf("escalated = %v, want %v", rep.Escalated, tc.Escalated)
			}
			if rep.Accountability != tc.Accountability {
				t.Errorf("accountability = %v, want %v", rep.Accountability, tc.Accountability)
			}
		})
	}
}

// TestEvalPerCheck evaluates each check's output independently (#115).
//
// The aggregate can be right for the wrong reason: a capability check that
// said clear and a reputation escalation that raised the level to critical
// produce a correct report while the capability error stays invisible. This
// compares every finding against its own label, so that cannot happen.
func TestEvalPerCheck(t *testing.T) {
	eng := mechanics.NewEngine()
	for _, tc := range eval.Corpus() {
		t.Run(tc.Dir, func(t *testing.T) {
			rep, err := eng.Run(context.Background(), loadSubject(t, tc.Dir))
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			res := eval.EvaluateChecks(rep, tc)
			if res.Partial {
				t.Fatalf("subject %s is only partially evaluated: labelled checks with no "+
					"finding %v, findings with no label %v", tc.Dir, res.Missing, res.Unlabelled)
			}
			for _, m := range res.Mismatches {
				t.Errorf("check %s disagrees: got %s, want %s", m.Check, m.Got, m.Want)
			}
			t.Logf("per-check agreement for %s: %v", tc.Dir, res.Agreed)
		})
	}
}

// TestEvalPerCheckDetectsWrongExpectation proves the per-check evaluator
// actually fails when a check's output diverges from its label, rather than
// reporting agreement unconditionally.
func TestEvalPerCheckDetectsWrongExpectation(t *testing.T) {
	eng := mechanics.NewEngine()

	var doge eval.Label
	found := false
	for _, tc := range eval.Corpus() {
		if tc.Dir == "doge-noflags-scam" {
			doge, found = tc, true
		}
	}
	if !found {
		t.Fatal("doge-noflags-scam is missing from the corpus")
	}

	// Deliberately wrong: DOGE's capability is honestly clear, and this claims
	// high. A passing evaluator would fail to notice.
	capability := doge.Checks["capability"]
	capability.Severity = mechanics.High
	doge.Checks["capability"] = capability

	rep, err := eng.Run(context.Background(), loadSubject(t, doge.Dir))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	res := eval.EvaluateChecks(rep, doge)
	if len(res.Mismatches) != 1 || res.Mismatches[0].Check != "capability" {
		t.Fatalf("a deliberately wrong per-check expectation was not caught: %+v", res)
	}
}

// TestEvalPerCheckReportsPartialLabels covers the missing state: a subject
// without per-check labels must be visibly partial, not silently passing.
func TestEvalPerCheckReportsPartialLabels(t *testing.T) {
	eng := mechanics.NewEngine()
	rep, err := eng.Run(context.Background(), loadSubject(t, "aqua-clear-verified"))
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	// No per-check labels at all. An evaluator that only looked at the
	// aggregate would call this complete.
	res := eval.EvaluateChecks(rep, eval.Label{Dir: "aqua-clear-verified"})
	if !res.Partial {
		t.Fatal("a subject without per-check labels was reported as fully evaluated")
	}
	if res.OK() {
		t.Fatal("OK() returned true for a partially labelled subject")
	}
	if len(res.Unlabelled) == 0 {
		t.Fatal("findings with no label were not reported as unlabelled")
	}
}

// TestAccountabilityNeverChangesSeverity is the property the whole model rests
// on. Two subjects with identical issuer flags must classify identically no
// matter how well attributed they are, or a contract gating on severity is
// relying on someone's opinion instead of on ledger mechanics.
func TestAccountabilityNeverChangesSeverity(t *testing.T) {
	eng := mechanics.NewEngine()

	verified := loadSubject(t, "aqua-clear-verified")
	anonymous := loadSubject(t, "aqua-clear-verified")
	// Strip every trace of attribution, leaving the flags untouched.
	anonymous.Issuer.HomeDomain = ""
	anonymous.Toml = nil
	anonymous.Directory = nil
	anonymous.Blocked = nil

	repV, err := eng.Run(context.Background(), verified)
	if err != nil {
		t.Fatal(err)
	}
	repA, err := eng.Run(context.Background(), anonymous)
	if err != nil {
		t.Fatal(err)
	}

	if repV.Severity != repA.Severity {
		t.Errorf("attribution changed severity: verified=%v anonymous=%v",
			repV.Severity, repA.Severity)
	}
	if repV.Accountability == repA.Accountability {
		t.Errorf("accountability should differ between the two subjects, both = %v",
			repV.Accountability)
	}
}

// TestNoHomeDomainIsUnknownNotUnverified is the distinction issue #3 asks for,
// asserted against a real capture rather than a stripped copy: VELO's issuer
// account carries no home_domain at all (Horizon omits the field entirely), so
// nobody has claimed the asset. That is a different state from a domain that
// was advertised and failed verification, and it must not move severity either
// — aqua-clear-verified is the same flags with a claim on top.
func TestNoHomeDomainIsUnknownNotUnverified(t *testing.T) {
	eng := mechanics.NewEngine()

	unclaimed, err := eng.Run(context.Background(), loadSubject(t, "velo-no-home-domain"))
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := eng.Run(context.Background(), loadSubject(t, "aqua-clear-verified"))
	if err != nil {
		t.Fatal(err)
	}

	if unclaimed.Accountability != mechanics.AccountabilityUnknown {
		t.Errorf("accountability = %q, want %q: an issuer with no home_domain has made no "+
			"claim, it has not failed one", unclaimed.Accountability, mechanics.AccountabilityUnknown)
	}
	if claimed.Accountability != mechanics.AccountabilityVerified {
		t.Errorf("control subject accountability = %q, want %q",
			claimed.Accountability, mechanics.AccountabilityVerified)
	}
	if unclaimed.Base != claimed.Base || unclaimed.Severity != claimed.Severity {
		t.Errorf("identical flags classified differently: no home_domain = %v/%v, verified domain = %v/%v",
			unclaimed.Base, unclaimed.Severity, claimed.Base, claimed.Severity)
	}

	var domain *mechanics.Finding
	for i := range unclaimed.Findings {
		if unclaimed.Findings[i].Check == "sep1-domain" {
			domain = &unclaimed.Findings[i]
		}
	}
	if domain == nil {
		t.Fatal("report carries no sep1-domain finding")
	}
	for _, want := range []string{"Nobody has publicly claimed", "not a failed verification"} {
		if !strings.Contains(domain.Reasoning, want) {
			t.Errorf("reasoning must say %q: %s", want, domain.Reasoning)
		}
	}
}

// TestConfiscationImpliesHigh enforces the ABI invariant the contract relies
// on: anything matching ConfiscationMask is at least High.
func TestConfiscationImpliesHigh(t *testing.T) {
	eng := mechanics.NewEngine()
	for _, tc := range eval.Corpus() {
		rep, err := eng.Run(context.Background(), loadSubject(t, tc.Dir))
		if err != nil {
			t.Fatal(err)
		}
		if rep.Mechanics&mechanics.ConfiscationMask != 0 && rep.Base < mechanics.High {
			t.Errorf("%s: confiscation-capable but base severity %v < high", tc.Dir, rep.Base)
		}
	}
}
