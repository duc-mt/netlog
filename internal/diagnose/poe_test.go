package diagnose

import (
	"strings"
	"testing"

	"netlog/internal/triage"
)

// Synthetic samples that follow the documented layouts; not live captures.
const (
	ciscoPoE = `Available:740.0(w)  Used:123.4(w)  Remaining:616.6(w)

Interface Admin  Oper       Power   Device              Class Max
                            (Watts)
--------- ------ ---------- ------- ------------------- ----- ----
Gi1/0/1   auto   on         15.4    Ieee PD             4     30.0
Gi1/0/2   auto   faulty     0.0     n/a                 n/a   30.0
Gi1/0/3   auto   power-deny 0.0     n/a                 n/a   30.0
Gi1/0/4   auto   off        0.0     n/a                 n/a   30.0
`
	ciscoStackPoE = `Module   Available     Used     Remaining
          (Watts)    (Watts)    (Watts)
------   ---------   --------   ---------
    1        370.0      129.0       241.0
    2        370.0      350.0        20.0

Interface Admin  Oper       Power   Device              Class Max
--------- ------ ---------- ------- ------------------- ----- ----
Gi1/0/1   auto   on         15.4    Ieee PD             4     30.0
Gi2/0/9   auto   overload   0.0     n/a                 n/a   30.0
`
	arubaPoE = ` Status and Counters - System Power Status

  Pre-standard Detect  : Off
  Chassis power-over-ethernet
  Total Available Power   : 382 W
  Total Failover Power    : 0 W
  Total Redundancy Power  : 0 W
  Total Used Power        : 360 W

 Port   Enabled  Detection Status  Class  Power
 -----  -------- ----------------- ------ ----------
 1      Yes      Delivering        3      7.1 W
 2      Yes      Fault             0      0 W
 3      Yes      Delivering        2      4.0 W
 Overload protection: enabled
`
	huaweiPoE = `PoE power state
Total power(W)       : 740
Consumption power(W) : 123
Port      PowerState
GE0/0/1   powered
GE0/0/2   fault
`
)

func TestParsePoE(t *testing.T) {
	tests := []struct {
		name, out string
		budgets   []PoEBudget
		flagged   []PoEPort
	}{
		{"cisco single", ciscoPoE, []PoEBudget{{"system", 740.0, 123.4}}, []PoEPort{{"Gi1/0/2", "faulty"}}},
		{"cisco stack modules", ciscoStackPoE, []PoEBudget{{"module 1", 370, 129}, {"module 2", 370, 350}}, []PoEPort{{"Gi2/0/9", "overload"}}},
		{"aruba", arubaPoE, []PoEBudget{{"system", 382, 360}}, []PoEPort{{"2", "faulty"}}}, // "Overload protection: enabled" is not a port row
		{"huawei", huaweiPoE, []PoEBudget{{"system", 740, 123}}, []PoEPort{{"GE0/0/2", "faulty"}}},
		{"empty", "", nil, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := ParsePoE(tc.out)
			if len(f.Budgets) != len(tc.budgets) || len(f.Flagged) != len(tc.flagged) {
				t.Fatalf("got %+v", f)
			}
			for i := range f.Budgets {
				if f.Budgets[i] != tc.budgets[i] {
					t.Errorf("budget %d = %+v, want %+v", i, f.Budgets[i], tc.budgets[i])
				}
			}
			for i := range f.Flagged {
				if f.Flagged[i] != tc.flagged[i] {
					t.Errorf("flagged %d = %+v, want %+v", i, f.Flagged[i], tc.flagged[i])
				}
			}
		})
	}
}

func TestAnalysePoEThresholdAndStatus(t *testing.T) {
	run := func(out string) Section {
		s := Section{Name: SecPoE, Output: out}
		analysePoE(&s)
		return s
	}
	// Healthy budget, one faulty port: warns about the port only.
	s := run(ciscoPoE)
	n := strings.Join(s.Notes, "\n")
	if s.Status != StatusWarn || !strings.Contains(n, "Gi1/0/2 (faulty)") || !strings.Contains(n, "16.7%") || strings.Contains(n, "threshold") {
		t.Errorf("single: %s %q", s.Status, s.Notes)
	}
	if s.Metrics["poe_flagged_ports"] != 1 {
		t.Errorf("metrics %v", s.Metrics)
	}

	// Exactly 90% does not exceed the threshold; just above it does.
	at := run("Available:400.0(w)  Used:360.0(w)  Remaining:40.0(w)\n")
	if at.Status != StatusOK {
		t.Errorf("90.0%% must pass: %s %q", at.Status, at.Notes)
	}
	over := run("Available:400.0(w)  Used:361.0(w)  Remaining:39.0(w)\n")
	if over.Status != StatusWarn || !strings.Contains(strings.Join(over.Notes, "\n"), "above the 90% threshold") {
		t.Errorf("90.25%% must warn: %s %q", over.Status, over.Notes)
	}

	// Per-module budgets are judged separately.
	st := run(ciscoStackPoE)
	if st.Status != StatusWarn || !strings.Contains(strings.Join(st.Notes, "\n"), "module 2") || st.Metrics["poe_module_2_used_pct"] < 94 {
		t.Errorf("stack: %s %q %v", st.Status, st.Notes, st.Metrics)
	}
	if ar := run(arubaPoE); ar.Status != StatusWarn || !strings.Contains(strings.Join(ar.Notes, "\n"), "94.2%") {
		t.Errorf("aruba: %s %q", ar.Status, ar.Notes)
	}

	// No budget in the output: say the check was skipped; ports still audited.
	nb := run("Port   Enabled  Detection Status\n 1      Yes      Delivering\n 2      Yes      Overload\n")
	if nb.Status != StatusWarn || !strings.Contains(strings.Join(nb.Notes, "\n"), "usage check was skipped") {
		t.Errorf("no budget: %s %q", nb.Status, nb.Notes)
	}
	// A clean switch is OK.
	if ok := run("Available:740.0(w)  Used:10.0(w)  Remaining:730.0(w)\nGi1/0/1   auto   on   15.4\n"); ok.Status != StatusOK {
		t.Errorf("clean: %s %q", ok.Status, ok.Notes)
	}
	// A platform that does not know the command is N/A, not a pass.
	rej := run("% Invalid input detected at '^' marker.\n")
	if rej.Status != StatusUnknown || !strings.Contains(strings.Join(rej.Notes, "\n"), "rejected the PoE command") {
		t.Errorf("rejected: %s %q", rej.Status, rej.Notes)
	}
}

func TestPoECommands(t *testing.T) {
	want := map[string]string{"cisco_ios": "show power inline", "aruba": "show power-over-ethernet", "huawei_vrp": "display poe power-state"}
	for key, cmd := range want {
		if got := PoECommand(key); got != cmd {
			t.Errorf("PoECommand(%s) = %q", key, got)
		}
		if err := triage.Check(cmd); err != nil {
			t.Errorf("%s: %v", cmd, err)
		}
	}
	for _, key := range []string{"ruijie", "juniper_junos", "arista", "cisco_asa", "cisco_sb", "mikrotik", "generic", ""} {
		if PoECommand(key) != "" {
			t.Errorf("%s must have no PoE command", key)
		}
	}
}

func FuzzParsePoE(f *testing.F) {
	for _, s := range []string{ciscoPoE, ciscoStackPoE, arubaPoE, huaweiPoE, "", "Available:(w) Used:(w)", "1 2 3 4", strings.Repeat("Gi1/0/1 fault\n", 100)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, out string) {
		s := Section{Name: SecPoE, Output: out}
		analysePoE(&s) // must not panic
		for _, b := range ParsePoE(out).Budgets {
			if b.Percent() < 0 {
				t.Fatalf("negative usage: %+v", b)
			}
		}
	})
}
