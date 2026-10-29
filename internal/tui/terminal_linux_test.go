//go:build linux

package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/term"

	"netlog/internal/collector"
	"netlog/internal/pipeline"
)

// ---- a pseudo-terminal pair --------------------------------------------------------------

func ioctl(fd uintptr, req uintptr, arg unsafe.Pointer) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(arg)); e != 0 {
		return e
	}
	return nil
}

// openPTY returns the master and slave ends of a new pseudo-terminal sized
// cols x rows, or skips the test where one cannot be made.
func openPTY(t *testing.T, cols, rows uint16) (master, slave *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal available: %v", err)
	}
	var unlock int32
	var n uint32
	if err := ioctl(m.Fd(), syscall.TIOCSPTLCK, unsafe.Pointer(&unlock)); err != nil {
		m.Close()
		t.Skipf("cannot unlock the pty: %v", err)
	}
	if err := ioctl(m.Fd(), syscall.TIOCGPTN, unsafe.Pointer(&n)); err != nil {
		m.Close()
		t.Skipf("cannot name the pty: %v", err)
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		m.Close()
		t.Skipf("cannot open the pty slave: %v", err)
	}
	ws := struct{ rows, cols, x, y uint16 }{rows, cols, 0, 0}
	if err := ioctl(s.Fd(), syscall.TIOCSWINSZ, unsafe.Pointer(&ws)); err != nil {
		t.Skipf("cannot size the pty: %v", err)
	}
	t.Cleanup(func() { m.Close(); s.Close() })
	return m, s
}

// capture collects everything the program writes to the terminal.
type capture struct {
	mu  sync.Mutex
	buf strings.Builder
}

func newCapture(master *os.File) *capture {
	c := &capture{}
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := master.Read(b)
			c.mu.Lock()
			c.buf.Write(b[:n])
			c.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	return c
}

func (c *capture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

func (c *capture) waitFor(t *testing.T, what string, subs ...string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		out := c.String()
		ok := true
		for _, s := range subs {
			ok = ok && strings.Contains(out, s)
		}
		if ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s (%q); output so far:\n%q", what, subs, c.String())
}

// ---- a fixed data source ----------------------------------------------------------------

type fixedSource struct {
	entries []collector.LogEntry
	devices []DeviceRow
	panicAt int // panic on this poll number (0 = never)
	polls   int
	mu      sync.Mutex
}

func (f *fixedSource) Poll(time.Time) ([]collector.LogEntry, []DeviceRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.polls++
	if f.panicAt != 0 && f.polls >= f.panicAt {
		panic("source exploded")
	}
	if f.polls == 1 {
		return f.entries, f.devices, nil
	}
	return nil, nil, nil
}

func sampleSource() *fixedSource {
	t0 := time.Now()
	return &fixedSource{
		entries: []collector.LogEntry{
			{Timestamp: t0.Add(-2 * time.Minute), Hostname: "core1", Category: "FAULT", Severity: "ERROR", Event: pipeline.EventLinkDown, Object: "Gi0/1", Summary: "Interface Gi0/1 down"},
			{Timestamp: t0.Add(-time.Minute), Hostname: "edge2", Category: "CONFIG", Severity: "WARNING", Event: pipeline.EventConfigChange, Summary: "config changed by tanvt"},
		},
		devices: []DeviceRow{{Hostname: "core1", Status: "OK", LastPoll: t0}},
	}
}

// ptyRun is a dashboard running on a pseudo-terminal.
type ptyRun struct {
	out    *capture
	master *os.File
	slave  *os.File
	before *term.State
	cancel context.CancelFunc
	done   chan error
}

func startRun(t *testing.T, src Source, cols, rows uint16) *ptyRun {
	t.Helper()
	master, slave := openPTY(t, cols, rows)
	before, err := term.GetState(int(slave.Fd()))
	if err != nil {
		t.Skipf("cannot read terminal state: %v", err)
	}
	r := &ptyRun{out: newCapture(master), master: master, slave: slave, before: before, done: make(chan error, 1)}
	var ctx context.Context
	ctx, r.cancel = context.WithCancel(context.Background())
	t.Cleanup(r.cancel)
	go func() {
		r.done <- Run(ctx, slave, slave, src, RunOptions{Refresh: 100 * time.Millisecond, Loc: time.UTC})
	}()
	return r
}

func (r *ptyRun) wait(t *testing.T) error {
	t.Helper()
	select {
	case err := <-r.done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
		return nil
	}
}

func (r *ptyRun) assertRestored(t *testing.T) {
	t.Helper()
	after, err := term.GetState(int(r.slave.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.before, after) {
		t.Error("the terminal was left in raw mode")
	}
	r.out.waitFor(t, "leaving the alternate screen", escLeaveScreen)
	out := r.out.String()
	if !strings.HasSuffix(out, escLeaveScreen) {
		t.Errorf("output must end by leaving the alternate screen and showing the cursor, ends with %q", out[max(0, len(out)-40):])
	}
	if strings.Count(out, "\x1b[?1049h") != 1 || strings.Count(out, "\x1b[?1049l") != 1 {
		t.Error("alternate screen entered or left an unexpected number of times")
	}
}

// ---- tests ------------------------------------------------------------------------------

func TestRunDrivesTheTerminalAndRestoresIt(t *testing.T) {
	r := startRun(t, sampleSource(), 110, 30)
	r.out.waitFor(t, "first frame", escEnterScreen, "netlog top", "Live events (2)", "core1", "Interface Gi0/1 down", "CONFIG 1")
	if now, err := term.GetState(int(r.slave.Fd())); err != nil || reflect.DeepEqual(now, r.before) {
		t.Error("the terminal should be in raw mode while the dashboard runs")
	}

	r.master.WriteString("c") // category filter: FAULT
	r.out.waitFor(t, "filter FAULT", "[filter: FAULT]", "Live events (FAULT, 1)")

	// An arrow key is not a command: its trailing 'C' must not advance the filter.
	r.master.WriteString("\x1b[C")
	r.master.WriteString("c")
	r.out.waitFor(t, "filter CONFIG", "[filter: CONFIG]")
	if strings.Contains(r.out.String(), "[filter: AUTH]") {
		t.Error("an arrow key sequence was taken for the c command")
	}

	r.master.WriteString("p")
	r.out.waitFor(t, "paused", "[PAUSED +0]")
	r.master.WriteString("p")

	r.master.WriteString("q")
	if err := r.wait(t); err != nil {
		t.Fatalf("Run returned %v", err)
	}
	r.assertRestored(t)
}

func TestRunQuitsOnCtrlCOnContextCancelAndWhenTheTerminalGoes(t *testing.T) {
	t.Run("ctrl+c", func(t *testing.T) {
		r := startRun(t, sampleSource(), 100, 28)
		r.out.waitFor(t, "first frame", "netlog top")
		r.master.WriteString("\x03")
		if err := r.wait(t); err != nil {
			t.Fatal(err)
		}
		r.assertRestored(t)
	})
	t.Run("context cancelled (SIGTERM)", func(t *testing.T) {
		r := startRun(t, sampleSource(), 100, 28)
		r.out.waitFor(t, "first frame", "netlog top")
		r.cancel()
		if err := r.wait(t); err != nil {
			t.Fatal(err)
		}
		r.assertRestored(t)
	})
	t.Run("terminal closed", func(t *testing.T) {
		r := startRun(t, sampleSource(), 100, 28)
		r.out.waitFor(t, "first frame", "netlog top")
		r.master.Close() // the user closed the window
		select {
		case <-r.done: // nil (input closed) or a write error: either way it returned
		case <-time.After(5 * time.Second):
			t.Fatal("Run hung after the terminal went away")
		}
	})
}

func TestRunRestoresTheTerminalWhenTheSourcePanics(t *testing.T) {
	master, slave := openPTY(t, 100, 28)
	before, err := term.GetState(int(slave.Fd()))
	if err != nil {
		t.Skip(err)
	}
	out := newCapture(master)
	src := sampleSource()
	src.panicAt = 2 // the first poll (before the first frame) works, the next one panics
	func() {
		defer func() {
			if recover() == nil {
				t.Error("the source panic should propagate")
			}
		}()
		Run(context.Background(), slave, slave, src, RunOptions{Refresh: 100 * time.Millisecond})
	}()
	after, _ := term.GetState(int(slave.Fd()))
	if !reflect.DeepEqual(before, after) {
		t.Error("terminal left in raw mode after a panic")
	}
	out.waitFor(t, "leave sequence", escLeaveScreen)
}

func TestRunRefusesANonTerminal(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if err := Run(context.Background(), r, w, sampleSource(), RunOptions{}); !errors.Is(err, ErrNotTerminal) {
		t.Errorf("pipe: %v", err)
	}
	// A terminal on one side only is refused as well.
	_, slave := openPTY(t, 80, 24)
	if err := Run(context.Background(), r, slave, sampleSource(), RunOptions{}); !errors.Is(err, ErrNotTerminal) {
		t.Errorf("piped stdin: %v", err)
	}
}

func TestRunRedrawsOnResizeAndSkipsUnchangedFrames(t *testing.T) {
	r := startRun(t, sampleSource(), 100, 30)
	r.out.waitFor(t, "first frame", "netlog top")

	// Between ticks nothing but (at most) the clock changes: the screen is
	// not rewritten wholesale every refresh.
	time.Sleep(150 * time.Millisecond)
	n1 := len(r.out.String())
	time.Sleep(250 * time.Millisecond)
	if grew := len(r.out.String()) - n1; grew > 3*10000 {
		t.Errorf("an unchanged frame was rewritten repeatedly (%d bytes)", grew)
	}

	// Shrinking the window below the minimum shows the size notice.
	ws := struct{ rows, cols, x, y uint16 }{8, 40, 0, 0}
	if err := ioctl(r.slave.Fd(), syscall.TIOCSWINSZ, unsafe.Pointer(&ws)); err != nil {
		t.Skip("cannot resize the pty")
	}
	r.out.waitFor(t, "size notice", "terminal too small (40x8)")
	r.master.WriteString("q")
	if err := r.wait(t); err != nil {
		t.Fatal(err)
	}
	r.assertRestored(t)
}
