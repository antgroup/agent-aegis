// ClawAegis sentinel runner (unified, M8).
//
// One static Go binary that handles three modes:
//   --mode=ebpf    : syscall tracepoint observer (replaces ebpf/runner/probe.py)
//   --mode=uprobe  : libc uprobe observer (replaces uprobe/runner/probe.py)
//   --mode=lsm     : LSM enforce (M7.5)
//
// Each mode reads optional control input from stdin (lsm: policy upserts;
// other modes: ignored) and writes JSONL events to stdout. The TS loaders
// in sentinel/probes/{ebpf,uprobe,lsm}/loader.ts spawn this binary with the
// appropriate --mode and parse stdout.
//
// Load failure (kernel < 5.7 for lsm, missing CAP_BPF, etc.) emits a
// `log/error` message and exits non-zero — the loader logs warn and lets
// sentinel keep running with the remaining probes.
package main

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed bpf/lsm.bpf.o
var lsmBpfObj []byte

//go:embed bpf/exec.bpf.o
var execBpfObj []byte

func main() {
	mode := flag.String("mode", "", "runner mode: ebpf | uprobe | lsm")
	targets := flag.String("targets", "execve,openat,connect", "comma-separated target syscalls (ebpf/uprobe only)")
	libcPath := flag.String("libc-path", "/lib/x86_64-linux-gnu/libc.so.6", "uprobe libc path")
	_ = flag.String("openssl-path", "", "uprobe openssl path (reserved)")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		logLine("error", "rlimit remove memlock failed: "+err.Error())
		os.Exit(3)
	}

	switch *mode {
	case "ebpf":
		runEbpfMode(parseTargets(*targets))
	case "uprobe":
		runUprobeMode(parseTargets(*targets), *libcPath)
	case "lsm":
		runLsmMode()
	default:
		fmt.Fprintln(os.Stderr, "missing or unknown --mode (use ebpf|uprobe|lsm)")
		os.Exit(2)
	}
}

func parseTargets(s string) map[string]bool {
	out := map[string]bool{}
	for _, t := range strings.Split(s, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			out[t] = true
		}
	}
	return out
}

// ----------------- shared event handling -----------------

const (
	commLen    = 16
	pathLen    = 256
	maxArgv    = 8
	maxArgLen  = 64
	kindExec   = 0
	kindOpen   = 1
	kindConn   = 2
)

type sysEvent struct {
	Kind  uint32
	Pid   uint32
	Ppid  uint32
	Comm  [commLen]byte
	Path  [pathLen]byte
	Argc  uint32
	Argv  [maxArgv][maxArgLen]byte
}

type runnerMessage struct {
	Kind    string   `json:"kind"`
	Hooks   []string `json:"hooks,omitempty"`
	Probes  []string `json:"probes,omitempty"`
	Hook    string   `json:"hook,omitempty"`
	Syscall string   `json:"syscall,omitempty"`
	Pid     uint32   `json:"pid,omitempty"`
	Ppid    uint32   `json:"ppid,omitempty"`
	Comm    string   `json:"comm,omitempty"`
	Path    string   `json:"path,omitempty"`
	Argv    []string `json:"argv,omitempty"`
	Match   string   `json:"match,omitempty"`
	Ts      int64    `json:"ts,omitempty"`
	Level   string   `json:"level,omitempty"`
	Message string   `json:"message,omitempty"`
}

func emit(m runnerMessage) {
	if err := json.NewEncoder(os.Stdout).Encode(m); err != nil {
		fmt.Fprintln(os.Stderr, "json encode failed:", err)
	}
}

func logLine(level, message string) {
	emit(runnerMessage{Kind: "log", Level: level, Message: message})
}

func syscallName(kind uint32) string {
	switch kind {
	case kindExec:
		return "execve"
	case kindOpen:
		return "openat"
	case kindConn:
		return "connect"
	}
	return "unknown"
}

func trimZero(b []byte) []byte {
	for i, c := range b {
		if c == 0 {
			return b[:i]
		}
	}
	return b
}

func emitSysEvent(ev sysEvent, targets map[string]bool) {
	sc := syscallName(ev.Kind)
	if !targets[sc] {
		return
	}
	argv := []string{}
	for i := uint32(0); i < ev.Argc && i < maxArgv; i++ {
		a := string(trimZero(ev.Argv[i][:]))
		if a != "" {
			argv = append(argv, a)
		}
	}
	emit(runnerMessage{
		Kind:    "syscall",
		Syscall: sc,
		Pid:     ev.Pid,
		Ppid:    ev.Ppid,
		Comm:    string(trimZero(ev.Comm[:])),
		Path:    string(trimZero(ev.Path[:])),
		Argv:    argv,
		Ts:      time.Now().UnixMilli(),
	})
}

// ----------------- ebpf tracepoint mode -----------------

func runEbpfMode(targets map[string]bool) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytesReader(execBpfObj))
	if err != nil {
		logLine("error", "BPF spec load failed: "+err.Error())
		os.Exit(4)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		logLine("error", "BPF NewCollection failed: "+err.Error())
		os.Exit(5)
	}
	defer coll.Close()

	var attached []string
	var links []link.Link
	tpProgs := []struct{ name, prog, group, sym string }{
		{"execve", "tp_sys_enter_execve", "syscalls", "sys_enter_execve"},
		{"openat", "tp_sys_enter_openat", "syscalls", "sys_enter_openat"},
		{"connect", "tp_sys_enter_connect", "syscalls", "sys_enter_connect"},
	}
	for _, t := range tpProgs {
		if !targets[t.name] {
			continue
		}
		p := coll.Programs[t.prog]
		if p == nil {
			logLine("warn", "tracepoint program missing: "+t.prog)
			continue
		}
		l, err := link.Tracepoint(t.group, t.sym, p, nil)
		if err != nil {
			logLine("warn", "tracepoint attach "+t.name+" failed: "+err.Error())
			continue
		}
		links = append(links, l)
		attached = append(attached, t.name)
	}
	if len(links) == 0 {
		logLine("error", "no tracepoints attached")
		os.Exit(6)
	}
	defer closeLinks(links)

	emit(runnerMessage{Kind: "ready", Probes: attached})

	rd, err := ringbuf.NewReader(coll.Maps["sys_events"])
	if err != nil {
		logLine("error", "ringbuf reader: "+err.Error())
		os.Exit(7)
	}
	defer rd.Close()

	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			logLine("warn", "ringbuf read: "+err.Error())
			continue
		}
		if len(rec.RawSample) < int(unsafe.Sizeof(sysEvent{})) {
			continue
		}
		ev := *(*sysEvent)(unsafe.Pointer(&rec.RawSample[0]))
		emitSysEvent(ev, targets)
	}
}

// ----------------- uprobe mode -----------------

func runUprobeMode(targets map[string]bool, libcPath string) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytesReader(execBpfObj))
	if err != nil {
		logLine("error", "BPF spec load failed: "+err.Error())
		os.Exit(4)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		logLine("error", "BPF NewCollection failed: "+err.Error())
		os.Exit(5)
	}
	defer coll.Close()

	exe, err := link.OpenExecutable(libcPath)
	if err != nil {
		logLine("error", "open libc failed: "+err.Error())
		os.Exit(6)
	}

	var attached []string
	var links []link.Link

	tryAttach := func(target, sym, progName string) {
		p := coll.Programs[progName]
		if p == nil {
			return
		}
		l, err := exe.Uprobe(sym, p, nil)
		if err != nil {
			logLine("warn", "uprobe "+target+" via sym "+sym+" failed: "+err.Error())
			return
		}
		links = append(links, l)
		attached = append(attached, target)
	}
	if targets["execve"] {
		tryAttach("execve", "execve", "up_execve")
	}
	if targets["openat"] {
		tryAttach("openat", "openat", "up_openat")
		tryAttach("openat", "openat64", "up_openat")
		tryAttach("openat", "open", "up_open")
	}
	if targets["connect"] {
		tryAttach("connect", "connect", "up_connect")
	}
	if len(links) == 0 {
		logLine("error", "no uprobes attached")
		os.Exit(7)
	}
	defer closeLinks(links)

	emit(runnerMessage{Kind: "ready", Probes: dedupe(attached)})

	rd, err := ringbuf.NewReader(coll.Maps["sys_events"])
	if err != nil {
		logLine("error", "ringbuf reader: "+err.Error())
		os.Exit(8)
	}
	defer rd.Close()

	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			logLine("warn", "ringbuf read: "+err.Error())
			continue
		}
		if len(rec.RawSample) < int(unsafe.Sizeof(sysEvent{})) {
			continue
		}
		ev := *(*sysEvent)(unsafe.Pointer(&rec.RawSample[0]))
		emitSysEvent(ev, targets)
	}
}

// ----------------- lsm enforce mode -----------------

const (
	policyValueLen = 256

	policyKindExecPath    uint32 = 0
	policyKindOpenPath    uint32 = 1
	policyKindConnectAddr uint32 = 2
)

type policyKey struct {
	Kind  uint32
	Value [policyValueLen]byte
}

type policyVal struct {
	ExpiresNs uint64
	Severity  uint32
	Pad       uint32 // align to 16 bytes to match BPF struct layout
}

type denyEvent struct {
	Pid   uint32
	Ppid  uint32
	Comm  [commLen]byte
	Hook  uint32
	Match [policyValueLen]byte
}

type policyEntryWire struct {
	Kind      string `json:"kind"`
	Value     string `json:"value"`
	Severity  string `json:"severity"`
	ExpiresAt int64  `json:"expiresAt"`
	Source    string `json:"source"`
}

type policyMessage struct {
	Kind  string           `json:"kind"`
	Entry *policyEntryWire `json:"entry,omitempty"`
}

func runLsmMode() {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytesReader(lsmBpfObj))
	if err != nil {
		logLine("error", "BPF spec load failed: "+err.Error())
		os.Exit(4)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		logLine("error", "BPF NewCollection failed: "+err.Error())
		os.Exit(5)
	}
	defer coll.Close()

	progs := []struct {
		name string
		prog *ebpf.Program
	}{
		{"file_open", coll.Programs["check_file_open"]},
		{"bprm_check_security", coll.Programs["check_bprm"]},
		{"socket_connect", coll.Programs["check_socket_connect"]},
	}
	var links []link.Link
	var hookNames []string
	for _, p := range progs {
		if p.prog == nil {
			logLine("warn", "program missing: "+p.name)
			continue
		}
		l, err := link.AttachLSM(link.LSMOptions{Program: p.prog})
		if err != nil {
			logLine("warn", "attach "+p.name+" failed: "+err.Error())
			continue
		}
		links = append(links, l)
		hookNames = append(hookNames, p.name)
	}
	if len(links) == 0 {
		logLine("error", "no LSM hooks attached")
		os.Exit(6)
	}
	defer closeLinks(links)

	policyMap := coll.Maps["policy_map"]
	denyMap := coll.Maps["deny_events"]
	if policyMap == nil || denyMap == nil {
		logLine("error", "expected BPF maps missing")
		os.Exit(7)
	}

	emit(runnerMessage{Kind: "ready", Hooks: hookNames})

	go func() {
		rd, err := ringbuf.NewReader(denyMap)
		if err != nil {
			logLine("error", "ringbuf reader: "+err.Error())
			return
		}
		defer rd.Close()
		for {
			rec, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				logLine("warn", "ringbuf read: "+err.Error())
				continue
			}
			if len(rec.RawSample) < int(unsafe.Sizeof(denyEvent{})) {
				continue
			}
			ev := *(*denyEvent)(unsafe.Pointer(&rec.RawSample[0]))
			emitDeny(ev)
		}
	}()

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var msg policyMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			logLine("warn", "policy parse: "+err.Error())
			continue
		}
		switch msg.Kind {
		case "policy_upsert":
			if msg.Entry == nil {
				continue
			}
			if err := upsertPolicy(policyMap, msg.Entry); err != nil {
				logLine("warn", "policy upsert: "+err.Error())
			}
		case "policy_clear":
			if err := clearPolicy(policyMap); err != nil {
				logLine("warn", "policy clear: "+err.Error())
			}
		default:
			logLine("debug", "ignored policy kind: "+msg.Kind)
		}
	}
	if err := scanner.Err(); err != nil {
		logLine("warn", "stdin scanner: "+err.Error())
	}
}

func basename(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}

func upsertPolicy(m *ebpf.Map, e *policyEntryWire) error {
	var k policyKey
	switch e.Kind {
	case "exec_path":
		k.Kind = policyKindExecPath
		// LSM bprm filename is what was passed to execve — that already
		// includes the full path on most kernels, so store as-is.
		copy(k.Value[:], e.Value)
	case "open_path":
		k.Kind = policyKindOpenPath
		// LSM file_open dentry exposes only the leaf (d_name.name). Key by
		// basename so the BPF lookup hits.
		copy(k.Value[:], basename(e.Value))
	case "connect_addr":
		k.Kind = policyKindConnectAddr
		ip := net.ParseIP(e.Value).To4()
		if ip == nil {
			return fmt.Errorf("connect_addr requires IPv4, got %q", e.Value)
		}
		copy(k.Value[0:4], ip)
	default:
		return fmt.Errorf("unknown policy kind %q", e.Kind)
	}
	val := policyVal{
		ExpiresNs: 0,
		Severity:  severityToInt(e.Severity),
	}
	return m.Update(&k, &val, ebpf.UpdateAny)
}

func clearPolicy(m *ebpf.Map) error {
	var k policyKey
	var v policyVal
	it := m.Iterate()
	type pair struct {
		Kind  uint32
		Value [policyValueLen]byte
	}
	var seen []pair
	for it.Next(&k, &v) {
		seen = append(seen, pair{Kind: k.Kind, Value: k.Value})
	}
	if err := it.Err(); err != nil {
		return err
	}
	for _, p := range seen {
		dk := policyKey{Kind: p.Kind, Value: p.Value}
		_ = m.Delete(&dk)
	}
	return nil
}

func severityToInt(s string) uint32 {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func emitDeny(ev denyEvent) {
	hookName := "unknown"
	switch ev.Hook {
	case policyKindExecPath:
		hookName = "bprm_check_security"
	case policyKindOpenPath:
		hookName = "file_open"
	case policyKindConnectAddr:
		hookName = "socket_connect"
	}
	match := trimZero(ev.Match[:])
	if ev.Hook == policyKindConnectAddr && len(match) >= 4 {
		match = []byte(net.IPv4(match[0], match[1], match[2], match[3]).String())
	}
	emit(runnerMessage{
		Kind:  "deny",
		Hook:  hookName,
		Pid:   ev.Pid,
		Ppid:  ev.Ppid,
		Comm:  string(trimZero(ev.Comm[:])),
		Match: string(match),
		Ts:    time.Now().UnixMilli(),
	})
}

// ----------------- helpers -----------------

func closeLinks(ls []link.Link) {
	for _, l := range ls {
		_ = l.Close()
	}
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func bytesReader(b []byte) *bytes.Reader {
	return bytes.NewReader(b)
}
