// auditctl 是审计链的运维命令行：
//
//	auditctl verify -data data [-from 2026-11-12T04:00] [-to 2026-11-12T05:00] [-json]
//	auditctl seal   -data data
//
// verify 退出码：0=完整；1=发现篡改；2=用法或 IO 错误。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"annot-audit/internal/audit"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	dataDir := fs.String("data", "data", "audit data directory")
	switch cmd {
	case "verify":
		from := fs.String("from", "", "window start, RFC3339 (inclusive); default=earliest")
		to := fs.String("to", "", "window end, RFC3339 (exclusive); default=latest")
		asJSON := fs.Bool("json", false, "emit machine-readable forensic report as JSON")
		_ = fs.Parse(os.Args[2:])
		code := runVerify(*dataDir, *from, *to, *asJSON)
		os.Exit(code)
	case "seal":
		_ = fs.Parse(os.Args[2:])
		w, err := audit.NewWriter(*dataDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "open writer: %v\n", err)
			os.Exit(2)
		}
		if err := w.Seal(); err != nil {
			_ = w.Close()
			fmt.Fprintf(os.Stderr, "seal: %v\n", err)
			os.Exit(2)
		}
		if err := w.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "close: %v\n", err)
			os.Exit(2)
		}
		fmt.Println("sealed OK")
	default:
		usage()
		os.Exit(2)
	}
}

func runVerify(dataDir, fromS, toS string, asJSON bool) int {
	opts := audit.VerifyOptions{}
	if fromS != "" {
		t, err := time.Parse(time.RFC3339, fromS)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bad -from: %v\n", err)
			return 2
		}
		opts.Start = t
	}
	if toS != "" {
		t, err := time.Parse(time.RFC3339, toS)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bad -to: %v\n", err)
			return 2
		}
		opts.End = t
	}
	rep, err := audit.Verify(dataDir, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify failed: %v\n", err)
		return 2
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	} else {
		printReport(rep)
	}
	if !rep.OK {
		return 1
	}
	return 0
}

func printReport(rep *audit.Report) {
	fmt.Println("================ AUDIT CHAIN FORENSIC REPORT ================")
	if rep.WindowStart != "" || rep.WindowEnd != "" {
		fmt.Printf("window: [%s, %s)\n", nz(rep.WindowStart), nz(rep.WindowEnd))
	}
	fmt.Printf("segments checked : %d\n", len(rep.Segments))
	fmt.Printf("events replayed  : %d\n", rep.ScannedEvents)
	fmt.Printf("elapsed          : %d ms\n", rep.DurationMS)
	for _, sr := range rep.Segments {
		status := "OK"
		if !sr.OK {
			status = fmt.Sprintf("FAIL (%d anomaly/anomalies)", len(sr.Anomalies))
		}
		fmt.Printf("  - %s [%s] seq=%d..%d count=%d merkle=%s %s\n",
			sr.Segment, sr.Kind, sr.StartSeq, sr.EndSeq, sr.Count,
			short(sr.MerkleRoot), status)
	}
	if rep.OK {
		fmt.Println("RESULT: INTEGRITY OK — hash chain, Merkle roots and metadata all match.")
		return
	}
	fmt.Println("RESULT: TAMPERED — integrity verification failed.")
	fmt.Println("---------------------------- anomalies ----------------------------")
	for _, a := range rep.Anomalies {
		loc := a.Segment
		if a.Line > 0 {
			loc += fmt.Sprintf(":%d", a.Line)
		}
		fmt.Printf("  [%s] %s seq=%d event=%s\n", a.Type, loc, a.Seq, nz(a.EventID))
		if a.Expected != "" || a.Actual != "" {
			fmt.Printf("      expected: %s\n      actual  : %s\n", nz(a.Expected), nz(a.Actual))
		}
		if a.Detail != "" {
			fmt.Printf("      detail  : %s\n", a.Detail)
		}
	}
	if rep.FirstBreach != nil {
		b := rep.FirstBreach
		fmt.Println("---------------------------- forensics ----------------------------")
		fmt.Printf("FIRST BREACH : segment=%s line=%d seq=%d event=%s type=%s\n",
			b.Segment, b.Line, b.Seq, nz(b.EventID), b.Type)
	}
	if rep.AffectedRange != nil {
		fmt.Printf("AFFECTED RANGE: seq %d..%d (records at/after the first breach are untrusted)\n",
			rep.AffectedRange.From, rep.AffectedRange.To)
	}
}

func nz(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func short(h string) string {
	if len(h) <= 16 {
		return nz(h)
	}
	return h[:16] + "…"
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  auditctl verify -data <dir> [-from RFC3339] [-to RFC3339] [-json]
  auditctl seal   -data <dir>`)
}
