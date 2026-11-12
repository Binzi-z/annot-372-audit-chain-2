// verify 命令对审计哈希链做时间窗口完整性验证。
//
//	go run ./cmd/verify -data data
//	go run ./cmd/verify -data data -from 2026-11-12T00:00:00Z -to 2026-11-12T23:59:59Z
//
// 退出码：0 = 完整；2 = 检测到篡改（取证报告写入 stdout 与 -out 文件）；1 = 其他错误。
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
	dataDir := flag.String("data", "data", "audit data directory")
	fromStr := flag.String("from", "", "window start, RFC3339 (inclusive); empty = beginning")
	toStr := flag.String("to", "", "window end, RFC3339 (inclusive); empty = now")
	out := flag.String("out", "", "write forensic JSON report to this file as well")
	flag.Parse()

	opts := audit.VerifyOptions{}
	if *fromStr != "" {
		t, err := time.Parse(time.RFC3339, *fromStr)
		fatalf("invalid -from: %v", err)
		opts.From = t
	}
	if *toStr != "" {
		t, err := time.Parse(time.RFC3339, *toStr)
		fatalf("invalid -to: %v", err)
		opts.To = t
	} else {
		opts.To = time.Now().UTC()
	}

	rep, err := audit.Verify(*dataDir, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify failed: %v\n", err)
		os.Exit(1)
	}

	buf, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal report: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(buf))
	if *out != "" {
		if err := os.WriteFile(*out, append(buf, '\n'), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write report: %v\n", err)
			os.Exit(1)
		}
	}

	if !rep.OK {
		fmt.Fprintln(os.Stderr, "INTEGRITY CHECK FAILED")
		if rep.AffectedRange != nil {
			ar := rep.AffectedRange
			fmt.Fprintf(os.Stderr, "first tampered record: segment=%s line=%d seq=%d\n",
				ar.FirstSegment, ar.FirstLine, ar.FirstSeq)
			fmt.Fprintf(os.Stderr, "untrusted range: seq %d .. %d\n", ar.FirstSeq, ar.LastSeq)
		}
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "OK: integrity verified")
}

func fatalf(format string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, format+"\n", err)
		os.Exit(1)
	}
}
