// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Command pdf-builder is the AGPL entry point that renders a usulnet
// recon Report as a PDF document. It reads a JSON Report on stdin,
// invokes the AGPL renderer at internal/services/recon/report/pdf.go,
// and writes the PDF bytes to stdout.
//
// This is the only AGPL surface the cloud SaaS reaches into for PDF
// generation. The cloud-side Worker
// (cloud-private/pdf-builder/) assembles the JSON, hands it to this
// binary running on the sandbox cluster, and uploads the resulting PDF
// to R2. Architecture rationale lives in
// `dev/0526/cloud/adr/07-pdf-builder.md`.
//
// CLI contract:
//
//	pdf-builder                  # JSON on stdin, PDF on stdout
//	pdf-builder -input file.json # JSON from file, PDF on stdout
//	pdf-builder -h | -help       # usage
//
// The "-input" flag exists for ergonomic ad-hoc renders from a
// developer shell (you cannot easily paste multi-KiB JSON into a
// terminal heredoc). Production runs through stdin so the sandbox
// container's HTTP wrapper can stream the request body directly.
//
// The JSON shape matches `internal/services/recon/report.Report`
// exactly — same field names, same type signatures. uuid.UUID fields
// accept the canonical 36-char hex-with-dashes form; the cloud Worker
// derives a deterministic UUID from its short id strings before
// invoking this binary.
//
// Exit codes:
//
//	0 — PDF written successfully.
//	1 — input is not valid JSON / mandatory fields missing.
//	2 — PDF generation failed (e.g. ill-shaped report).
//	3 — I/O error reading input or writing stdout.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/fr4nsys/usulnet/internal/services/recon/report"
)

// main is the thin CLI shell. The actual work happens in `run` so the
// _test file can drive the same code path with in-memory buffers.
func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "pdf-builder: %v\n", err)
		os.Exit(exitCodeFor(err))
	}
}

// runError tags an error with the exit code we should surface. The
// AGPL package returns plain `error` values, so we wrap them here when
// classification matters.
type runError struct {
	code int
	err  error
}

func (e *runError) Error() string { return e.err.Error() }
func (e *runError) Unwrap() error { return e.err }

func exitCodeFor(err error) int {
	if err == nil {
		return 0
	}
	if re, ok := err.(*runError); ok && re.code != 0 {
		return re.code
	}
	return 1
}

func run(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	fs := flag.NewFlagSet("pdf-builder", flag.ContinueOnError)
	fs.SetOutput(stderr)
	inputPath := fs.String("input", "", "path to a Report JSON file (default: read stdin)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usulnet pdf-builder — render a recon Report JSON to PDF on stdout")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Usage:")
		fmt.Fprintln(stderr, "  pdf-builder                  # JSON on stdin, PDF on stdout")
		fmt.Fprintln(stderr, "  pdf-builder -input report.json")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Flags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		// flag.Parse already wrote its own error message to stderr.
		return &runError{code: 1, err: err}
	}

	var reader io.Reader = stdin
	if *inputPath != "" {
		f, err := os.Open(*inputPath)
		if err != nil {
			return &runError{code: 3, err: fmt.Errorf("open %q: %w", *inputPath, err)}
		}
		defer func() { _ = f.Close() }()
		reader = f
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		return &runError{code: 3, err: fmt.Errorf("read input: %w", err)}
	}
	if len(body) == 0 {
		return &runError{code: 1, err: fmt.Errorf("no input received")}
	}

	var r report.Report
	dec := json.NewDecoder(bytesReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		// We tolerate unknown fields by retrying with the strict mode
		// off — the cloud-side Worker MAY add extra metadata (debug
		// fields, etc.) that does not exist on the AGPL struct. Strict
		// mode catches typos in development; the retry keeps production
		// resilient to future schema growth.
		var r2 report.Report
		if err2 := json.Unmarshal(body, &r2); err2 != nil {
			return &runError{code: 1, err: fmt.Errorf("decode JSON: %w", err2)}
		}
		r = r2
	}

	if err := report.GeneratePDF(&r, stdout); err != nil {
		return &runError{code: 2, err: fmt.Errorf("render PDF: %w", err)}
	}
	return nil
}

// bytesReader returns an io.Reader over the given byte slice. We do
// not depend on `bytes` directly so the import section stays small;
// this is the same shape `bytes.NewReader` produces.
func bytesReader(b []byte) io.Reader {
	return &sliceReader{b: b}
}

type sliceReader struct {
	b []byte
	i int
}

func (r *sliceReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}
