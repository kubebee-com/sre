// sre-evaluate compares frozen offline outputs. It never constructs a provider.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/kubebee-com/sre/pkg/evaluation"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
func run(args []string, out, errout io.Writer) int {
	fs := flag.NewFlagSet("sre-evaluate", flag.ContinueOnError)
	fs.SetOutput(errout)
	dataset := fs.String("dataset", "testdata/evaluation/causal-v1.json", "frozen synthetic dataset JSON")
	baseline := fs.String("baseline", "abstain/v1", "abstain/v1, conservative/v1, or a recorded JSON file")
	candidate := fs.String("candidate", "conservative/v1", "abstain/v1, conservative/v1, or a recorded JSON file")
	budget := fs.Int("max-calls", 512, "total paired evaluation budget (maximum 512)")
	if e := fs.Parse(args); e != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(errout, "unexpected positional arguments")
		return 2
	}
	data, e := readBounded(*dataset)
	if e != nil {
		fmt.Fprintln(errout, "cannot read bounded dataset file")
		return 2
	}
	d, e := evaluation.LoadDataset(data)
	if e != nil {
		fmt.Fprintln(errout, "invalid dataset")
		return 2
	}
	load := func(name string) (evaluation.Runner, error) {
		if r, e := evaluation.Builtin(name); e == nil {
			return r, nil
		}
		raw, e := readBounded(name)
		if e != nil {
			return nil, e
		}
		return evaluation.LoadRecording(raw, d)
	}
	a, e := load(*baseline)
	if e != nil {
		fmt.Fprintln(errout, "invalid offline baseline")
		return 2
	}
	b, e := load(*candidate)
	if e != nil {
		fmt.Fprintln(errout, "invalid offline candidate")
		return 2
	}
	report, e := evaluation.Compare(context.Background(), d, a, b, *budget)
	if e != nil {
		fmt.Fprintln(errout, "evaluation rejected: invalid budget or inputs")
		return 2
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if enc.Encode(report) != nil {
		fmt.Fprintln(errout, "cannot write report")
		return 1
	}
	return 0
}
func readBounded(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > evaluation.MaxInputBytes {
		return nil, evaluation.ErrInvalid
	}
	b, e := io.ReadAll(io.LimitReader(f, evaluation.MaxInputBytes+1))
	if e != nil || len(b) > evaluation.MaxInputBytes {
		return nil, evaluation.ErrInvalid
	}
	return b, nil
}
