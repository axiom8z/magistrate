// Command secretscore runs the secret scanner over one scoring set from bench/secrets and prints what
// it did to each case: the case ID, blocked or not, and the rule. It never prints a value, not even in
// an error, so its output is safe to keep.
//
//	secretscore -hash        prints the rule-table hash
//	secretscore <set.jsonl>  prints the hash as a JSON line, then one JSON line per case
package main

import (
	"bufio"
	"bytes"
	"encoding/json/v2"
	"fmt"
	"io"
	"os"

	"github.com/axiom8z/magistrate/internal/secrets"
)

// testCase is one set line. Each call is scanned on its own, as the gateway would see it.
type testCase struct {
	ID    string     `json:"id"`
	Calls [][]string `json:"calls"`
}

type result struct {
	ID      string `json:"id"`
	Blocked bool   `json:"blocked"`
	Rule    string `json:"rule"`
}

func main() {
	if len(os.Args) != 2 {
		fail("usage: secretscore -hash | secretscore <set.jsonl>")
	}
	if os.Args[1] == "-hash" {
		fmt.Println(secrets.RulesHash())
		return
	}
	file, err := os.Open(os.Args[1])
	if err != nil {
		fail("cannot open the set")
	}
	defer file.Close()

	in := bufio.NewReader(file)
	out := bufio.NewWriter(os.Stdout)
	fmt.Fprintf(out, "{\"rules_hash\":%q}\n", secrets.RulesHash())
	for number := 1; ; number++ {
		line, readErr := in.ReadBytes('\n')
		if readErr != nil && readErr != io.EOF {
			fail(fmt.Sprintf("cannot read line %d", number))
		}
		if len(bytes.TrimSpace(line)) > 0 {
			score(line, number, out)
		}
		if readErr == io.EOF {
			break
		}
	}
	if err := out.Flush(); err != nil {
		fail("cannot write the results")
	}
}

// score scans one case. A failed parse names the line and nothing else, because a parse error can
// quote the text it stopped on.
func score(line []byte, number int, out io.Writer) {
	var c testCase
	if err := json.Unmarshal(line, &c); err != nil || c.ID == "" || len(c.Calls) == 0 {
		fail(fmt.Sprintf("line %d is not a case", number))
	}
	res := result{ID: c.ID}
	for _, leaves := range c.Calls {
		if rule := secrets.ScanCall(leaves); rule != "" {
			res.Blocked, res.Rule = true, rule
			break
		}
	}
	encoded, err := json.Marshal(res)
	if err != nil {
		fail(fmt.Sprintf("cannot encode the result of line %d", number))
	}
	fmt.Fprintf(out, "%s\n", encoded)
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, "secretscore: "+message)
	os.Exit(1)
}
