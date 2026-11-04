// Package archtest holds rules about the source tree as a whole. They run as ordinary tests, so that
// breaking one fails the build the same way a bug does.
package archtest

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// maxLines is the ceiling from DESIGN section 2. Comments and blank lines count: the point is how
// much there is to read and explain, and this way nobody can fit under it by writing fewer comments.
const maxLines = 3500

const repoRoot = "../.."

// goFiles calls visit for every non-test Go file under cmd and internal.
func goFiles(t *testing.T, visit func(path string, data []byte)) {
	t.Helper()
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(repoRoot, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			visit(path, data)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestGoModHasNoRequire(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.Lines(string(data)) {
		if strings.HasPrefix(strings.TrimSpace(line), "require") {
			t.Errorf("go.mod requires a module, and this project is standard library only: %s", line)
		}
	}
	if !bytes.Contains(data, []byte("module github.com/axiom8z/sayswho")) {
		t.Errorf("this does not look like the right go.mod: %s", data)
	}
}

func TestNonTestLinesStayUnderTheCeiling(t *testing.T) {
	total, files := 0, 0
	goFiles(t, func(_ string, data []byte) {
		total += bytes.Count(data, []byte("\n"))
		files++
	})
	if files == 0 {
		t.Fatal("found no Go files, so this test is looking in the wrong place")
	}
	t.Logf("%d non-test lines in %d files", total, files)
	if total >= maxLines {
		t.Errorf("%d non-test lines under cmd and internal; the ceiling is %d", total, maxLines)
	}
}

// Stdout carries the protocol, so stray output there breaks the client. Only the command itself may
// name it, and it hands it straight to the code that writes one message per line.
func TestOnlyTheCommandTouchesStdout(t *testing.T) {
	banned := []string{"os.Stdout", "fmt.Print(", "fmt.Printf(", "fmt.Println(", "println("}
	goFiles(t, func(path string, data []byte) {
		if strings.HasPrefix(filepath.ToSlash(path), repoRoot+"/cmd/") {
			return
		}
		for _, word := range banned {
			if bytes.Contains(data, []byte(word)) {
				t.Errorf("%s uses %s", path, word)
			}
		}
	})
}
