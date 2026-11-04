package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// designExample is the example from DESIGN section 3, with the mode this milestone can run.
const designExample = `{"mode":"pass","bound_ids":true,"asks_per_session":5,"trusted_values":[],
 "servers":{"crm":{"command":"crm.exe","env":["CRM_TOKEN"]}},
 "tools":{
  "crm__find_notes":{"effect":"read","output":"untrusted","pin":"sha256:...",
    "binds":{"path":"result[*].id","kind":"note"}},
  "crm__edit_note":{"effect":"act","store":"crm","pin":"sha256:...",
    "args":{"note_id":{"role":"control","bind":"note"},"text":"content"}},
  "crm__delete_note":{"effect":"act","irreversible":true,"store":"crm","pin":"sha256:...",
    "args":{"note_id":"control"}},
  "pay__transfer":{"effect":"act","pin":"sha256:...",
    "args":{"to":"control","amount":{"role":"quantity","max":100},"memo":"content",
            "on":{"role":"data","type":"date"}}}}}`

func TestParseDesignExample(t *testing.T) {
	p, err := Parse([]byte(designExample))
	if err != nil {
		t.Fatal(err)
	}
	if !p.BoundIDs || p.AsksPerSession != 5 || p.TrustedValues == nil {
		t.Errorf("fields for later milestones were not kept: %+v", p)
	}
	s := p.Servers["crm"]
	if s.Command != "crm.exe" || len(s.Env) != 1 || s.Env[0] != "CRM_TOKEN" {
		t.Errorf("server = %+v", s)
	}
	if len(p.Tools) != 4 || !strings.Contains(string(p.Tools["pay__transfer"]), `"max":100`) {
		t.Errorf("tools were not kept: %d entries", len(p.Tools))
	}
}

func TestParseMinimal(t *testing.T) {
	p, err := Parse([]byte(`{"mode":"pass","servers":{"a":{"command":"x","args":["--flag"]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Servers["a"].Args; len(got) != 1 || got[0] != "--flag" {
		t.Errorf("args = %v", got)
	}
}

func TestParseRejects(t *testing.T) {
	server := `"servers":{"a":{"command":"x"}}`
	tests := []struct {
		name, policy, wantErr string
	}{
		{"not JSON", `nope`, ""},
		{"empty file", ``, ""},
		{"a list", `[]`, ""},
		{"a byte order mark, as some Windows editors add", "\xef\xbb\xbf{\"mode\":\"pass\",\"servers\":{\"a\":{\"command\":\"x\"}}}", ""},
		{"null", `null`, "mode"},
		{"trailing data", `{"mode":"pass",` + server + `} {}`, ""},
		{"unknown top-level key", `{"mode":"pass","modee":"value",` + server + `}`, "modee"},
		{"unknown server key", `{"mode":"pass","servers":{"a":{"command":"x","cwd":"/"}}}`, "cwd"},
		{"duplicate top-level key", `{"mode":"pass","mode":"pass",` + server + `}`, "duplicate"},
		{"duplicate server", `{"mode":"pass","servers":{"a":{"command":"x"},"a":{"command":"y"}}}`, "duplicate"},
		{"duplicate key inside tools", `{"mode":"pass",` + server + `,"tools":{"t":{"pin":"a","pin":"b"}}}`, "duplicate"},
		{"invalid UTF-8", "{\"mode\":\"pass\",\"servers\":{\"a\":{\"command\":\"\xff\"}}}", "UTF-8"},
		{"no mode", `{` + server + `}`, "mode"},
		{"mode of the wrong type", `{"mode":1,` + server + `}`, ""},
		{"unknown mode", `{"mode":"nonsense",` + server + `}`, "nonsense"},
		{"a mode from the design that is not built yet", `{"mode":"value",` + server + `}`, "value"},
		{"session mode is not built yet", `{"mode":"session",` + server + `}`, "session"},
		{"no servers key", `{"mode":"pass"}`, "no servers"},
		{"empty servers", `{"mode":"pass","servers":{}}`, "no servers"},
		{"null server", `{"mode":"pass","servers":{"a":null}}`, "no command"},
		{"no command", `{"mode":"pass","servers":{"a":{}}}`, "no command"},
		{"empty command", `{"mode":"pass","servers":{"a":{"command":""}}}`, "no command"},
		{"command of the wrong type", `{"mode":"pass","servers":{"a":{"command":["x"]}}}`, ""},
		{"args of the wrong type", `{"mode":"pass","servers":{"a":{"command":"x","args":"--flag"}}}`, ""},
		{"env of the wrong type", `{"mode":"pass","servers":{"a":{"command":"x","env":{"A":"1"}}}}`, ""},
		{"env holding a value", `{"mode":"pass","servers":{"a":{"command":"x","env":["TOKEN=abc"]}}}`, "variable"},
		{"empty env name", `{"mode":"pass","servers":{"a":{"command":"x","env":[""]}}}`, "variable"},
		{"server name with the separator", `{"mode":"pass","servers":{"a__b":{"command":"x"}}}`, "bad name"},
		{"server name that forms the separator at the join", `{"mode":"pass","servers":{"a_":{"command":"x"}}}`, "bad name"},
		{"server name with a space", `{"mode":"pass","servers":{"a b":{"command":"x"}}}`, "bad name"},
		{"empty server name", `{"mode":"pass","servers":{"":{"command":"x"}}}`, "bad name"},
		{"server name over the length bound", `{"mode":"pass","servers":{"` + strings.Repeat("a", 129) + `":{"command":"x"}}}`, "bad name"},
		{"negative asks", `{"mode":"pass","asks_per_session":-1,` + server + `}`, "asks_per_session"},
		{"bound_ids of the wrong type", `{"mode":"pass","bound_ids":"yes",` + server + `}`, ""},
		{"trusted_values of the wrong type", `{"mode":"pass","trusted_values":"x",` + server + `}`, ""},
		{"tools of the wrong type", `{"mode":"pass","tools":[],` + server + `}`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.policy))
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not mention %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"getUser", true},
		{"DATA_EXPORT_v2", true},
		{"admin.tools.list", true},
		{"a-b", true},
		{"a__b", true},
		{strings.Repeat("a", 128), true},
		{strings.Repeat("a", 129), false},
		{"", false},
		{"has space", false},
		{"comma,", false},
		{"new\nline", false},
		{"é", false},
		{"a/b", false},
	}
	for _, tt := range tests {
		if got := ValidName(tt.name); got != tt.want {
			t.Errorf("ValidName(%q) = %v", tt.name, got)
		}
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(`{"mode":"pass","servers":{"a":{"command":"x"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("loaded a file that does not exist")
	}
}

// FuzzParse checks the loader never panics and never returns a policy that breaks its own rules.
func FuzzParse(f *testing.F) {
	f.Add([]byte(designExample))
	f.Add([]byte(`{"mode":"pass","servers":{"a":{"command":"x","args":["y"],"env":["Z"]}}}`))
	f.Add([]byte(`{"mode":"value","servers":{"a__b":{}}}`))
	f.Add([]byte(`[null,{"mode":1}]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Parse(data)
		if err != nil {
			return
		}
		if p.Mode != "pass" || len(p.Servers) == 0 {
			t.Fatalf("accepted %+v", p)
		}
		for name, s := range p.Servers {
			if strings.Contains(name, "__") || strings.HasSuffix(name, "_") || !ValidName(name) || s.Command == "" {
				t.Fatalf("accepted server %q: %+v", name, s)
			}
		}
	})
}
