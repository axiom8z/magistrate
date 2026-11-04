package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// designExample is the example from DESIGN section 3, word for word.
const designExample = `{"mode":"value","bound_ids":true,"asks_per_session":5,"trusted_values":[],
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
	if p.Mode != ModeValue || !p.BoundIDs || p.AsksPerSession != 5 || p.TrustedValues == nil {
		t.Errorf("top-level fields were not kept: %+v", p)
	}
	s := p.Servers["crm"]
	if s.Command != "crm.exe" || len(s.Env) != 1 || s.Env[0] != "CRM_TOKEN" {
		t.Errorf("server = %+v", s)
	}
	if len(p.Tools) != 4 {
		t.Fatalf("tools were not kept: %d entries", len(p.Tools))
	}
	find := p.Tools["crm__find_notes"]
	if find.Effect != EffectRead || find.Output != OutputUntrusted || find.Binds == nil ||
		find.Binds.Path != "result[*].id" || find.Binds.Kind != "note" {
		t.Errorf("find_notes = %+v", find)
	}
	edit := p.Tools["crm__edit_note"]
	if edit.Store != "crm" || edit.Args["note_id"].Role != RoleControl || edit.Args["note_id"].Bind != "note" || edit.Args["text"].Role != RoleContent {
		t.Errorf("edit_note = %+v", edit)
	}
	if del := p.Tools["crm__delete_note"]; !del.Irreversible || del.Args["note_id"].Role != RoleControl {
		t.Errorf("delete_note = %+v", del)
	}
	pay := p.Tools["pay__transfer"]
	if amount := pay.Args["amount"]; amount.Role != RoleQuantity || amount.Max == nil || *amount.Max != 100 {
		t.Errorf("amount = %+v", amount)
	}
	if on := pay.Args["on"]; on.Role != RoleData || on.Type != TypeDate {
		t.Errorf("on = %+v", on)
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
		{"duplicate key inside tools", `{"mode":"pass",` + server + `,"tools":{"t":{"effect":"read","pin":"a","pin":"b"}}}`, "duplicate"},
		{"invalid UTF-8", "{\"mode\":\"pass\",\"servers\":{\"a\":{\"command\":\"\xff\"}}}", "UTF-8"},
		{"no mode", `{` + server + `}`, "mode"},
		{"mode of the wrong type", `{"mode":1,` + server + `}`, ""},
		{"unknown mode", `{"mode":"nonsense",` + server + `}`, "nonsense"},
		{"a mode in another case", `{"mode":"VALUE",` + server + `}`, "VALUE"},
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
		{"a non-ASCII trusted value, which could never match", `{"mode":"pass","trusted_values":["alıce"],` + server + `}`, "ASCII"},
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

// checkToolInvariants states the lint rules over again, so the fuzzer can catch a policy they let by.
func checkToolInvariants(t *testing.T, p *Policy, name string, tool Tool) {
	t.Helper()
	if tool.Effect != EffectRead && tool.Effect != EffectAct {
		t.Fatalf("tool %q has effect %q", name, tool.Effect)
	}
	if tool.Output == OutputTrusted && tool.Store != "" {
		for other, o := range p.Tools {
			if o.Effect == EffectAct && o.Store == tool.Store {
				t.Fatalf("tool %q is trusted while act %q writes its store", name, other)
			}
		}
	}
	for argName, a := range tool.Args {
		switch a.Role {
		case RoleControl, RoleContent, RoleCredential, RoleData:
		case RoleQuantity:
			if a.Max == nil || *a.Max < 0 {
				t.Fatalf("argument %q of %q is a quantity with no valid max", argName, name)
			}
		default:
			t.Fatalf("argument %q of %q has role %q", argName, name, a.Role)
		}
		if a.Bind != "" && (tool.Irreversible || a.Role != RoleControl) {
			t.Fatalf("argument %q of %q has a bind it may not have", argName, name)
		}
	}
}

// FuzzParse checks the loader never panics and never returns a policy that breaks its own rules.
func FuzzParse(f *testing.F) {
	f.Add([]byte(designExample))
	f.Add([]byte(`{"mode":"pass","servers":{"a":{"command":"x","args":["y"],"env":["Z"]}}}`))
	f.Add([]byte(`{"mode":"value","servers":{"a__b":{}}}`))
	f.Add([]byte(`[null,{"mode":1}]`))
	f.Add([]byte(`{"mode":"session","servers":{"a":{"command":"x"}},"tools":{"a__t":{"effect":"act","irreversible":true,"args":{"b":{"role":"control","bind":"k"}}}}}`))
	f.Add([]byte(`{"mode":"value","servers":{"a":{"command":"x"}},"tools":{"a__t":{"effect":"read","output":"trusted","store":"s","binds":{"path":"a[*].b","kind":"k"}},"a__u":{"effect":"act","store":"s"}}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Parse(data)
		if err != nil {
			return
		}
		if (p.Mode != ModePass && p.Mode != ModeSession && p.Mode != ModeValue) || len(p.Servers) == 0 {
			t.Fatalf("accepted %+v", p)
		}
		for name, s := range p.Servers {
			if strings.Contains(name, "__") || strings.HasSuffix(name, "_") || !ValidName(name) || s.Command == "" {
				t.Fatalf("accepted server %q: %+v", name, s)
			}
		}
		for name, tool := range p.Tools {
			checkToolInvariants(t, p, name, tool)
		}
	})
}
