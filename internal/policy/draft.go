package policy

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"strings"

	"github.com/axiom8z/sayswho/internal/upstream"
)

// draftCeiling is the quantity ceiling the design's forecasts assume. A reviewer sets the real one.
var draftCeiling = 100.0

// lexicon is the one table init labels arguments from. It looks up the whole name and then its last
// "_" word, so start_time finds "time" and note_id finds "id". Any string not in here is control.
var lexicon = map[string]Arg{
	"body":        {Role: RoleContent},
	"content":     {Role: RoleContent},
	"description": {Role: RoleContent},
	"location":    {Role: RoleContent},
	"message":     {Role: RoleContent},
	"note":        {Role: RoleContent},
	"subject":     {Role: RoleContent},
	"summary":     {Role: RoleContent},
	"text":        {Role: RoleContent},
	"title":       {Role: RoleContent},
	"api_key":     {Role: RoleCredential},
	"apikey":      {Role: RoleCredential},
	"password":    {Role: RoleCredential},
	"pin":         {Role: RoleCredential},
	"secret":      {Role: RoleCredential},
	"token":       {Role: RoleCredential},
	"amount":      {Role: RoleQuantity, Max: &draftCeiling},
	"date":        {Role: RoleData, Type: TypeDate},
	"day":         {Role: RoleData, Type: TypeDate},
	"time":        {Role: RoleData, Type: TypeDate},
	"id":          {Role: RoleControl}, // here so that a numeric ID stays control, not data
}

// Verbs init reads from a tool name's "_" words. A read verb must come first, as in get_user.
var (
	readVerbs         = map[string]bool{"check": true, "find": true, "get": true, "list": true, "read": true, "search": true}
	irreversibleVerbs = map[string]bool{"cancel": true, "delete": true, "remove": true, "share": true}
	// reachWords name arguments that can reach beyond the tool's own service. DESIGN section 3: such
	// a tool acts, whatever its name.
	reachWords = map[string]bool{"endpoint": true, "host": true, "link": true, "uri": true, "url": true, "webhook": true}
)

// Draft labels one tool for init. A draft is for a person to correct, so every guess it can't make is
// the strict one: acts unless plainly a read, untrusted output, and a store named after the server,
// so that marking a tool trusted fails lint until someone has thought about who writes it. Sensitive
// is the exception. A schema doesn't say what a tool returns, so that one is left to the reviewer.
func Draft(server string, t upstream.Tool) (Tool, error) {
	pin, err := Pin(t)
	if err != nil {
		return Tool{}, err
	}
	draft := Tool{Effect: EffectAct, Output: OutputUntrusted, Store: server, Pin: pin, Args: map[string]Arg{}}
	reaches := false
	for name, schemaType := range schemaTypes(t.InputSchema) {
		draft.Args[name] = draftArg(name, schemaType)
		reaches = reaches || reachWords[lastWord(name)]
	}
	words := strings.Split(strings.ToLower(t.Name), "_")
	raised, destructive := readHints(t.Annotations)
	if readVerbs[words[0]] && !reaches && !raised {
		draft.Effect = EffectRead
	}
	draft.Irreversible = destructive
	for _, word := range words {
		draft.Irreversible = draft.Irreversible || irreversibleVerbs[word]
	}
	return draft, nil
}

func draftArg(name, schemaType string) Arg {
	entry, listed := lexicon[strings.ToLower(name)]
	if !listed {
		entry, listed = lexicon[lastWord(name)]
	}
	numeric := schemaType == "number" || schemaType == "integer"
	switch {
	case listed && !(numeric && entry.Type == TypeDate):
		return entry
	case numeric:
		return Arg{Role: RoleData, Type: TypeNumber}
	case schemaType == "boolean":
		return Arg{Role: RoleData, Type: TypeBoolean}
	}
	return Arg{Role: RoleControl}
}

func lastWord(name string) string {
	name = strings.ToLower(strings.Trim(name, "_"))
	return name[strings.LastIndexByte(name, '_')+1:]
}

// schemaTypes maps each declared argument to its JSON Schema type. A type that is not one plain
// string comes back empty, which draftArg treats as a string, and so as control.
func schemaTypes(schema jsontext.Value) map[string]string {
	var parsed struct {
		Properties map[string]jsontext.Value `json:"properties"`
	}
	json.Unmarshal(schema, &parsed) // on failure there are no properties, and every argument is unknown
	types := map[string]string{}
	for name, property := range parsed.Properties {
		var p struct {
			Type string `json:"type"`
		}
		json.Unmarshal(property, &p)
		types[name] = p.Type
	}
	return types
}

// readHints reads a server's annotations, which are untrusted hints. So they may only raise risk: a
// read-named tool can become an act, but readOnlyHint on send_mail changes nothing. A hint of the
// wrong type stops the decoding, and all that can cost is a raise a hostile server didn't want.
func readHints(annotations jsontext.Value) (raised, destructive bool) {
	var hints struct {
		ReadOnly    *bool `json:"readOnlyHint"`
		Destructive *bool `json:"destructiveHint"`
		OpenWorld   *bool `json:"openWorldHint"`
	}
	json.Unmarshal(annotations, &hints)
	destructive = hints.Destructive != nil && *hints.Destructive
	openWorld := hints.OpenWorld != nil && *hints.OpenWorld
	notReadOnly := hints.ReadOnly != nil && !*hints.ReadOnly
	return destructive || openWorld || notReadOnly, destructive
}
