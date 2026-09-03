// Structural guard: THIS SERVICE never writes the registration details an agent
// submits to a log line, and the local note of where it registered has no column
// that could hold them.
//
// "This service" is the load-bearing part, and the promise is worded that way in
// both places it is made. What a THIRD PARTY writes is a separate question: an
// Exchange's own refusal text is logged, bounded to 300 bytes, so an Exchange
// that quotes a submitted value back into its refusal puts a short value on an
// operator line. That is out of this guard's reach by design — it reads this
// repository's source, and the echoing peer is not in it — and it is pinned by
// TestRegister_BoundsAnExchangeThatEchoesThePayloadBack instead.
//
// The rule is a promise this repository makes to an operator in two places — the
// migration that creates the table and the identity service's runbook — and it is
// the kind of promise that breaks by addition rather than by edit. Nobody deletes
// it; somebody adds "fields" to a log line while debugging a refusal, or adds a
// payload column while making the hint list more useful, and the sentence stays
// there being false.
//
// TWO PLACES, not three. This header used to say the ramp_register tool
// description carried it too. That description says nothing about logging or
// storage, and it is the right place for that silence: it tells an AGENT what to
// send, where the schema is published and what submitting accepts, while what an
// operator's own service records is an operator's question answered in the
// runbook. Counting a document that never made the promise is how a guard comes
// to believe it covers more than it does.
//
// TWO HALVES, and neither is sufficient. This file is the structural half: it
// reads the diff's own source and the migration's own columns, so a violation
// fails in review rather than in production. Its limit is stated rather than
// hidden — it matches the payload by the names the two layers it reads bind it
// to, so a value copied into a third variable first is invisible to it. The
// behavioural half covers exactly that: an integration test registers with a
// distinctive value and asserts it appears in no captured log line, on the
// success path and the refusal path both.
//
// The behavioural half does not make the file set a detail. It drives the paths
// a test happens to exercise, and the local refusals inside the service are
// driven by tests that use no distinctive value — so a leak added to one of those
// branches is caught by the structural half or by nothing.
package guards

import (
	"go/ast"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// payloadPackages are the two packages the submitted payload is in scope in, and
// the guard reads every non-test file in both.
//
// The payload crosses two layers. The tool decodes it off the request and hands
// it on; the service holds it as a parameter, checks it against the protocol's
// bounds and the Exchange's schema, and packs it into a protobuf value. Both are
// somewhere a log line could be added while debugging a refusal, and the service
// is the layer with more reason to add one — it is where every local refusal is
// decided. A guard reading only the tool would pass a leak written one call
// deeper.
//
// PACKAGES rather than a list of files, because this promise breaks by addition.
// A named list is checked when a file is deleted — parsing fails loudly — and
// silent when one is added, which is the direction the header says the promise
// breaks in. The mcp package has already been split once; a second split that
// moved the register handler into a new file would have carried the payload out
// of a named list with nothing to say so.
var payloadPackages = []string{
	"src/identity/internal/mcp",
	"src/identity/internal/exchacct",
}

// payloadNames are what those two layers bind the submitted fields to: the tool
// input's own member, the service's parameter, and the protobuf value built from
// it. Each is the payload, so each is forbidden as a logging argument.
//
// Both spellings of the name are here on purpose. The tool binds the exported
// member and the service binds a lowercase parameter, so a set carrying one of
// them can only catch a leak in one of the files.
var payloadNames = map[string]bool{"Fields": true, "fields": true, "data": true}

// logMethods are the slog calls a leak would travel through. With and With Group
// are included because an attribute attached there reaches every later line from
// that logger, which is the version of this mistake that leaks the most.
var logMethods = map[string]bool{
	"InfoContext": true, "WarnContext": true, "ErrorContext": true, "DebugContext": true,
	"Info": true, "Warn": true, "Error": true, "Debug": true,
	"With": true, "WithGroup": true, "Log": true, "LogAttrs": true,
}

// TestSubmittedRegistrationFieldsAreNeverLogged fails when the register payload
// is passed to a logging call.
func TestSubmittedRegistrationFieldsAreNeverLogged(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	for _, path := range payloadPackageFiles(t, root) {
		f := parseGoFile(t, root, path)
		for _, name := range loggedPayloadNames(f) {
			t.Errorf("%s passes the submitted registration fields (%s) to a logging call — "+
				"they are the operator's business details, and this service neither logs nor "+
				"stores them. Log the exchange and the outcome instead.", path, name)
		}
	}
}

// payloadPackageFiles lists every non-test Go file in payloadPackages, as
// repo-root-relative paths.
//
// It fails when a package yields nothing. A glob that matches no file is not an
// error to filepath.Glob, so a package renamed or moved would otherwise turn
// this guard into a loop over an empty list that reports nothing and passes.
func payloadPackageFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	for _, pkg := range payloadPackages {
		matches, err := filepath.Glob(filepath.Join(root, pkg, "*.go"))
		if err != nil {
			t.Fatalf("glob %s: %v", pkg, err)
		}
		found := 0
		for _, abs := range matches {
			if strings.HasSuffix(abs, "_test.go") {
				continue
			}
			files = append(files, filepath.Join(pkg, filepath.Base(abs)))
			found++
		}
		if found == 0 {
			t.Fatalf("%s holds no non-test Go file — the guard is reading nowhere; "+
				"the package moved and payloadPackages was not updated with it", pkg)
		}
	}
	return files
}

// loggedPayloadNames returns the payload names f hands to a logging call.
//
// It matches an argument that IS one of the payload names, or a selector ending
// in one (in.Fields). A name reached through a third variable is not matched,
// which is the limit the file header names and the behavioural test covers.
func loggedPayloadNames(f *ast.File) []string {
	var found []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !logMethods[sel.Sel.Name] {
			return true
		}
		for _, arg := range call.Args {
			if name := payloadNameOf(arg); name != "" {
				found = append(found, name)
			}
		}
		return true
	})
	return found
}

// payloadNameOf reports the payload name an expression denotes, or "".
func payloadNameOf(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		if payloadNames[e.Name] {
			return e.Name
		}
	case *ast.SelectorExpr:
		if payloadNames[e.Sel.Name] {
			return e.Sel.Name
		}
	}
	return ""
}

// registrationNoteMigration creates the local note, and its column set IS the
// promise: nothing here can hold what was submitted because there is nowhere to
// put it.
const registrationNoteMigration = "src/identity/internal/db/migrations/000005_exchange_registration.up.sql"

// noteColumns are the three the table may have. Written out rather than derived,
// so ADDING one fails here and has to be argued for in the diff.
var noteColumns = []string{"subdomain", "exchange", "registered_at"}

// noteTableBody captures what is between the note table's parentheses, so a
// second table added to this migration cannot be read as part of the first.
var noteTableBody = regexp.MustCompile(`(?s)CREATE TABLE identity\.exchange_registration \((.*?)\n\);`)

// columnLine matches a column definition inside that body: a name at the start of
// a four-space-indented line, followed by anything at all.
//
// It knows NOTHING about types, and that is deliberate. It used to carry an
// alternation of the seven this table happens to use, so a column of any other
// type was invisible — "payload json" or "details varchar(2000)" left the guard
// reporting exactly the three columns it expected. The whole point of the check
// is that an extra column is a place to put the payload, and that property did
// not hold outside the list. Writing the alternation case-insensitively would
// only have moved the blind spot; the fix is to stop reading the type. The
// meta-test below found the second hole before this comment was written: the
// first replacement still missed an upper-cased type.
//
// Continuation lines are excluded structurally rather than by naming them.
// REFERENCES sits at eight spaces, so the four-space anchor rejects it, and
// CONSTRAINT is upper case where a column name is not. Neither depends on
// knowing which keywords this particular table uses.
var columnLine = regexp.MustCompile(`(?m)^ {4}([a-z_]+)[ \t]+\S`)

// TestRegistrationNoteHoldsNoPayloadColumns fails when the note's table grows a
// column beyond the three it is allowed.
//
// The migration is the one file that has to change for submitted data to be
// persisted, so watching its columns is watching the only door. Both directions
// fail: an extra column is a place to put the payload, and a missing one means
// the guard is reading a table that is no longer the one it describes.
func TestRegistrationNoteHoldsNoPayloadColumns(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), registrationNoteMigration))
	if err != nil {
		t.Fatalf("read %s: %v", registrationNoteMigration, err)
	}
	got := noteColumnsIn(t, string(raw))
	if strings.Join(got, ",") != strings.Join(noteColumns, ",") {
		t.Errorf("%s declares columns %v, want exactly %v — the note records THAT a "+
			"registration happened and nothing about what was submitted, so any further "+
			"column is somewhere the payload could land",
			registrationNoteMigration, got, noteColumns)
	}
}

// noteColumnsIn returns the column names the note table declares, in order.
//
// Split out from the test so the meta-tests below can drive the detector over a
// table they write themselves. Without that, nothing had ever shown this
// detector fail: the behavioural test cannot backstop it either, because the
// repository selects columns by name, so a written-but-never-selected column is
// invisible to it.
func noteColumnsIn(t *testing.T, migration string) []string {
	t.Helper()
	body := noteTableBody.FindStringSubmatch(migration)
	if body == nil {
		t.Fatalf("no CREATE TABLE identity.exchange_registration found — the guard is "+
			"reading a file that no longer creates the table it describes:\n%s", migration)
	}
	matches := columnLine.FindAllStringSubmatch(body[1], -1)
	got := make([]string, 0, len(matches))
	for _, m := range matches {
		got = append(got, m[1])
	}
	return got
}

// TestMeta_ColumnDetectorSeesAnyType is the detector's own negative, the pair the
// log detector below has had from the start and this one did not.
//
// Every case is a fourth column the table must not grow. The types are chosen to
// be outside the list the detector used to carry, because that list was the
// defect: a column it could not name did not exist as far as the guard was
// concerned.
func TestMeta_ColumnDetectorSeesAnyType(t *testing.T) {
	t.Parallel()
	for name, decl := range map[string]string{
		"json":                "    payload       json NOT NULL",
		"varchar with size":   "    details       varchar(2000) NOT NULL",
		"numeric":             "    amount        numeric(12,2) NOT NULL",
		"an array":            "    tags          text[] NOT NULL",
		"a domain type":       "    contact       email_address NOT NULL",
		"an upper-cased type": "    fields        JSONB NOT NULL",
		"no type at all":      "    fields        text",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := noteColumnsIn(t, noteTableWith(decl))
			want := strings.Fields(strings.TrimSpace(decl))[0]
			if !slices.Contains(got, want) {
				t.Fatalf("the detector did not see the column %q declared by %q; it read %v",
					want, decl, got)
			}
		})
	}
}

// TestMeta_ColumnDetectorPassesTheTableWeWant is the other half: a detector that
// flagged the three allowed columns, or read a constraint as one, would be
// removed rather than obeyed.
func TestMeta_ColumnDetectorPassesTheTableWeWant(t *testing.T) {
	t.Parallel()
	got := noteColumnsIn(t, noteTableWith(""))
	if strings.Join(got, ",") != strings.Join(noteColumns, ",") {
		t.Errorf("the detector read %v from the table it is meant to accept, want %v",
			got, noteColumns)
	}
}

// noteTableWith renders the note's CREATE TABLE with one extra line in the body,
// so a meta-test states only what it adds.
func noteTableWith(extra string) string {
	body := `CREATE TABLE identity.exchange_registration (
    subdomain     text        NOT NULL
        REFERENCES identity.developer_account (subdomain) ON DELETE CASCADE,
    exchange      text        NOT NULL,
    registered_at timestamptz NOT NULL,`
	if extra != "" {
		body += "\n" + extra + ","
	}
	return body + `
    CONSTRAINT exchange_registration_pkey PRIMARY KEY (subdomain, exchange)
);
`
}

// cascadeClause is the retention rule the migration states in prose: the notes
// go when the developer account they were signed under goes.
//
// Read from the file rather than exercised against a live database, because the
// behaviour has no production surface to drive it through — there is no
// agent-deletion flow yet, and a test that issued its own DELETE would be
// reaching past every layer to arrange the state it then asserts on. What CAN be
// pinned without that is the clause itself, and the clause is the whole
// mechanism: the reference alone is satisfied by ON DELETE RESTRICT, which
// inverts the promise, blocking a developer's deletion instead of carrying the
// notes along with it.
var cascadeClause = regexp.MustCompile(
	`REFERENCES\s+identity\.developer_account\s*\(\s*subdomain\s*\)\s+ON\s+DELETE\s+CASCADE`)

// TestRegistrationNoteGoesWithTheAgent fails when the note's lifetime stops
// being structural.
func TestRegistrationNoteGoesWithTheAgent(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), registrationNoteMigration))
	if err != nil {
		t.Fatalf("read %s: %v", registrationNoteMigration, err)
	}
	if !cascadeClause.MatchString(string(raw)) {
		t.Errorf("%s does not key the note's lifetime to the developer account with "+
			"ON DELETE CASCADE — without that clause the migration's retention paragraph "+
			"is a promise the schema does not keep",
			registrationNoteMigration)
	}
}

// TestMeta_PayloadLogDetectorFires is the positive meta-test: each shape the
// detector claims to catch must be caught.
func TestMeta_PayloadLogDetectorFires(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"the tool input's member":   `log.InfoContext(ctx, "registered", "fields", in.Fields)`,
		"the service's parameter":   `log.WarnContext(ctx, "refused", "fields", fields)`,
		"the protobuf value":        `log.InfoContext(ctx, "registered", "payload", data)`,
		"attached to the logger":    `log.With("fields", in.Fields).Info("registered")`,
		"a plain slog call":         `log.Warn("refused", "fields", in.Fields)`,
		"the parameter on a logger": `log.With("fields", fields).Info("registered")`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := parseSnippet(t, "package x\n\nfunc leak() { "+body+" }\n")
			if got := loggedPayloadNames(f); len(got) == 0 {
				t.Fatalf("detector passed a leak: %s", body)
			}
		})
	}
}

// TestMeta_PayloadLogDetectorPassesTheLinesWeWant is the negative meta-test. The
// register path logs the Exchange and the outcome on purpose, and a guard that
// objected to those would be removed rather than obeyed.
func TestMeta_PayloadLogDetectorPassesTheLinesWeWant(t *testing.T) {
	t.Parallel()
	clean := `log.InfoContext(ctx, "identity.mcp.register", "subdomain", who.subdomain, ` +
		`"exchange", in.Exchange, "active", resp.GetActive())`
	f := parseSnippet(t, "package x\n\nfunc fine() { "+clean+" }\n")
	if got := loggedPayloadNames(f); len(got) != 0 {
		t.Fatalf("detector objected to %v on a line carrying only the routing and the outcome", got)
	}
}

// TestMeta_PayloadLogDetectorIgnoresNonLoggingCalls pins the other half of the
// negative: the payload is PASSED AROUND on this path — to the bounds check, to
// the validator, onto the request — and none of that is a leak.
func TestMeta_PayloadLogDetectorIgnoresNonLoggingCalls(t *testing.T) {
	t.Parallel()
	used := `helpers.CheckRegistrationDataStruct(in.Data); schema.Validate(in.Fields); send(data)`
	f := parseSnippet(t, "package x\n\nfunc uses() { "+used+" }\n")
	if got := loggedPayloadNames(f); len(got) != 0 {
		t.Fatalf("detector objected to %v where the payload is used rather than logged", got)
	}
}
