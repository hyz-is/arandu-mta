package unit_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func packageRoot(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the test file")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// productionFiles parses every non-test Go file of the module: the root package
// and mtatest, the test doubles it ships.
func productionFiles(t testing.TB) map[string]*ast.File {
	t.Helper()
	root := packageRoot(t)
	fset := token.NewFileSet()
	out := map[string]*ast.File{}
	for _, dir := range []string{".", "mtatest"} {
		entries, err := os.ReadDir(filepath.Join(root, dir))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, filepath.Join(root, dir, name), nil, parser.ParseComments)
			if err != nil {
				t.Fatal(err)
			}
			out[filepath.Join(dir, name)] = f
		}
	}
	if len(out) == 0 {
		t.Fatal("no production files found")
	}
	return out
}

// TestTheModuleNeedsNothingButTheStandardLibraryAndX holds the rule of the
// hyz-is modules that wrap no outside technology: golang.org/x/* and nothing
// else, in the imports and in go.mod.
func TestTheModuleNeedsNothingButTheStandardLibraryAndX(t *testing.T) {
	const self = "github.com/hyz-is/arandu-mta"
	for name, f := range productionFiles(t) {
		for _, imp := range f.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			first, _, _ := strings.Cut(path, "/")
			switch {
			case !strings.Contains(first, "."): // the standard library
			case strings.HasPrefix(path, "golang.org/x/"):
			case path == self || strings.HasPrefix(path, self+"/"):
			default:
				t.Errorf("%s imports %s; only the standard library and golang.org/x/* are allowed", name, path)
			}
		}
	}
	goMod, err := os.ReadFile(filepath.Join(packageRoot(t), "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range regexp.MustCompile(`(?m)^(?:require\s+|\t)(\S+)\s+v\S+(\s*//\s*indirect)?\s*$`).FindAllStringSubmatch(string(goMod), -1) {
		if !strings.HasPrefix(m[1], "golang.org/x/") {
			t.Errorf("go.mod requires %s", m[1])
		}
	}
	if regexp.MustCompile(`(?m)^replace\b`).Match(goMod) {
		t.Error("go.mod has a replace directive")
	}
}

// TestTheModuleIsALibrary refuses the hidden wiring Arandu forbids: no init,
// no framework, no global registry.
func TestTheModuleIsALibrary(t *testing.T) {
	for name, f := range productionFiles(t) {
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == "init" {
				t.Errorf("%s declares init(); wiring is explicit", name)
			}
		}
		for _, imp := range f.Imports {
			if strings.Contains(imp.Path.Value, "arandu-io") {
				t.Errorf("%s imports the framework", name)
			}
		}
	}
	root := packageRoot(t)
	for _, forbidden := range []string{"go.work", "CLAUDE.md", "app", "routes", "bootstrap", "resources"} {
		if _, err := os.Lstat(filepath.Join(root, forbidden)); err == nil {
			t.Errorf("%s must not exist in a library module", forbidden)
		}
	}
}

// TestTheManifestIsWhatTheCodeDoes compares arandu.mod.toml with what the code
// imports and calls. aru doctor never opens an installed package, so this is
// the only place the declaration is checked.
func TestTheManifestIsWhatTheCodeDoes(t *testing.T) {
	manifest, err := os.ReadFile(filepath.Join(packageRoot(t), "arandu.mod.toml"))
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^(network|filesystem|exec|migrations)\s*=\s*(true|false)\s*$`).FindAllStringSubmatch(string(manifest), -1) {
		declared[m[1]] = m[2] == "true"
	}
	if len(declared) != 4 {
		t.Fatalf("manifest declares %v; all four permissions must be present", declared)
	}
	if !regexp.MustCompile(`(?m)^name = "hyz-is/mta"$`).Match(manifest) {
		t.Error("manifest name must be hyz-is/mta")
	}

	fsCalls := map[string]bool{"OpenFile": true, "ReadFile": true, "WriteFile": true, "Open": true, "Create": true, "Remove": true,
		"Rename": true, "MkdirAll": true, "Mkdir": true, "ReadDir": true, "Stat": true, "Lstat": true}
	netCalls := map[string]bool{"Dial": true, "DialContext": true, "Listen": true, "ListenPacket": true}
	var usesNet, usesFS, usesExec, usesDB bool
	for name, f := range productionFiles(t) {
		if strings.HasPrefix(name, "mtatest") {
			continue // the test doubles are not linked into an application's binary
		}
		for _, imp := range f.Imports {
			switch p, _ := strconv.Unquote(imp.Path.Value); p {
			case "os/exec":
				usesExec = true
			case "database/sql":
				usesDB = true
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok {
				switch {
				case id.Name == "os" && fsCalls[sel.Sel.Name]:
					usesFS = true
				case id.Name == "net" && netCalls[sel.Sel.Name]:
					usesNet = true
				}
			}
			if sel.Sel.Name == "DialContext" {
				usesNet = true
			}
			return true
		})
	}
	for _, c := range []struct {
		name         string
		declared, in bool
	}{
		{"network", declared["network"], usesNet},
		{"filesystem", declared["filesystem"], usesFS},
		{"exec", declared["exec"], usesExec},
		{"migrations", declared["migrations"], usesDB},
	} {
		if c.declared != c.in {
			t.Errorf("manifest declares %s = %v, and the code's use of it is %v", c.name, c.declared, c.in)
		}
	}
}

// TestEveryExportedSymbolHasADocComment is the documentation rule of the family.
func TestEveryExportedSymbolHasADocComment(t *testing.T) {
	for name, f := range productionFiles(t) {
		if strings.HasSuffix(name, "doc.go") {
			continue
		}
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Name.IsExported() && d.Doc == nil && (d.Recv == nil || exportedRecv(d.Recv)) {
					t.Errorf("%s: func %s has no doc comment", name, d.Name.Name)
				}
			case *ast.GenDecl:
				for _, s := range d.Specs {
					switch s := s.(type) {
					case *ast.TypeSpec:
						if s.Name.IsExported() && d.Doc == nil && s.Doc == nil {
							t.Errorf("%s: type %s has no doc comment", name, s.Name.Name)
						}
					case *ast.ValueSpec:
						for _, n := range s.Names {
							if n.IsExported() && d.Doc == nil && s.Doc == nil && s.Comment == nil {
								t.Errorf("%s: %s has no doc comment", name, n.Name)
							}
						}
					}
				}
			}
		}
	}
}

func exportedRecv(r *ast.FieldList) bool {
	if len(r.List) == 0 {
		return false
	}
	t := r.List[0].Type
	if s, ok := t.(*ast.StarExpr); ok {
		t = s.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.IsExported()
	}
	return false
}

// TestDocumentsAreInEnglishAndNameNoVendor keeps the vocabulary of the
// repository: no AI vendor instruction file, no attribution in the tree.
func TestTheTreeCarriesNoAIAttribution(t *testing.T) {
	root := packageRoot(t)
	banned := regexp.MustCompile(`(?i)co-authored-by|generated with|claude\.ai|\bchatgpt\b`)
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, "structure_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if loc := banned.FindIndex(b); loc != nil {
			t.Errorf("%s mentions %q", strings.TrimPrefix(path, root+"/"), b[loc[0]:loc[1]])
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
