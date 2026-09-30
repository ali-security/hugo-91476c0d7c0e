// Copyright 2024 The Hugo Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cssjs_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/bep/logg"
	qt "github.com/frankban/quicktest"
	"github.com/gohugoio/hugo/htesting"
	"github.com/gohugoio/hugo/hugofs"
	"github.com/gohugoio/hugo/hugolib"
)

const postCSSIntegrationTestFiles = `
-- assets/css/components/a.css --
/* A comment. */
/* Another comment. */
class-in-a {
	color: blue;
}

-- assets/css/components/all.css --
@import "a.css";
@import "b.css";
-- assets/css/components/b.css --
@import "a.css";

class-in-b {
	color: blue;
}

-- assets/css/styles.css --
@tailwind base;
@tailwind components;
@tailwind utilities;
  @import "components/all.css";
h1 {
	@apply text-2xl font-bold;
}

-- config.toml --
disablekinds = ['taxonomy', 'term', 'page']
baseURL = "https://example.com"
[build]
useResourceCacheWhen = 'never'
-- content/p1.md --
-- data/hugo.toml --
slogan = "Hugo Rocks!"
-- i18n/en.yaml --
hello:
   other: "Hello"
-- i18n/fr.yaml --
hello:
   other: "Bonjour"
-- layouts/index.html --
{{ $options := dict "inlineImports" true }}
{{ $styles := resources.Get "css/styles.css" | css.PostCSS $options }}
Styles RelPermalink: {{ $styles.RelPermalink }}
{{ $cssContent := $styles.Content }}
Styles Content: Len: {{ len $styles.Content }}|
-- package.json --
{
	"scripts": {},

	"devDependencies": {
	"postcss-cli": "7.1.0",
	"tailwindcss": "1.2.0"
	}
}
-- postcss.config.js --
console.error("Hugo Environment:", process.env.HUGO_ENVIRONMENT );
console.error("Hugo PublishDir:", process.env.HUGO_PUBLISHDIR );
// https://github.com/gohugoio/hugo/issues/7656
console.error("package.json:", process.env.HUGO_FILE_PACKAGE_JSON );
console.error("PostCSS Config File:", process.env.HUGO_FILE_POSTCSS_CONFIG_JS );

module.exports = {
	plugins: [
	require('tailwindcss')
	]
}

`

func TestTransformPostCSS(t *testing.T) {
	if !htesting.IsCI() {
		t.Skip("Skip long running test when running locally")
	}

	c := qt.New(t)
	tempDir, clean, err := htesting.CreateTempDir(hugofs.Os, "hugo-integration-test")
	c.Assert(err, qt.IsNil)
	c.Cleanup(clean)

	for _, s := range []string{"never", "always"} {

		repl := strings.NewReplacer(
			"https://example.com",
			"https://example.com/foo",
			"useResourceCacheWhen = 'never'",
			fmt.Sprintf("useResourceCacheWhen = '%s'", s),
		)

		files := repl.Replace(postCSSIntegrationTestFiles)

		b := hugolib.NewIntegrationTestBuilder(
			hugolib.IntegrationTestConfig{
				T:               c,
				NeedsOsFS:       true,
				NeedsNpmInstall: true,
				LogLevel:        logg.LevelInfo,
				WorkingDir:      tempDir,
				TxtarString:     files,
			}).Build()

		b.AssertFileContent("public/index.html", `
Styles RelPermalink: /foo/css/styles.css
Styles Content: Len: 770917|
`)

		if s == "never" {
			b.AssertLogContains("Hugo Environment: production")
			b.AssertLogContains("Hugo PublishDir: " + filepath.Join(tempDir, "public"))
		}
	}
}

// 9880
func TestTransformPostCSSError(t *testing.T) {
	if !htesting.IsCI() {
		t.Skip("Skip long running test when running locally")
	}

	if runtime.GOOS == "windows" {
		// TODO(bep) This has started to fail on Windows with Go 1.19 on GitHub Actions for some mysterious reason.
		t.Skip("Skip on Windows")
	}

	c := qt.New(t)

	s, err := hugolib.NewIntegrationTestBuilder(
		hugolib.IntegrationTestConfig{
			T:               c,
			NeedsOsFS:       true,
			NeedsNpmInstall: true,
			TxtarString:     strings.ReplaceAll(postCSSIntegrationTestFiles, "color: blue;", "@apply foo;"), // Syntax error
		}).BuildE()

	s.AssertIsFileError(err)
	c.Assert(err.Error(), qt.Contains, "a.css:4:2")
}

// nodePermissionsProbeJS returns a JavaScript snippet that tries to read
// readFilename and write writeFilename and logs the outcome to stderr.
func nodePermissionsProbeJS(readFilename, writeFilename string) string {
	return fmt.Sprintf(`
const hugoProbeFs = require("fs");
let hugoProbeRead = "READ_ALLOWED";
try { hugoProbeFs.readFileSync(%q); } catch (e) { hugoProbeRead = "READ_" + e.code; }
let hugoProbeWrite = "WRITE_ALLOWED";
try { hugoProbeFs.writeFileSync(%q, "pwned"); } catch (e) { hugoProbeWrite = "WRITE_" + e.code; }
console.error("NodePermissionsProbe:", hugoProbeRead, hugoProbeWrite);
`, readFilename, writeFilename)
}

// nodePermissionsOutsideProject creates a secret file and the path of a file to be
// written, both in a directory outside of the Hugo project.
func nodePermissionsOutsideProject(t testing.TB) (secretFilename, writeFilename string) {
	t.Helper()
	outsideDir := t.TempDir()
	secretFilename = filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(secretFilename, []byte("hugo-secret-content"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeFilename = filepath.Join(outsideDir, "pwned.txt")
	return
}

// CVE-2026-44301: Node tools must not be able to read or write files outside the project.
func TestTransformPostCSSNodePermissions(t *testing.T) {
	if !htesting.IsCI() {
		t.Skip("Skip long running test when running locally")
	}

	for _, disable := range []bool{true, false} {
		t.Run(fmt.Sprintf("disable=%t", disable), func(t *testing.T) {
			c := qt.New(t)
			secretFilename, writeFilename := nodePermissionsOutsideProject(c)

			files := strings.Replace(postCSSIntegrationTestFiles, "-- postcss.config.js --\n", "-- postcss.config.js --\n"+nodePermissionsProbeJS(secretFilename, writeFilename), 1)
			if disable {
				files = strings.Replace(files, "useResourceCacheWhen = 'never'\n", "useResourceCacheWhen = 'never'\n[security.node.permissions]\ndisable = true\n", 1)
			}

			b := hugolib.NewIntegrationTestBuilder(
				hugolib.IntegrationTestConfig{
					T:               c,
					NeedsOsFS:       true,
					NeedsNpmInstall: true,
					LogLevel:        logg.LevelInfo,
					TxtarString:     files,
				}).Build()

			b.AssertFileContent("public/index.html", "Styles Content: Len: 770917|")

			_, err := os.Stat(writeFilename)
			if disable {
				// Without the Node.js permission model, the tool can access the file system outside of the project.
				b.AssertLogContains("NodePermissionsProbe: READ_ALLOWED WRITE_ALLOWED")
				c.Assert(err, qt.IsNil)
			} else {
				b.AssertLogContains("NodePermissionsProbe: READ_ERR_ACCESS_DENIED WRITE_ERR_ACCESS_DENIED")
				c.Assert(os.IsNotExist(err), qt.IsTrue)
			}
		})
	}
}

// #9895
func TestTransformPostCSSImportError(t *testing.T) {
	if !htesting.IsCI() {
		t.Skip("Skip long running test when running locally")
	}

	c := qt.New(t)

	s, err := hugolib.NewIntegrationTestBuilder(
		hugolib.IntegrationTestConfig{
			T:               c,
			NeedsOsFS:       true,
			NeedsNpmInstall: true,
			LogLevel:        logg.LevelInfo,
			TxtarString:     strings.ReplaceAll(postCSSIntegrationTestFiles, `@import "components/all.css";`, `@import "components/doesnotexist.css";`),
		}).BuildE()

	s.AssertIsFileError(err)
	c.Assert(err.Error(), qt.Contains, "styles.css:4:3")
	c.Assert(err.Error(), qt.Contains, filepath.FromSlash(`failed to resolve CSS @import "/css/components/doesnotexist.css"`))
}

func TestTransformPostCSSImporSkipInlineImportsNotFound(t *testing.T) {
	if !htesting.IsCI() {
		t.Skip("Skip long running test when running locally")
	}

	c := qt.New(t)

	files := strings.ReplaceAll(postCSSIntegrationTestFiles, `@import "components/all.css";`, `@import "components/doesnotexist.css";`)
	files = strings.ReplaceAll(files, `{{ $options := dict "inlineImports" true }}`, `{{ $options := dict "inlineImports" true "skipInlineImportsNotFound" true }}`)

	s := hugolib.NewIntegrationTestBuilder(
		hugolib.IntegrationTestConfig{
			T:               c,
			NeedsOsFS:       true,
			NeedsNpmInstall: true,
			LogLevel:        logg.LevelInfo,
			TxtarString:     files,
		}).Build()

	s.AssertFileContent("public/css/styles.css", `@import "components/doesnotexist.css";`)
}

// Issue 9787
func TestTransformPostCSSResourceCacheWithPathInBaseURL(t *testing.T) {
	if !htesting.IsCI() {
		t.Skip("Skip long running test when running locally")
	}

	c := qt.New(t)
	tempDir, clean, err := htesting.CreateTempDir(hugofs.Os, "hugo-integration-test")
	c.Assert(err, qt.IsNil)
	c.Cleanup(clean)

	for i := range 2 {
		files := postCSSIntegrationTestFiles

		if i == 1 {
			files = strings.ReplaceAll(files, "https://example.com", "https://example.com/foo")
			files = strings.ReplaceAll(files, "useResourceCacheWhen = 'never'", "	useResourceCacheWhen = 'always'")
		}

		b := hugolib.NewIntegrationTestBuilder(
			hugolib.IntegrationTestConfig{
				T:               c,
				NeedsOsFS:       true,
				NeedsNpmInstall: true,
				LogLevel:        logg.LevelInfo,
				TxtarString:     files,
				WorkingDir:      tempDir,
			}).Build()

		b.AssertFileContent("public/index.html", `
Styles Content: Len: 770917
`)

	}
}
