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
	"testing"

	"github.com/bep/logg"
	qt "github.com/frankban/quicktest"
	"github.com/gohugoio/hugo/htesting"
	"github.com/gohugoio/hugo/hugofs"
	"github.com/gohugoio/hugo/hugolib"
)

func TestTailwindV4Basic(t *testing.T) {
	if !htesting.IsCI() {
		t.Skip("Skip long running test when running locally")
	}

	files := `
-- hugo.toml --
security.exec.allow = ['^go$', '^git$', '^node$', '^tailwindcss$']
-- package.json --
{
  "license": "MIT",
  "repository": {
    "type": "git",
    "url": "https://github.com/bep/hugo-starter-tailwind-basic.git"
  },
  "devDependencies": {
    "@tailwindcss/cli": "^4.0.1",
    "tailwindcss": "^4.0.1"
  },
  "name": "hugo-starter-tailwind-basic",
  "version": "0.1.0"
}
-- assets/css/styles.css --
@import "tailwindcss";

@theme {
  --font-family-display: "Satoshi", "sans-serif";

  --breakpoint-3xl: 1920px;

  --color-neon-pink: oklch(71.7% 0.25 360);
  --color-neon-lime: oklch(91.5% 0.258 129);
  --color-neon-cyan: oklch(91.3% 0.139 195.8);
}
-- layouts/index.html --
{{ $css := resources.Get "css/styles.css" | css.TailwindCSS }}
CSS: {{ $css.Content | safeCSS }}|
`

	b := hugolib.NewIntegrationTestBuilder(
		hugolib.IntegrationTestConfig{
			T:               t,
			TxtarString:     files,
			NeedsOsFS:       true,
			NeedsNpmInstall: true,
			LogLevel:        logg.LevelInfo,
		}).Build()

	b.AssertFileContent("public/index.html", "/*! tailwindcss v4.")
}

func TestTailwindCSSNoInlineImportsIssue13719(t *testing.T) {
	t.Parallel()

	files := `
-- hugo.toml --
disableKinds = ['page','rss','section','sitemap','taxonomy','term']
theme = 'my-theme'

security.exec.allow = ['^go$', '^git$', '^node$', '^tailwindcss$']

[[module.mounts]]
source = 'assets'
target = 'assets'

[[module.mounts]]
source = 'other'
target = 'assets/css'
-- assets/css/main.css --
@import "tailwindcss";

@import "colors/red.css";
@import "colors/blue.css";
@import "colors/purple.css";
-- assets/css/colors/red.css --
@import "green.css";

.red {color: red;}
-- assets/css/colors/green.css --
.green {color: green;}
-- themes/my-theme/assets/css/colors/blue.css --
.blue {color: blue;}
-- other/colors/purple.css --
.purple {color: purple;}
-- layouts/home.html --
{{ with (templates.Defer (dict "key" "global")) }}
  {{ with resources.Get "css/main.css" }}
    {{ $opts := dict "disableInlineImports" true }}
    {{ with . | css.TailwindCSS $opts }}
      <link rel="stylesheet" href="{{ .RelPermalink }}">
    {{ end }}
  {{ end }}
{{ end }}
-- package.json --
{
  "devDependencies": {
    "@tailwindcss/cli": "^4.1.7",
    "tailwindcss": "^4.1.7"
  }
}
`

	b, err := hugolib.NewIntegrationTestBuilder(
		hugolib.IntegrationTestConfig{
			T:               t,
			TxtarString:     files,
			NeedsOsFS:       true,
			NeedsNpmInstall: true,
			LogLevel:        logg.LevelInfo,
		}).BuildE()

	b.Assert(err, qt.IsNotNil)
	b.Assert(err.Error(), qt.Contains, "Can't resolve 'colors/red.css'")
	b.Assert(err.Error(), qt.Contains, "You may want to set the 'disableInlineImports' option to false")
}

// CVE-2026-44301: Node tools must not be able to read or write files outside the project.
func TestTailwindCSSNodePermissions(t *testing.T) {
	if !htesting.IsCI() {
		t.Skip("Skip long running test when running locally")
	}

	const packageJSON = `
-- package.json --
{
  "devDependencies": {
    "@tailwindcss/cli": "^4.1.7",
    "tailwindcss": "^4.1.7"
  }
}
`

	// A plugin (e.g. provided by a theme) reads and writes files outside of the project.
	t.Run("Plugin", func(t *testing.T) {
		for _, disable := range []bool{true, false} {
			t.Run(fmt.Sprintf("disable=%t", disable), func(t *testing.T) {
				c := qt.New(t)
				secretFilename, writeFilename := nodePermissionsOutsideProject(c)

				files := fmt.Sprintf(`
-- hugo.toml --
disableKinds = ['page','rss','section','sitemap','taxonomy','term']
[security.exec]
allow = ['^go$', '^git$', '^node$', '^tailwindcss$']
[security.node.permissions]
disable = %t
-- probe.js --
%s
module.exports = function () {};
-- assets/css/main.css --
@import "tailwindcss";
@plugin "./probe.js";
-- layouts/home.html --
{{ with resources.Get "css/main.css" | css.TailwindCSS }}CSS: {{ .Content | safeCSS }}|{{ end }}
`, disable, nodePermissionsProbeJS(secretFilename, writeFilename)) + packageJSON

				b := hugolib.NewIntegrationTestBuilder(
					hugolib.IntegrationTestConfig{
						T:               c,
						TxtarString:     files,
						NeedsOsFS:       true,
						NeedsNpmInstall: true,
						LogLevel:        logg.LevelInfo,
					}).Build()

				b.AssertFileContent("public/index.html", "/*! tailwindcss v4.")

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
	})

	// A stylesheet (e.g. provided by a theme) imports a file outside of the project.
	t.Run("Import", func(t *testing.T) {
		for _, disable := range []bool{true, false} {
			t.Run(fmt.Sprintf("disable=%t", disable), func(t *testing.T) {
				c := qt.New(t)
				workingDir, clean, err := htesting.CreateTempDir(hugofs.Os, "hugo-integration-test")
				c.Assert(err, qt.IsNil)
				c.Cleanup(clean)

				outsideCSSFilename := filepath.Join(c.TempDir(), "outside.css")
				c.Assert(os.WriteFile(outsideCSSFilename, []byte(".leaked-outside-content { color: red; }\n"), 0o644), qt.IsNil)
				rel, err := filepath.Rel(workingDir, outsideCSSFilename)
				c.Assert(err, qt.IsNil)

				files := fmt.Sprintf(`
-- hugo.toml --
disableKinds = ['page','rss','section','sitemap','taxonomy','term']
[security.exec]
allow = ['^go$', '^git$', '^node$', '^tailwindcss$']
[security.node.permissions]
disable = %t
-- assets/css/main.css --
@import "tailwindcss";
@import %q;
-- layouts/home.html --
{{ with resources.Get "css/main.css" | css.TailwindCSS (dict "disableInlineImports" true) }}CSS: {{ .Content | safeCSS }}|{{ end }}
`, disable, filepath.ToSlash(rel)) + packageJSON

				b, err := hugolib.NewIntegrationTestBuilder(
					hugolib.IntegrationTestConfig{
						T:               c,
						TxtarString:     files,
						NeedsOsFS:       true,
						NeedsNpmInstall: true,
						LogLevel:        logg.LevelInfo,
						WorkingDir:      workingDir,
					}).BuildE()

				if disable {
					// Without the Node.js permission model, the tool can read files outside of the project.
					c.Assert(err, qt.IsNil)
					b.AssertFileContent("public/index.html", "leaked-outside-content")
					return
				}
				if err != nil {
					c.Assert(err.Error(), qt.Not(qt.Contains), "leaked-outside-content")
				} else {
					b.AssertFileContent("public/index.html", "! leaked-outside-content")
				}
			})
		}
	})
}
