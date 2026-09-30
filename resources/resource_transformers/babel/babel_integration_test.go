// Copyright 2021 The Hugo Authors. All rights reserved.
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

package babel_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/bep/logg"
	qt "github.com/frankban/quicktest"
	"github.com/gohugoio/hugo/htesting"
	"github.com/gohugoio/hugo/hugolib"
)

func TestTransformBabel(t *testing.T) {
	if !htesting.IsCI() {
		t.Skip("Skip long running test when running locally")
	}

	files := `
-- assets/js/main.js --
/* A Car */
class Car {
	constructor(brand) {
	this.carname = brand;
	}
}
-- assets/js/main2.js --
/* A Car2 */
class Car2 {
	constructor(brand) {
	this.carname = brand;
	}
}
-- babel.config.js --
console.error("Hugo Environment:", process.env.HUGO_ENVIRONMENT );

module.exports = {
	presets: ["@babel/preset-env"],
};
-- config.toml --
disablekinds = ['taxonomy', 'term', 'page']
[security]
	[security.exec]
	allow = ['^node$', '^babel$']
-- layouts/index.html --
{{ $options := dict "noComments" true }}
{{ $transpiled := resources.Get "js/main.js" | babel -}}
Transpiled: {{ $transpiled.Content | safeJS }}

{{ $transpiled := resources.Get "js/main2.js" | babel (dict "sourceMap" "inline") -}}
Transpiled2: {{ $transpiled.Content | safeJS }}

{{ $transpiled := resources.Get "js/main2.js" | babel (dict "sourceMap" "external") -}}
Transpiled3: {{ $transpiled.Permalink }}
-- package.json --
{
	"scripts": {},

	"devDependencies": {
	"@babel/cli": "7.8.4",
	"@babel/core": "7.9.0",	
	"@babel/preset-env": "7.9.5"
	}
}

	`

	b := hugolib.NewIntegrationTestBuilder(
		hugolib.IntegrationTestConfig{
			T:               t,
			TxtarString:     files,
			NeedsOsFS:       true,
			NeedsNpmInstall: true,
			LogLevel:        logg.LevelInfo,
		}).Build()

	b.AssertLogContains("babel: Hugo Environment: production")
	b.AssertFileContent("public/index.html", `var Car2 =`)
	b.AssertFileContent("public/js/main2.js", `var Car2 =`)
	b.AssertFileContent("public/js/main2.js.map", `{"version":3,`)
	b.AssertFileContent("public/index.html", `
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozL`)
}

// CVE-2026-44301: Node tools must not be able to read or write files outside the project.
func TestTransformBabelNodePermissions(t *testing.T) {
	if !htesting.IsCI() {
		t.Skip("Skip long running test when running locally")
	}

	filesTemplate := `
-- assets/js/main.js --
/* A Car */
class Car {
	constructor(brand) {
	this.carname = brand;
	}
}
-- babel.config.js --
const hugoProbeFs = require("fs");
let hugoProbeRead = "READ_ALLOWED";
try { hugoProbeFs.readFileSync(%q); } catch (e) { hugoProbeRead = "READ_" + e.code; }
let hugoProbeWrite = "WRITE_ALLOWED";
try { hugoProbeFs.writeFileSync(%q, "pwned"); } catch (e) { hugoProbeWrite = "WRITE_" + e.code; }
console.error("NodePermissionsProbe:", hugoProbeRead, hugoProbeWrite);

module.exports = {
	presets: ["@babel/preset-env"],
};
-- config.toml --
disablekinds = ['taxonomy', 'term', 'page']
[security]
	[security.exec]
	allow = ['^node$', '^babel$']
	[security.node.permissions]
	disable = %t
-- layouts/index.html --
{{ $transpiled := resources.Get "js/main.js" | babel -}}
Transpiled: {{ $transpiled.Content | safeJS }}
-- package.json --
{
	"scripts": {},

	"devDependencies": {
	"@babel/cli": "7.8.4",
	"@babel/core": "7.9.0",
	"@babel/preset-env": "7.9.5"
	}
}

	`

	for _, disable := range []bool{true, false} {
		t.Run(fmt.Sprintf("disable=%t", disable), func(t *testing.T) {
			c := qt.New(t)

			outsideDir := t.TempDir()
			secretFilename := filepath.Join(outsideDir, "secret.txt")
			c.Assert(os.WriteFile(secretFilename, []byte("hugo-secret-content"), 0o644), qt.IsNil)
			writeFilename := filepath.Join(outsideDir, "pwned.txt")

			files := fmt.Sprintf(filesTemplate, secretFilename, writeFilename, disable)

			b := hugolib.NewIntegrationTestBuilder(
				hugolib.IntegrationTestConfig{
					T:               c,
					TxtarString:     files,
					NeedsOsFS:       true,
					NeedsNpmInstall: true,
					LogLevel:        logg.LevelInfo,
				}).Build()

			b.AssertFileContent("public/index.html", `var Car =`)

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
