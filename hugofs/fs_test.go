// Copyright 2016 The Hugo Authors. All rights reserved.
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

package hugofs

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/bep/overlayfs"
	"github.com/gohugoio/hugo/config"

	qt "github.com/frankban/quicktest"
	"github.com/gohugoio/hugo/htesting/hqt"
	"github.com/spf13/afero"
)

func TestIsOsFs(t *testing.T) {
	c := qt.New(t)

	c.Assert(IsOsFs(Os), qt.Equals, true)
	c.Assert(IsOsFs(&afero.MemMapFs{}), qt.Equals, false)
	c.Assert(IsOsFs(NewBasePathFs(&afero.MemMapFs{}, "/public")), qt.Equals, false)
	c.Assert(IsOsFs(NewBasePathFs(Os, t.TempDir())), qt.Equals, true)
}

func TestNewDefault(t *testing.T) {
	c := qt.New(t)
	v := config.New()
	v.Set("workingDir", t.TempDir())
	v.Set("publishDir", "public")
	f := NewDefault(v)

	c.Assert(f.Source, qt.IsNotNil)
	c.Assert(f.Source, hqt.IsSameType, new(afero.OsFs))
	c.Assert(f.Os, qt.IsNotNil)
	c.Assert(f.WorkingDirReadOnly, qt.IsNotNil)
	c.Assert(IsOsFs(f.WorkingDirReadOnly), qt.IsTrue)
	c.Assert(IsOsFs(f.Source), qt.IsTrue)
	c.Assert(IsOsFs(f.PublishDir), qt.IsTrue)
	c.Assert(IsOsFs(f.Os), qt.IsTrue)
}

func TestDropSymlinksFs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skip on Windows, creating symlinks needs admin privileges")
	}

	c := qt.New(t)

	dir1, dir2, outside := t.TempDir(), t.TempDir(), t.TempDir()

	c.Assert(os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0o666), qt.IsNil)
	c.Assert(os.WriteFile(filepath.Join(dir1, "regular1.txt"), []byte("regular1"), 0o666), qt.IsNil)
	c.Assert(os.WriteFile(filepath.Join(dir2, "regular2.txt"), []byte("regular2"), 0o666), qt.IsNil)
	c.Assert(os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(dir1, "filesymlink.txt")), qt.IsNil)
	c.Assert(os.Symlink(outside, filepath.Join(dir2, "dirsymlink")), qt.IsNil)

	// Same structure as the os template funcs' filesystem:
	// an overlay of a read-only fs wrapping an overlay of base path filesystems.
	inner := overlayfs.New(overlayfs.Options{Fss: []afero.Fs{NewBasePathFs(Os, dir1), NewBasePathFs(Os, dir2)}})

	for i, fs := range []afero.Fs{
		inner,
		NewReadOnlyFs(inner),
		overlayfs.New(overlayfs.Options{Fss: []afero.Fs{NewReadOnlyFs(inner)}}),
	} {
		c.Run(fmt.Sprintf("fs%d", i), func(c *qt.C) {
			for _, name := range []string{"filesymlink.txt", "dirsymlink"} {
				fi, err := LstatIfPossible(fs, name)
				c.Assert(err, qt.IsNil)
				c.Assert(fi.Mode()&os.ModeSymlink != 0, qt.IsTrue, qt.Commentf("%s", name))
			}

			dfs := NewDropSymlinksFs(fs)

			for _, name := range []string{"filesymlink.txt", "dirsymlink", "doesnotexist.txt"} {
				_, err := dfs.Stat(name)
				c.Assert(err, qt.ErrorIs, os.ErrNotExist, qt.Commentf("%s", name))
				_, err = dfs.Open(name)
				c.Assert(err, qt.ErrorIs, os.ErrNotExist, qt.Commentf("%s", name))
				exists, err := afero.Exists(dfs, name)
				c.Assert(err, qt.IsNil)
				c.Assert(exists, qt.IsFalse, qt.Commentf("%s", name))
			}

			_, err := afero.ReadFile(dfs, "filesymlink.txt")
			c.Assert(err, qt.ErrorIs, os.ErrNotExist)
			_, err = afero.ReadDir(dfs, "dirsymlink")
			c.Assert(err, qt.ErrorIs, os.ErrNotExist)

			b, err := afero.ReadFile(dfs, "regular1.txt")
			c.Assert(err, qt.IsNil)
			c.Assert(string(b), qt.Equals, "regular1")
			b, err = afero.ReadFile(dfs, "regular2.txt")
			c.Assert(err, qt.IsNil)
			c.Assert(string(b), qt.Equals, "regular2")
			fi, err := dfs.Stat("regular2.txt")
			c.Assert(err, qt.IsNil)
			c.Assert(fi.Size(), qt.Equals, int64(len("regular2")))
		})
	}
}
