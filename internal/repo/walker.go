// Package repo implements --repo mode: static checks on a local source tree
// before it is deployed.
package repo

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// File is one readable text file from the repository.
type File struct {
	Rel     string // slash-separated path relative to the root
	Body    string
	IsEnv   bool // .env, .env.local, .env.production, ... (not .env.example)
	Ignored bool // matched by the root .gitignore
}

// WalkOptions limits how much is read.
type WalkOptions struct {
	MaxFileBytes int64
	MaxFiles     int
}

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".venv": true,
	"__pycache__": true, ".turbo": true, ".cache": true, ".idea": true, ".vscode": true,
}

var skipFiles = map[string]bool{
	"package-lock.json": true, "pnpm-lock.yaml": true, "yarn.lock": true,
	"bun.lock": true, "go.sum": true, "Cargo.lock": true, "composer.lock": true,
}

var envRe = regexp.MustCompile(`^\.env(\..+)?$`)

func isEnvName(base string) bool {
	if !envRe.MatchString(base) {
		return false
	}
	for _, suffix := range []string{".example", ".sample", ".template", ".dist"} {
		if strings.HasSuffix(base, suffix) {
			return false
		}
	}
	return true
}

// Walk reads text files under root, skipping dependencies, binaries and
// very large files.
func Walk(root string, opts WalkOptions) ([]File, []string, error) {
	if opts.MaxFileBytes <= 0 {
		opts.MaxFileBytes = 2 << 20
	}
	if opts.MaxFiles <= 0 {
		opts.MaxFiles = 5000
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, nil, err
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("%s is not a directory", root)
	}

	ig := loadIgnore(root)
	var (
		files    []File
		warnings []string
	)
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entry: skip
		}
		if d.IsDir() {
			if p != root && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if skipFiles[d.Name()] || !d.Type().IsRegular() {
			return nil
		}
		if len(files) >= opts.MaxFiles {
			warnings = append(warnings, fmt.Sprintf("stopped after %d files (raise the limit with --max-files)", opts.MaxFiles))
			return filepath.SkipAll
		}
		fi, err := d.Info()
		if err != nil || fi.Size() > opts.MaxFileBytes || fi.Size() == 0 {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		head := b
		if len(head) > 8000 {
			head = head[:8000]
		}
		if bytes.IndexByte(head, 0) >= 0 {
			return nil // binary
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		files = append(files, File{
			Rel:     rel,
			Body:    string(b),
			IsEnv:   isEnvName(d.Name()),
			Ignored: ig.matches(rel),
		})
		return nil
	})
	return files, warnings, err
}

// ---- minimal .gitignore support (root file only) ----

type ignorePattern struct {
	glob     string
	negate   bool
	dirOnly  bool
	anchored bool
}

type ignoreSet []ignorePattern

func loadIgnore(root string) ignoreSet {
	b, err := os.ReadFile(filepath.Join(root, ".gitignore"))
	if err != nil {
		return nil
	}
	var set ignoreSet
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := ignorePattern{}
		if strings.HasPrefix(line, "!") {
			p.negate = true
			line = line[1:]
		}
		if strings.HasSuffix(line, "/") {
			p.dirOnly = true
			line = strings.TrimSuffix(line, "/")
		}
		if strings.Contains(line, "/") {
			p.anchored = true
			line = strings.TrimPrefix(line, "/")
		}
		p.glob = line
		set = append(set, p)
	}
	return set
}

// matches reports whether rel is ignored; the last matching pattern wins.
func (s ignoreSet) matches(rel string) bool {
	ignored := false
	parts := strings.Split(rel, "/")
	for _, p := range s {
		if p.match(parts) {
			ignored = !p.negate
		}
	}
	return ignored
}

func (p ignorePattern) match(parts []string) bool {
	if p.anchored {
		for i := 1; i <= len(parts); i++ {
			if p.dirOnly && i == len(parts) {
				break
			}
			if ok, _ := path.Match(p.glob, strings.Join(parts[:i], "/")); ok {
				return true
			}
		}
		return false
	}
	for i, part := range parts {
		if p.dirOnly && i == len(parts)-1 {
			break // a directory-only pattern cannot match the file itself
		}
		if ok, _ := path.Match(p.glob, part); ok {
			return true
		}
	}
	return false
}
