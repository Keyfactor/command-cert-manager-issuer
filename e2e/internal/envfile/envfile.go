/*
Copyright © 2026 Keyfactor

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package envfile loads KEY=VALUE files into the process environment. It lets the
// setup tool and the test suite share one configuration file.
package envfile

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// Load reads KEY=VALUE lines from path into the process environment.
// Variables that are already set are not overridden. A leading "export " is
// accepted so files written for `source` work too. Values may be single or
// double quoted; unquoted values end at a " #" comment.
func Load(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening env file: %w", err)
	}
	defer f.Close()
	return parse(f, os.LookupEnv, os.Setenv)
}

func parse(r io.Reader, lookup func(string) (string, bool), set func(string, string) error) error {
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")

		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("env file line %d: expected KEY=VALUE", n)
		}
		key = strings.TrimSpace(key)
		val = parseValue(strings.TrimSpace(val))

		if _, exists := lookup(key); exists {
			continue
		}
		if err := set(key, val); err != nil {
			return err
		}
	}
	return sc.Err()
}

func parseValue(v string) string {
	if v == "" {
		return ""
	}
	if q := v[0]; q == '"' || q == '\'' {
		if end := strings.IndexByte(v[1:], q); end >= 0 {
			return v[1 : 1+end]
		}
		return v[1:]
	}
	if i := strings.Index(v, " #"); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}
