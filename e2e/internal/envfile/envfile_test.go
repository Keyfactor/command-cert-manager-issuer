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

package envfile

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	in := `# comment
export A="one two"
B='three' # trailing comment
C=four # trailing comment
D=
E=keep
`
	got := map[string]string{"E": "existing"}
	lookup := func(k string) (string, bool) { v, ok := got[k]; return v, ok }
	set := func(k, v string) error { got[k] = v; return nil }

	if err := parse(strings.NewReader(in), lookup, set); err != nil {
		t.Fatal(err)
	}

	want := map[string]string{"A": "one two", "B": "three", "C": "four", "D": "", "E": "existing"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestParseRejectsMalformedLine(t *testing.T) {
	err := parse(strings.NewReader("not a pair\n"), func(string) (string, bool) { return "", false }, func(string, string) error { return nil })
	if err == nil {
		t.Fatal("expected an error")
	}
}
