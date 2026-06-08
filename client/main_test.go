package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestIsSignInvocation(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{[]string{"-Y", "sign", "-n", "git", "-f", "k", "/tmp/buf"}, true},
		{[]string{"-Y", "verify", "-f", "allowed"}, false},
		{[]string{"attest", "https://host"}, false},
	}
	for _, c := range cases {
		if got := isSignInvocation(c.args); got != c.want {
			t.Errorf("isSignInvocation(%v) = %v, want %v", c.args, got, c.want)
		}
	}
}

func TestParseSign(t *testing.T) {
	ns, file := parseSign([]string{"-Y", "sign", "-n", "git", "-f", "/keys/id", "/tmp/buffer"})
	if ns != "git" {
		t.Errorf("namespace = %q, want git", ns)
	}
	if file != "/tmp/buffer" {
		t.Errorf("file = %q, want /tmp/buffer", file)
	}
}

func TestRunSignWritesSigFile(t *testing.T) {
	const armored = "-----BEGIN SSH SIGNATURE-----\nABCD\n-----END SSH SIGNATURE-----\n"

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sign" {
			http.NotFound(w, r)
			return
		}
		var req signRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Namespace != "git" {
			t.Errorf("namespace forwarded = %q", req.Namespace)
		}
		_ = json.NewEncoder(w).Encode(signResponse{Signature: armored})
	}))
	defer srv.Close()

	dir := t.TempDir()
	file := filepath.Join(dir, "buffer")
	if err := os.WriteFile(file, []byte("commit payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENCLAVE_URL", srv.URL)

	if err := runSign([]string{"-Y", "sign", "-n", "git", "-f", "k", file}); err != nil {
		t.Fatalf("runSign: %v", err)
	}
	got, err := os.ReadFile(file + ".sig")
	if err != nil {
		t.Fatalf("read .sig: %v", err)
	}
	if string(got) != armored {
		t.Fatalf("sig file = %q, want %q", got, armored)
	}
}
