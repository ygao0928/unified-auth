package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ygao0928/unified-auth/auth-center/internal/keys"
)

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	dir := fs.String("dir", ".dev-keys", "directory for the development signing key")
	bits := fs.Int("bits", 2048, "RSA modulus bits")
	kid := fs.String("kid", "", "key id; default is a random dev- id")
	force := fs.Bool("force", false, "overwrite an existing active.pem")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(*dir, "active.pem")
	if _, err := os.Stat(path); err == nil && !*force {
		existing, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fmt.Printf("keeping %s\n", path)
		fmt.Printf("kid: %s\n", kidFrom(existing))
		return nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	pemBytes, jwk, err := keys.GenerateRSA(*kid, *bits)
	if err != nil {
		return err
	}
	// 目录是 0700。文件本身 0644，这样本地容器里的非 root 用户也能读到挂载的开发密钥。
	if err := os.WriteFile(path, pemBytes, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n", path)
	fmt.Printf("AUTH_CENTER_KEY_ACTIVE_ALG=%s\n", keys.AlgRS256)
	fmt.Printf("AUTH_CENTER_KEY_ACTIVE_PEM_FILE=%s\n", path)
	fmt.Printf("kid: %s\n", jwk.KeyID)
	return nil
}

func kidFrom(raw []byte) string {
	for _, line := range splitLines(string(raw)) {
		const prefix = "# kid:"
		if len(line) >= len(prefix) && line[:len(prefix)] == prefix {
			i := len(prefix)
			for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
				i++
			}
			return line[i:]
		}
	}
	return ""
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, trimCR(s[start:i]))
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, trimCR(s[start:]))
	}
	return out
}

func trimCR(s string) string {
	if len(s) > 0 && s[len(s)-1] == '\r' {
		return s[:len(s)-1]
	}
	return s
}
