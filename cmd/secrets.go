package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Diniboy1123/usque/config"
)

// secretsBundle is what --secrets-stdin reads: every key the command needs, sent
// through a pipe by the app that starts usque, so the keys never sit in a file.
//
//	{"config": {...config.json...}, "exit_config": {...}, "wg": "[Interface]\n..."}
//
// exit_config and wg are only used by the chain command.
type secretsBundle struct {
	Config     json.RawMessage `json:"config"`
	ExitConfig json.RawMessage `json:"exit_config"`
	WG         string          `json:"wg"`
}

// stdinSecrets is set when the keys came from stdin; commands consume (and clear)
// the parts they need.
var stdinSecrets *secretsBundle

const maxSecretsBytes = 1 << 20

func readSecretsStdin(r io.Reader) (*secretsBundle, error) {
	if tracerAttached() {
		return nil, errors.New("refusing to read keys: a debugger or tracer is attached")
	}
	raw, err := io.ReadAll(io.LimitReader(r, maxSecretsBytes+1))
	defer clear(raw)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxSecretsBytes {
		return nil, fmt.Errorf("more than %d bytes", maxSecretsBytes)
	}
	var b secretsBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("not a key bundle: %w", err)
	}
	if len(b.Config) == 0 {
		return nil, errors.New(`no "config" in the key bundle`)
	}
	return &b, nil
}

// wipe drops the bundle's remaining key material (best effort: Go may have
// copied it already, but nothing keeps a reference to these bytes after this).
func (b *secretsBundle) wipe() {
	if b == nil {
		return
	}
	clear(b.Config)
	clear(b.ExitConfig)
	b.Config, b.ExitConfig, b.WG = nil, nil, ""
}

// loadSecretsFromStdin backs --secrets-stdin: it reads the bundle and loads the
// WARP identity from it in place of the -c file.
func loadSecretsFromStdin() error {
	b, err := readSecretsStdin(os.Stdin)
	if err != nil {
		return err
	}
	if err := config.LoadConfigBytes(b.Config); err != nil {
		b.wipe()
		return err
	}
	clear(b.Config)
	b.Config = nil
	stdinSecrets = b
	return nil
}