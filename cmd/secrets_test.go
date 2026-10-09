package cmd

import (
	"strings"
	"testing"
)

const testWG = `[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.8.0.2/32

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 0.0.0.0/0
Endpoint = 203.0.113.7:51820
`

func TestReadSecretsStdin(t *testing.T) {
	in := `{"config":{"private_key":"k1","ipv4":"172.16.0.2"},"exit_config":{"private_key":"k2"},"wg":` +
		strings.ReplaceAll(`"`+testWG+`"`, "\n", `\n`) + `}`
	b, err := readSecretsStdin(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b.Config), `"k1"`) || !strings.Contains(string(b.ExitConfig), `"k2"`) || !strings.Contains(b.WG, "Endpoint = 203.0.113.7:51820") {
		t.Fatalf("bundle parsed wrong: %+v", b)
	}

	stdinSecrets = b
	defer func() { stdinSecrets = nil }()
	wg, exit, err := chainKeys("", "")
	if err != nil {
		t.Fatal(err)
	}
	if exit.PrivateKey != "k2" || wg.Peers[0].Endpoint != "203.0.113.7:51820" {
		t.Fatalf("chainKeys from the bundle: exit=%q endpoint=%q", exit.PrivateKey, wg.Peers[0].Endpoint)
	}
	if b.WG != "" || b.ExitConfig != nil {
		t.Fatal("the chain keys were left in the bundle after use")
	}
}

func TestReadSecretsStdinRejects(t *testing.T) {
	for name, in := range map[string]string{
		"empty":     "",
		"no config": `{"wg":"x"}`,
		"not json":  "private_key=abc",
		"too big":   `{"config":{"x":"` + strings.Repeat("a", maxSecretsBytes) + `"}}`,
	} {
		if _, err := readSecretsStdin(strings.NewReader(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
