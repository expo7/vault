# Local Credential Vault

A small, local command-line vault for passwords, tokens, deployment
credentials, recovery codes, and other secrets. It is designed so you can
give an AI assistant a stable credential name and retrieval command without
giving it the credential value.

The vault uses AES-256-GCM authenticated encryption from
[`cryptography`](https://cryptography.io/). Its key is derived from your
master password using scrypt. The encrypted data is local only:

`~/.local/share/vault/vault.enc`

or `$XDG_DATA_HOME/vault/vault.enc` when `XDG_DATA_HOME` is set. No vault data,
keys, or master passwords belong in this source repository.

## Install

From this repository:

```sh
pipx install .
```

This creates an isolated environment and makes `vault` available on your
`PATH`. If `pipx` is not installed, install it with your operating system's
package manager. Then verify:

```sh
vault --help
```

For development with tests:

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
```

## Everyday use

Create a record. The vault asks for a master password on first use, then asks
for the secret using hidden terminal input. Never put the secret after the
command name.

```sh
vault add quantelle-research-operator-token \
  --description "Research API access" \
  --username "my-account" \
  --url "https://example.com" \
  --tag research --tag api
```

The command prints the stable retrieval command, but never echoes the secret:

```text
Saved: quantelle-research-operator-token
Retrieve later with: vault get quantelle-research-operator-token
```

Retrieve a secret only when you deliberately need it:

```sh
vault get quantelle-research-operator-token
```

Discovery commands never reveal secrets:

```sh
vault list
vault search quantelle
vault info quantelle-research-operator-token
```

Copy without printing (when a supported clipboard utility is available):

```sh
vault copy quantelle-research-operator-token
```

`copy` tries to clear the clipboard after 30 seconds, and only clears it when
the clipboard still contains the value copied by this command. Use
`--clear-after SECONDS` to choose another positive timeout.

Delete requires confirmation:

```sh
vault delete quantelle-research-operator-token
```

## AI-assistant workflow

Tell an assistant only the stable name, for example
`quantelle-research-operator-token`. It can instruct you to run:

```sh
vault add quantelle-research-operator-token
```

You enter the value privately in your terminal. Later it can safely recommend:

```sh
vault get quantelle-research-operator-token
```

Do not put secrets in metadata fields. See [SECURITY.md](SECURITY.md) for the
threat model and limitations.
