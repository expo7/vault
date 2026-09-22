# Security policy and threat model

## What this protects

Vault records are encrypted at rest with AES-256-GCM, an authenticated
encryption mode provided by `cryptography`. The encryption key is derived from
your master password with scrypt and a fresh random salt for every vault write.
The encrypted vault is stored at `~/.local/share/vault/vault.enc` by default
(or `$XDG_DATA_HOME/vault/vault.enc`), with restrictive `0700` directory and
`0600` file permissions where the operating system supports them.

The master password and record secrets are never stored separately, logged, or
accepted as normal command-line arguments. `add` uses hidden terminal input.

## What this does not protect

This tool cannot protect secrets on a compromised machine, from malware or a
keylogger, from someone who knows or can guess the master password, or from a
user account that can read your files while the vault is unlocked. Back up the
encrypted vault file if it matters: losing both that file and its master
password makes the secrets unrecoverable.

Metadata is encrypted at rest too, but it is intentionally displayed after
authentication by `list`, `search`, and `info`. Treat descriptions, URLs,
notes, and tags as non-secret. The optional clipboard feature temporarily puts
the selected secret on the system clipboard; it attempts to clear it after the
configured timeout only if the clipboard has not changed.

## Reporting a vulnerability

Do not put sensitive vulnerability details in a public issue. Contact the
maintainer privately through the repository owner's GitHub profile.
