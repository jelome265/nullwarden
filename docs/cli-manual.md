# CLI Manual

## Installation
Binary distributions are available for Linux, Windows, and macOS. All binaries are signed with `minisign` and published with `SHA256SUMS`.

## Commands

### `nullwarden init`
Initializes a new vault. Prompts for a master password.
- Enforces zxcvbn score ≥ 3.
- Creates `vault.nwd` in the default data directory.

### `nullwarden add <title> <username> [password]`
Adds a new entry to the vault.
- Prompts for password if not provided as an argument.
- Passing a password as a CLI argument is supported but discouraged because shell history and process inspection can expose it.
- `--notes`: Optional notes for the entry.

### `nullwarden get <title>`
Retrieves an entry. Prompts for the master password.
- Default: Copies password to clipboard.
- If you use a clipboard manager, clear its history after use.
- `--print`: Prints password to stdout (NOT RECOMMENDED).

### `nullwarden export [--output path]`
Copies the encrypted vault blob to an offline backup file.
- Default output path: same directory as the vault, with `.nwbackup` extension.
- The exported file remains encrypted and can be stored offline.

### `nullwarden list`
Lists all entry titles in the vault.

### `nullwarden delete <title>`
Deletes an entry from the vault.

### `nullwarden register <username> [password]`
Registers a new account on the synchronization server.

### `nullwarden push`
Uploads the local vault to the server.
- Uses version-based conflict detection.
- Rejects if server has a newer version.
- Warns when the CLI is still pointed at the default localhost server URL.

### `nullwarden pull`
Downloads the vault from the server.
- Performs integrity check before overwriting local vault.
- Warns when the CLI is still pointed at the default localhost server URL.

## New Device Restore

1. Install `nullwarden-cli` on the new device.
2. Configure `server_url` in the CLI config if your server is not the default localhost address.
3. Register or log in to obtain session tokens.
4. Run `nullwarden pull`.
5. Enter the existing master password when prompted so the downloaded vault can be verified before it is written locally.

## Security Considerations
- **Lock by Exit:** The CLI does not persist keys in memory between commands.
- **Keyring:** Session tokens are stored in the OS keyring when available. If keyring storage fails, the CLI falls back to local session files.
- **Windows session files:** The fallback session files attempt to restrict access using `icacls`.
- **Clipboard:** Retrieved passwords are copied to the clipboard, but the CLI does not guarantee automatic clipboard clearing.
