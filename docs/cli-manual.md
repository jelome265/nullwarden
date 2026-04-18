# CLI Manual

## Installation
Binary distributions are available for Windows and Linux. All binaries are signed with `minisign`.

## Commands

### `nullwarden init`
Initializes a new vault. Prompts for a master password.
- Enforces zxcvbn score ≥ 3.
- Creates `vault.nwd` in the default data directory.

### `nullwarden add <title> <username> [password]`
Adds a new entry to the vault.
- Prompts for password if not provided as an argument.
- `--notes`: Optional notes for the entry.

### `nullwarden get <title>`
Retrieves an entry. Prompts for the master password.
- Default: Copies password to clipboard (clears after 30s).
- `--print`: Prints password to stdout (NOT RECOMMENDED).

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

### `nullwarden pull`
Downloads the vault from the server.
- Performs integrity check before overwriting local vault.

## Security Considerations
- **Lock by Exit:** The CLI does not persist keys in memory between commands.
- **Keyring:** Session tokens are stored in the OS Keyring (Credential Manager on Windows, Secret Service on Linux).
- **Clipboard:** Retrieved passwords are automatically cleared from the clipboard to prevent exposure.
