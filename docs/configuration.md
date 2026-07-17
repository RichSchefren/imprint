# Configuration

The default config is `~/.config/imprint/config.json` on macOS/Linux and
`%APPDATA%\Imprint\config.json` on Windows. Set `IMPRINT_CONFIG` to use a
different file. The installer merges its required values into an existing JSON
object and preserves unknown namespaced extensions.

## Fields

- `config_version`: configuration contract version. `3.1.1` is current;
  `3.0.0` is accepted and upcast in memory without rewriting the file.
- `data_root`: absolute, local directory above all operator directories.
- `operator_slug`: lowercase letters, digits, and hyphens; default `default`.
- `node_id`: this machine's spool identity; default `primary`.
- `compiler`: only one node may be `true` for a shared logical Imprint.
- `context_budget_bytes`: 4,096–131,072. The tested/default value is 32,768.
  Values above 32,768 require `allow_higher_budget: true`.
- `spool_retention_days`: 1–36,500; default 30. Pruning is never automatic and
  deletes only this configured `node_id`'s hash-verified, acknowledged inputs.
- `domains`: optional closed array of domain packs. Each pack declares a safe
  `domain_id`, `public_label`, optional `safe_paths`, optional `keywords`, and
  `frozen`. Selection order is explicit ID, longest safe path, then keyword.
  Ties inject no domain; domain retrieval is delivered once per session and
  snapshot and never repeats the core/general session-start payload.

The former `experimental.digest` and `experimental.profile_learning` flags were
removed because no shipped runtime implemented them. Legacy configs containing
only `false` values are accepted and discarded during in-memory upcast; enabled,
unknown, or malformed former flags fail validation truthfully.

The release artifact includes `config.example.json`. Replace its placeholder
absolute path before using it.

## Environment overrides

- `IMPRINT_CONFIG`: config path.
- `IMPRINT_DATA_ROOT`: default data root used when config omits `data_root`.
- `IMPRINT_INSTALL_ROOT`: installer/application destination.
- `CLAUDE_SETTINGS_PATH`: Claude Code settings path used by installers.
- `XDG_CONFIG_HOME` and `XDG_DATA_HOME`: respected on POSIX systems.

## Multi-operator and multi-node use

Each operator gets a separate directory and canonical database. Do not point two
operators at the same slug. Multiple machines may emit immutable per-node spool
files, but exactly one configured compiler may consume them. Do not place the
canonical SQLite database in Dropbox, OneDrive, Google Drive, iCloud Drive, an
NFS share, or another synchronized/shared-writer location.

## Hook registration

The installer edits only `hooks.SessionStart`, `hooks.UserPromptSubmit`, and
`hooks.Stop`. Before every edit it creates a timestamped settings backup. Managed
entries contain `imprint-local-managed-hook`; reinstall first removes those
entries, then adds one copy of each intended hook. Unrelated entries are retained.
