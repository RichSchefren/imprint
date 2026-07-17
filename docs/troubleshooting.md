# Troubleshooting

## Installer cannot create a virtual environment

Install a complete Python 3.10 or newer distribution with `venv` and `pip`, then rerun
the same artifact installer. On some Linux distributions, `python3-venv` is a
separate OS package. This is a dependency fix; manually copying source files is
not a durable substitute.

## Hook registration fails

The installer fails closed and leaves a timestamped settings backup. Validate
that the settings file is JSON and that its `hooks` value is an object whose
event values are lists. Restore the latest backup if another tool wrote invalid
JSON, correct that writer, and rerun the installer.

## Health is degraded

Read the structured status and counts. Missing config, denied filesystem access,
corrupt spool inputs, a disabled compiler, or database integrity failure require
different fixes. Health reports never include captured text. Preserve corrupt
inputs and the database before repair.

## Cloud-sync root refused

Move the data root to a local non-synchronized directory and update config. A
manual bypass would reintroduce concurrent-writer and partial-sync corruption;
the permanent fix is to keep the canonical database local and move immutable
exchange artifacts separately.
