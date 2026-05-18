# macOS Storage Audit

Read-only macOS app storage audit tool. It finds installed `.app` bundles and estimates related cache, support, and container data under your user `~/Library` folder.

Nothing is deleted or modified. The script prints sortable summaries and writes CSV files so you can decide what to inspect or clean up manually.

## What It Reports

- Largest app-matched cache-like data
- Largest app-matched cache plus support/container data
- Largest installed app bundles
- Largest `~/Library` directories to inspect manually
- CSV output for spreadsheet filtering and sorting

Cache-like locations include:

- `~/Library/Caches`
- `~/Library/HTTPStorages`
- `~/Library/WebKit`
- `~/Library/Logs`
- `~/Library/Saved Application State`

Support/container locations include:

- `~/Library/Application Support`
- `~/Library/Containers`
- `~/Library/Group Containers`

## Requirements

- macOS
- Python 3.8 or newer
- The built-in macOS/BSD `du` command

No third-party Python packages are required.

## Installation

Clone or download this repository, then optionally create a virtual environment:

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

The `pip install` step is effectively a no-op today because the script only uses the Python standard library.

## Usage

Run the audit:

```sh
python3 mac-storage-audit.py
```

Show fewer rows per section:

```sh
python3 mac-storage-audit.py --top 10
```

Scan deeper under cache and Application Support directories:

```sh
python3 mac-storage-audit.py --scan-depth 3
```

Include `/System/Applications` in the app bundle scan:

```sh
python3 mac-storage-audit.py --include-system
```

Choose a custom CSV filename prefix:

```sh
python3 mac-storage-audit.py --csv-prefix my_audit
```

This writes:

- `my_audit_by_app.csv`
- `my_audit_large_library_dirs.csv`

## Options

| Option | Default | Description |
| --- | --- | --- |
| `--top` | `30` | Number of rows to print in each terminal section. |
| `--scan-depth` | `2` | Directory depth to inspect under cache and support roots. |
| `--include-system` | off | Also scan `/System/Applications` for app bundles. |
| `--csv-prefix` | `mac_storage_audit` | Prefix for generated CSV files. |

## Output Files

By default, the script writes:

- `mac_storage_audit_by_app.csv`
- `mac_storage_audit_large_library_dirs.csv`

The app CSV includes app name, bundle ID, app bundle size, cache-like size, support/container size, total related size, installed app path, and matched Library paths.

The Library directory CSV lists large cache-like and support/container directories found during the scan.

## Interpreting Results

Cache-like paths are usually better cleanup candidates, but you should still verify what an app uses before deleting anything.

Be more careful with `Application Support`, `Containers`, and `Group Containers`. These locations can contain important app data, account state, offline files, databases, settings, or project data.

The matching is best-effort. The script combines exact bundle ID paths with fuzzy matching for common Library directory names, so review the matched paths before acting on the results.

## License

MIT. See [LICENSE](LICENSE).
