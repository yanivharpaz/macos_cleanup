# macOS App Storage Audit

Read-only macOS storage audit tool for installed apps. It finds `.app` bundles and estimates related cache, support, and container data under your user `~/Library` folder.

Nothing in app data is deleted or modified. The script prints summaries and writes CSV files for manual review.

## Requirements

- macOS
- Python 3.8 or newer
- The built-in macOS/BSD `du` command

No third-party Python packages are required.

## Usage

Run the current audit script:

```sh
python3 mac_app_storage_audit_v2.py
```

Common options:

```sh
python3 mac_app_storage_audit_v2.py --top 10
python3 mac_app_storage_audit_v2.py --scan-depth 3
python3 mac_app_storage_audit_v2.py --include-system
python3 mac_app_storage_audit_v2.py --csv-prefix data/mac_storage_audit_v2
```

## Options

| Option | Default | Description |
| --- | --- | --- |
| `--top` | `30` | Number of rows to print in each terminal section. |
| `--scan-depth` | `2` | Directory depth to inspect under cache and support roots. |
| `--include-system` | off | Also scan `/System/Applications` for app bundles. |
| `--csv-prefix` | `mac_storage_audit_v2` | Prefix for generated CSV files. Parent directories are created if needed. |

## Output Files

By default, the script writes:

- `mac_storage_audit_v2_by_app.csv`
- `mac_storage_audit_v2_matched_paths.csv`
- `mac_storage_audit_v2_large_library_dirs_raw.csv`
- `mac_storage_audit_v2_large_library_dirs_specific.csv`

`*_by_app.csv` summarizes app bundle size, cache-like size, support/container size, total related size, candidate counts, ambiguous matches, and matched paths.

`*_matched_paths.csv` lists each matched path with its app, size, match reason, and any other app that matched the same path.

`*_large_library_dirs_raw.csv` lists large scanned Library directories, including parent rollups.

`*_large_library_dirs_specific.csv` filters out likely rollup parents and overlapping paths so the list is easier to inspect manually.

## What Gets Scanned

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

The script also looks for cache-like descendants inside support/container matches so category totals stay useful without double-counting parent and child paths.

## Interpreting Results

Cache-like paths are usually better cleanup candidates, but verify what an app uses before deleting anything.

Be more careful with `Application Support`, `Containers`, and `Group Containers`. These locations can contain important app data, account state, offline files, databases, settings, or project data.

The matching is best-effort. v2 uses exact bundle ID paths and conservative segment matching to reduce false positives, and it flags paths matched by more than one app as ambiguous.

## Tests

Run the unit tests with the standard library test runner:

```sh
python3 -m unittest
```

## License

MIT. See [LICENSE](LICENSE).
