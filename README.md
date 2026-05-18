# macOS App Storage Audit

Read-only macOS storage audit tool for installed apps, with an optional Dropbox-focused scan. It finds `.app` bundles and estimates related cache, support, and container data under your user `~/Library` folder.

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
python3 mac_app_storage_audit_v2.py --dropbox
python3 mac_app_storage_audit_v2.py --dropbox-only
```

## Options

| Option | Default | Description |
| --- | --- | --- |
| `--top` | `30` | Number of rows to print in each terminal section. |
| `--scan-depth` | `2` | Directory depth to inspect under cache and support roots. |
| `--include-system` | off | Also scan `/System/Applications` for app bundles. |
| `--csv-prefix` | `mac_storage_audit_v2` | Prefix for generated CSV files. Parent directories are created if needed. |
| `--dropbox` | off | Run the app audit, then run the Dropbox-specific scan. |
| `--dropbox-only` | off | Skip the general app audit and run only the Dropbox-specific scan. |
| `--dropbox-search-volumes` | off | Also look one level under `/Volumes` for Dropbox roots. |
| `--dropbox-deep-discovery` | off | Run a slower best-effort search for Dropbox-named paths. |
| `--dropbox-discovery-depth` | `5` | Max depth for Dropbox deep discovery. |
| `--dropbox-top-children` | `40` | Top children to list per Dropbox root/cache root; use `0` to disable. |
| `--dropbox-local-inventory` | off | Walk Dropbox roots/cache roots and write local-file inventory CSVs based on allocated disk blocks. |
| `--dropbox-min-local-kb` | `1024` | Minimum allocated KiB for rows in `*_dropbox_local_files.csv`; use `0` for every local file occupying blocks. |
| `--dropbox-inventory-depth` | `2` | Directory depth to include in `*_dropbox_local_dirs.csv`; files are still scanned recursively. |

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

When Dropbox scanning is enabled, the script also writes:

- `*_dropbox_locations.csv`
- `*_dropbox_top_children.csv`
- `*_dropbox_local_dirs.csv` when `--dropbox-local-inventory` is enabled
- `*_dropbox_local_files.csv` when `--dropbox-local-inventory` is enabled

The Dropbox scan looks for modern File Provider roots, legacy Dropbox roots, `.dropbox.cache`, known app cache/support locations, and Dropbox-named Library paths. The local inventory reports allocated blocks so online-only placeholder files are not mistaken for fully local files.

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

For Dropbox results, prefer Dropbox controls such as make-online-only or selective sync for `sync-root-local-files`. Treat `legacy-sync-cache` and `file-provider-cache` as the most cache-like categories. Do not blindly delete `app-support`, `metadata/support`, or `container/group-container` paths because they may contain account state, databases, or File Provider state.

## Tests

Run the unit tests with the standard library test runner:

```sh
python3 -m unittest
```

## License

MIT. See [LICENSE](LICENSE).
