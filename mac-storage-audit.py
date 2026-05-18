#!/usr/bin/env python3
"""
Read-only macOS app storage audit.

Finds installed .app bundles and estimates likely cache/support/container data sizes.
Nothing is deleted or modified.

Outputs:
  - Largest app-matched cache-like data
  - Largest app-matched cache + support/container data
  - Largest installed app bundles
  - Largest Library directories to inspect manually
  - CSV files for sorting/filtering
"""

from __future__ import annotations

import argparse
import csv
import os
import plistlib
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple

HOME = Path.home()
LIB = HOME / "Library"

CACHE_ROOTS = [
    LIB / "Caches",
    LIB / "HTTPStorages",
    LIB / "WebKit",
    LIB / "Logs",
    LIB / "Saved Application State",
]

STATE_ROOTS = [
    LIB / "Application Support",
    LIB / "Containers",
    LIB / "Group Containers",
]

STOPWORDS = {
    "app", "apps", "application", "applications", "desktop", "helper", "launcher",
    "mac", "macos", "osx", "com", "org", "net", "io", "co", "inc", "llc",
    "apple", "software", "technology", "technologies", "the",
}


@dataclass
class AppInfo:
    name: str
    bundle_id: str
    path: Path
    size_kb: int
    executable: str = ""
    candidates: Dict[Path, str] = field(default_factory=dict)


def run_du_kb(path: Path) -> int:
    """Return disk usage from macOS/BSD du in KiB. Returns 0 if inaccessible."""
    try:
        out = subprocess.check_output(
            ["du", "-sk", str(path)],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return int(out.split()[0])
    except Exception:
        return 0


def human(kb: int) -> str:
    if kb <= 0:
        return "0 B"

    units = ["KiB", "MiB", "GiB", "TiB"]
    n = float(kb)

    for unit in units:
        if n < 1024 or unit == units[-1]:
            return f"{n:.1f} {unit}"
        n /= 1024.0

    return f"{n:.1f} TiB"


def norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", s.lower())


def read_info_plist(app: Path) -> Tuple[str, str, str]:
    info = app / "Contents" / "Info.plist"

    name = app.stem
    bundle_id = ""
    executable = ""

    try:
        with info.open("rb") as f:
            pl = plistlib.load(f)

        name = str(pl.get("CFBundleDisplayName") or pl.get("CFBundleName") or app.stem)
        bundle_id = str(pl.get("CFBundleIdentifier", "") or "")
        executable = str(pl.get("CFBundleExecutable", "") or "")
    except Exception:
        pass

    return name, bundle_id, executable


def find_apps(roots: Iterable[Path]) -> List[AppInfo]:
    apps: List[AppInfo] = []
    seen: Set[str] = set()

    for root in roots:
        if not root.exists():
            continue

        for dirpath, dirnames, _filenames in os.walk(root):
            current = Path(dirpath)

            app_names = [d for d in dirnames if d.endswith(".app")]

            for d in app_names:
                app = current / d
                real = str(app.resolve()) if app.exists() else str(app)

                if real in seen:
                    continue

                seen.add(real)

                name, bundle_id, executable = read_info_plist(app)

                apps.append(
                    AppInfo(
                        name=name,
                        bundle_id=bundle_id,
                        executable=executable,
                        path=app,
                        size_kb=run_du_kb(app),
                    )
                )

            # Do not descend into .app bundles.
            dirnames[:] = [d for d in dirnames if not d.endswith(".app")]

    return apps


def app_match_keys(app: AppInfo) -> Set[str]:
    """Normalized names that commonly appear in Library paths."""
    keys: Set[str] = set()

    raw = [app.name, app.path.stem, app.executable]

    if app.bundle_id:
        raw.append(app.bundle_id)

        parts = [
            p for p in app.bundle_id.split(".")
            if p and p.lower() not in STOPWORDS
        ]

        if parts:
            raw.append(parts[-1])

        if len(parts) >= 2:
            raw.append(parts[-2] + parts[-1])

    for r in raw:
        nr = norm(r)
        if len(nr) >= 4:
            keys.add(nr)

    return keys


def exact_candidate_paths(app: AppInfo) -> List[Tuple[Path, str]]:
    paths: List[Tuple[Path, str]] = []

    names = {app.name, app.path.stem, app.executable}
    names = {n for n in names if n}

    if app.bundle_id:
        bid = app.bundle_id

        paths.extend([
            (LIB / "Caches" / bid, "cache-like"),
            (LIB / "HTTPStorages" / bid, "cache-like"),
            (LIB / "WebKit" / bid, "cache-like"),
            (LIB / "Logs" / bid, "cache-like"),
            (LIB / "Saved Application State" / f"{bid}.savedState", "cache-like"),

            (LIB / "Application Support" / bid, "support/container"),

            (LIB / "Containers" / bid / "Data" / "Library" / "Caches", "cache-like"),
            (LIB / "Containers" / bid / "Data" / "Library" / "HTTPStorages", "cache-like"),
            (LIB / "Containers" / bid / "Data" / "Library" / "Application Support", "support/container"),
            (LIB / "Containers" / bid, "support/container"),

            (LIB / "Group Containers" / bid, "support/container"),
        ])

    for n in names:
        paths.extend([
            (LIB / "Caches" / n, "cache-like"),
            (LIB / "Application Support" / n, "support/container"),
            (LIB / "Logs" / n, "cache-like"),
        ])

    return paths


def iter_dirs(root: Path, max_depth: int):
    if not root.exists():
        return

    root_parts = len(root.parts)

    for dirpath, dirnames, _filenames in os.walk(root):
        p = Path(dirpath)
        rel_depth = len(p.parts) - root_parts

        if rel_depth > 0:
            yield p

        if rel_depth >= max_depth:
            dirnames[:] = []


def build_dir_index(max_depth: int):
    """Return path/kind/root/normalized-relative/normalized-leaf."""
    out = []

    for root in CACHE_ROOTS:
        for p in iter_dirs(root, max_depth=max_depth) or []:
            rel = str(p.relative_to(root))
            out.append((p, "cache-like", root, norm(rel), norm(p.name)))

    for root in STATE_ROOTS:
        depth = 1 if root.name in {"Containers", "Group Containers"} else max_depth

        for p in iter_dirs(root, max_depth=depth) or []:
            rel = str(p.relative_to(root))
            out.append((p, "support/container", root, norm(rel), norm(p.name)))

    return out


def add_candidates(apps: List[AppInfo], scan_depth: int) -> None:
    # Exact paths first.
    for app in apps:
        for p, kind in exact_candidate_paths(app):
            if p.exists():
                app.candidates[p] = kind

    # Best-effort fuzzy matching for paths like:
    #   ~/Library/Caches/Google/Chrome
    #   ~/Library/Application Support/Code
    indexed = build_dir_index(scan_depth)

    for app in apps:
        keys = app_match_keys(app)

        if not keys:
            continue

        for p, kind, _root, rel_norm, leaf_norm in indexed:
            matched = False

            for key in keys:
                # Short keys must match exactly to avoid Code -> Xcode false positives.
                if len(key) <= 5:
                    if leaf_norm == key or rel_norm == key:
                        matched = True
                        break
                else:
                    if leaf_norm == key or rel_norm == key or key in rel_norm:
                        matched = True
                        break

            if matched:
                app.candidates[p] = kind


def totals_for(app: AppInfo) -> Tuple[int, int, int]:
    cache_kb = 0
    state_kb = 0

    chosen: List[Tuple[Path, str]] = []

    # Avoid double-counting nested paths within the same app/kind.
    for p, kind in sorted(app.candidates.items(), key=lambda x: len(x[0].parts)):
        if any(str(p).startswith(str(parent) + os.sep) for parent, _ in chosen):
            continue
        chosen.append((p, kind))

    for p, kind in chosen:
        s = run_du_kb(p)

        if kind == "cache-like":
            cache_kb += s
        else:
            state_kb += s

    return app.size_kb, cache_kb, state_kb


def write_csv(path: Path, rows: List[Dict[str, str]]) -> None:
    if not rows:
        return

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def print_table(title: str, headers: List[str], rows: List[List[str]], limit: int) -> None:
    print("\n" + title)
    print("=" * len(title))

    rows = rows[:limit]

    if not rows:
        print("No rows.")
        return

    widths = [len(h) for h in headers]

    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = min(max(widths[i], len(cell)), 56)

    def cut(s: str, w: int) -> str:
        return s if len(s) <= w else s[: max(0, w - 1)] + "…"

    print("  ".join(cut(h, widths[i]).ljust(widths[i]) for i, h in enumerate(headers)))
    print("  ".join("-" * widths[i] for i in range(len(headers))))

    for row in rows:
        print("  ".join(cut(cell, widths[i]).ljust(widths[i]) for i, cell in enumerate(row)))


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only macOS app/cache/support storage audit")
    parser.add_argument("--top", type=int, default=30, help="Rows to print per section")
    parser.add_argument("--scan-depth", type=int, default=2, help="Depth to inspect under Caches/Application Support")
    parser.add_argument("--include-system", action="store_true", help="Also scan /System/Applications")
    parser.add_argument("--csv-prefix", default="mac_storage_audit", help="CSV filename prefix")

    args = parser.parse_args()

    roots = [Path("/Applications"), HOME / "Applications"]

    if args.include_system:
        roots.append(Path("/System/Applications"))

    print("Read-only scan. This may take a few minutes. Nothing will be deleted.\n")

    apps = find_apps(roots)
    add_candidates(apps, scan_depth=args.scan_depth)

    by_app_rows: List[Dict[str, str]] = []

    for app in apps:
        app_kb, cache_kb, state_kb = totals_for(app)
        total_related = cache_kb + state_kb

        if app_kb == 0 and total_related == 0:
            continue

        paths = "; ".join(str(p) for p in sorted(app.candidates.keys())[:5])

        if len(app.candidates) > 5:
            paths += f"; +{len(app.candidates) - 5} more"

        by_app_rows.append({
            "app": app.name,
            "bundle_id": app.bundle_id,
            "app_bundle": human(app_kb),
            "app_bundle_kb": str(app_kb),
            "cache_like": human(cache_kb),
            "cache_like_kb": str(cache_kb),
            "support_container": human(state_kb),
            "support_container_kb": str(state_kb),
            "total_related_kb": str(total_related),
            "path": str(app.path),
            "matched_library_paths": paths,
        })

    by_cache = sorted(by_app_rows, key=lambda r: int(r["cache_like_kb"]), reverse=True)

    printable_by_cache = []
    for r in by_cache:
        if int(r["cache_like_kb"]) <= 0:
            continue

        printable_by_cache.append([
            r["app"],
            r["cache_like"],
            r["support_container"],
            r["app_bundle"],
            r["matched_library_paths"],
        ])

    print_table(
        "Largest app-matched cache-like data",
        ["App", "Cache-like", "Support/container", "App bundle", "Matched paths"],
        printable_by_cache,
        args.top,
    )

    by_state = sorted(by_app_rows, key=lambda r: int(r["total_related_kb"]), reverse=True)

    printable_by_state = []
    for r in by_state:
        if int(r["total_related_kb"]) <= 0:
            continue

        printable_by_state.append([
            r["app"],
            r["cache_like"],
            r["support_container"],
            r["app_bundle"],
            r["matched_library_paths"],
        ])

    print_table(
        "Largest app-matched cache + support/container data",
        ["App", "Cache-like", "Support/container", "App bundle", "Matched paths"],
        printable_by_state,
        args.top,
    )

    by_bundle = sorted(by_app_rows, key=lambda r: int(r["app_bundle_kb"]), reverse=True)

    printable_bundle = [
        [r["app"], r["app_bundle"], r["path"]]
        for r in by_bundle
    ]

    print_table(
        "Largest installed app bundles",
        ["App", "App bundle", "Path"],
        printable_bundle,
        args.top,
    )

    large_dirs: List[Dict[str, str]] = []
    scanned_paths_seen: Set[str] = set()

    for root in CACHE_ROOTS + STATE_ROOTS:
        depth = 1 if root.name in {"Containers", "Group Containers"} else args.scan_depth

        for p in iter_dirs(root, depth) or []:
            sp = str(p)

            if sp in scanned_paths_seen:
                continue

            scanned_paths_seen.add(sp)

            kb = run_du_kb(p)

            if kb <= 0:
                continue

            kind = "cache-like" if root in CACHE_ROOTS else "support/container"

            large_dirs.append({
                "kind": kind,
                "size": human(kb),
                "size_kb": str(kb),
                "path": sp,
            })

    large_dirs.sort(key=lambda r: int(r["size_kb"]), reverse=True)

    printable_dirs = [
        [r["kind"], r["size"], r["path"]]
        for r in large_dirs
    ]

    print_table(
        "Largest Library directories to inspect manually",
        ["Kind", "Size", "Path"],
        printable_dirs,
        args.top,
    )

    prefix = Path(args.csv_prefix)

    write_csv(
        prefix.with_name(prefix.name + "_by_app.csv"),
        sorted(by_app_rows, key=lambda r: int(r["total_related_kb"]), reverse=True),
    )

    write_csv(
        prefix.with_name(prefix.name + "_large_library_dirs.csv"),
        large_dirs,
    )

    print(f"\nCSV written:")
    print(f"  {prefix.name}_by_app.csv")
    print(f"  {prefix.name}_large_library_dirs.csv")
    print("\nNothing was deleted.")

    print(
        "\nInterpretation tip: cache-like paths are usually better cleanup candidates. "
        "Application Support, Containers, and Group Containers can contain important app data."
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())

