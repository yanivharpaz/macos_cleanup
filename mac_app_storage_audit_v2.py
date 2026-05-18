#!/usr/bin/env python3
"""
Read-only macOS app storage audit, v2.

Finds installed .app bundles and estimates associated cache/support/container data.
Nothing is deleted or modified.

v2 changes vs the original draft:
  - Avoids broad substring fuzzy matching that caused cross-app false positives.
  - Flags shared/ambiguous paths that match more than one app.
  - Handles parent/child paths without double-counting total size.
  - Estimates cache-like children inside Application Support / Containers separately.
  - Adds raw and more-specific large Library directory CSVs.
  - Caches du results so repeated size lookups are faster.
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
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple

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

ALL_LIBRARY_ROOTS = CACHE_ROOTS + STATE_ROOTS

STOPWORDS = {
    "app", "apps", "application", "applications", "desktop", "helper", "launcher",
    "mac", "macos", "osx", "com", "org", "net", "io", "co", "inc", "llc",
    "apple", "software", "technology", "technologies", "the", "company",
    "electron", "browser", "thebrowser", "updater", "update", "shipit",
}

CACHEY_LEAF_PATTERNS = [
    "cache", "caches", "cached", "codecache", "gpucache", "shadercache",
    "dawngraphitecache", "dawnwebgpucache", "httpstorages", "webkit",
    "logs", "crashpad", "crashreports",
]


def is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", s.lower())


def split_words(s: str) -> List[str]:
    return [x for x in re.split(r"[^A-Za-z0-9]+", s) if x]


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


class SizeCache:
    def __init__(self) -> None:
        self._cache: Dict[str, int] = {}
        self.errors: Dict[str, str] = {}

    def du_kb(self, path: Path) -> int:
        key = str(path)
        if key in self._cache:
            return self._cache[key]
        try:
            out = subprocess.check_output(
                ["du", "-sk", str(path)],
                stderr=subprocess.PIPE,
                text=True,
            )
            kb = int(out.split()[0])
        except Exception as exc:
            kb = 0
            self.errors[key] = str(exc)
        self._cache[key] = kb
        return kb


SIZE_CACHE = SizeCache()


@dataclass
class PathCandidate:
    path: Path
    kind: str  # "cache-like" or "support/container"
    reason: str


@dataclass
class AppInfo:
    name: str
    bundle_id: str
    path: Path
    size_kb: int
    executable: str = ""
    candidates: Dict[Path, PathCandidate] = field(default_factory=dict)


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
                apps.append(AppInfo(name, bundle_id, app, SIZE_CACHE.du_kb(app), executable))
            # Never descend into .app bundles.
            dirnames[:] = [d for d in dirnames if not d.endswith(".app")]
    return apps


def library_root_for(path: Path) -> Optional[Path]:
    for root in ALL_LIBRARY_ROOTS:
        if root == path or is_relative_to(path, root):
            return root
    return None


def is_cachey_leaf(path: Path) -> bool:
    leaf = norm(path.name)
    if not leaf:
        return False
    return any(pat in leaf for pat in CACHEY_LEAF_PATTERNS)


def kind_for_path(path: Path) -> str:
    root = library_root_for(path)
    if root in CACHE_ROOTS:
        return "cache-like"
    # Sandboxed apps often put these under Containers/<bundle>/Data/Library/...
    lowered_parts = {part.lower() for part in path.parts}
    if {"caches", "httpstorages", "webkit", "logs"} & lowered_parts:
        return "cache-like"
    if is_cachey_leaf(path):
        return "cache-like"
    return "support/container"


def add_candidate(app: AppInfo, path: Path, reason: str) -> None:
    if not path.exists():
        return
    app.candidates[path] = PathCandidate(path, kind_for_path(path), reason)


def app_display_names(app: AppInfo) -> Set[str]:
    names = {app.name, app.path.stem, app.executable}
    return {n.strip() for n in names if n and n.strip()}


def name_variant_paths(root: Path, name: str) -> Iterator[Path]:
    # Direct: "Google Chrome" -> root/"Google Chrome"
    yield root / name

    # Common vendor/product split: "Google Chrome" -> root/Google/Chrome
    words = split_words(name)
    if len(words) >= 2:
        yield root / words[0] / " ".join(words[1:])
        # Common updater layout: "Microsoft Edge" -> Microsoft/EdgeUpdater.
        yield root / words[0] / f"{words[1]}Updater"

    # Common hyphenated leaf: "Brave Browser" -> root/Brave-Browser
    if len(words) >= 2:
        yield root / "-".join(words)


def exact_candidate_paths(app: AppInfo) -> Iterator[Tuple[Path, str]]:
    bid = app.bundle_id

    if bid:
        yield LIB / "Caches" / bid, "bundle-id cache"
        # Common macOS updater cache conventions. These were intentionally exact
        # additions, replacing the broad substring match used by v1.
        yield LIB / "Caches" / f"{bid}.ShipIt", "bundle-id updater cache"
        yield LIB / "Caches" / f"{bid}.Updater", "bundle-id updater cache"
        yield LIB / "Caches" / f"{bid}.updater", "bundle-id updater cache"
        yield LIB / "HTTPStorages" / bid, "bundle-id http storage"
        yield LIB / "WebKit" / bid, "bundle-id webkit"
        yield LIB / "Logs" / bid, "bundle-id logs"
        yield LIB / "Saved Application State" / f"{bid}.savedState", "bundle-id saved state"
        yield LIB / "Application Support" / bid, "bundle-id support"
        yield LIB / "Containers" / bid, "bundle-id container"
        yield LIB / "Containers" / bid / "Data" / "Library" / "Caches", "container cache"
        yield LIB / "Containers" / bid / "Data" / "Library" / "HTTPStorages", "container http storage"
        yield LIB / "Containers" / bid / "Data" / "Library" / "Application Support", "container app support"
        yield LIB / "Group Containers" / bid, "bundle-id group container"

    for name in app_display_names(app):
        for root in [LIB / "Caches", LIB / "Application Support", LIB / "Logs"]:
            for p in name_variant_paths(root, name):
                yield p, "app-name exact"


def match_keys(app: AppInfo) -> Set[str]:
    keys: Set[str] = set()

    for name in app_display_names(app):
        n = norm(name)
        if n and n not in STOPWORDS:
            keys.add(n)

    if app.bundle_id:
        parts = [p for p in app.bundle_id.split(".") if p]
        filtered = [p for p in parts if norm(p) not in STOPWORDS]
        # Useful for com.google.Chrome -> googlechrome, com.microsoft.edgemac -> microsoftedgemac.
        for span in (2, 3):
            if len(filtered) >= span:
                joined = norm("".join(filtered[-span:]))
                if joined and joined not in STOPWORDS:
                    keys.add(joined)
        # Useful for io.rancherdesktop.app -> rancherdesktop.
        if filtered:
            last = norm(filtered[-1])
            if len(last) >= 3 and last not in STOPWORDS:
                keys.add(last)

    return keys


@dataclass
class DirIndexEntry:
    path: Path
    root: Path
    rel_norm: str
    leaf_norm: str
    first2_norm: str
    depth: int


def iter_dirs(root: Path, max_depth: int) -> Iterator[Path]:
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


def build_dir_index(scan_depth: int) -> List[DirIndexEntry]:
    entries: List[DirIndexEntry] = []
    for root in ALL_LIBRARY_ROOTS:
        if root.name in {"Containers", "Group Containers"}:
            depth_limit = 1
        else:
            depth_limit = scan_depth
        for p in iter_dirs(root, depth_limit):
            rel = p.relative_to(root)
            parts = list(rel.parts)
            first2 = "".join(parts[:2]) if len(parts) >= 2 else "".join(parts)
            entries.append(
                DirIndexEntry(
                    path=p,
                    root=root,
                    rel_norm=norm(str(rel)),
                    leaf_norm=norm(p.name),
                    first2_norm=norm(first2),
                    depth=len(parts),
                )
            )
    return entries


def entry_matches_app(entry: DirIndexEntry, keys: Set[str]) -> bool:
    if not keys:
        return False
    # Deliberately exact/boundary-like matching only. No broad `key in rel` substring.
    return (
        entry.rel_norm in keys
        or entry.leaf_norm in keys
        or entry.first2_norm in keys
    )


def add_candidates(apps: List[AppInfo], scan_depth: int) -> None:
    for app in apps:
        for p, reason in exact_candidate_paths(app):
            add_candidate(app, p, reason)

    indexed = build_dir_index(scan_depth)
    for app in apps:
        keys = match_keys(app)
        for entry in indexed:
            if entry_matches_app(entry, keys):
                add_candidate(app, entry.path, "safe fuzzy exact/segment match")


def non_nested(paths: Iterable[Path]) -> List[Path]:
    selected: List[Path] = []
    for p in sorted(set(paths), key=lambda x: len(x.parts)):
        if any(is_relative_to(p, parent) and p != parent for parent in selected):
            continue
        selected.append(p)
    return selected


def cache_like_descendants(parent: Path, max_depth: int = 2) -> List[Path]:
    if not parent.exists() or not parent.is_dir():
        return []
    root_parts = len(parent.parts)
    found: List[Path] = []
    for dirpath, dirnames, _filenames in os.walk(parent):
        p = Path(dirpath)
        depth = len(p.parts) - root_parts
        if depth > 0 and kind_for_path(p) == "cache-like":
            found.append(p)
            # If this path is cache-like, deeper children are already included in its du.
            dirnames[:] = []
            continue
        if depth >= max_depth:
            dirnames[:] = []
    return non_nested(found)


def summarize_app_paths(app: AppInfo) -> Tuple[int, int, List[Tuple[Path, str, int, str]]]:
    """Return cache_kb, support_kb, selected path details.

    Parent paths are counted once for total size. If a support/container parent has
    cache-like descendants, those descendants are estimated separately and subtracted
    from support for category reporting. Total related size remains non-overlapping.
    """
    selected_parents = non_nested(app.candidates.keys())
    details: List[Tuple[Path, str, int, str]] = []
    cache_kb = 0
    support_kb = 0

    for parent in selected_parents:
        cand = app.candidates[parent]
        parent_kb = SIZE_CACHE.du_kb(parent)
        if parent_kb <= 0:
            continue

        if cand.kind == "cache-like":
            cache_kb += parent_kb
            details.append((parent, "cache-like", parent_kb, cand.reason))
            continue

        child_caches = cache_like_descendants(parent, max_depth=2)
        child_cache_kb = 0
        for child in child_caches:
            kb = SIZE_CACHE.du_kb(child)
            if kb <= 0:
                continue
            child_cache_kb += kb
            details.append((child, "cache-like-inside-support", kb, "cache-like descendant"))

        # Keep total non-overlapping. du block accounting can make child sums slightly
        # larger than parent in rare cases, so clamp residual at zero.
        residual_support = max(0, parent_kb - child_cache_kb)
        support_kb += residual_support
        cache_kb += min(child_cache_kb, parent_kb)
        details.append((parent, "support/container", residual_support, cand.reason))

    details.sort(key=lambda x: x[2], reverse=True)
    return cache_kb, support_kb, details


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
            widths[i] = min(max(widths[i], len(cell)), 62)

    def cut(s: str, w: int) -> str:
        return s if len(s) <= w else s[: max(0, w - 1)] + "..."

    print("  ".join(cut(h, widths[i]).ljust(widths[i]) for i, h in enumerate(headers)))
    print("  ".join("-" * widths[i] for i in range(len(headers))))
    for row in rows:
        print("  ".join(cut(cell, widths[i]).ljust(widths[i]) for i, cell in enumerate(row)))


def build_large_dir_rows(scan_depth: int) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    raw: List[Dict[str, str]] = []

    for root in ALL_LIBRARY_ROOTS:
        if root.name in {"Containers", "Group Containers"}:
            depth_limit = 1
        else:
            depth_limit = scan_depth
        for p in iter_dirs(root, depth_limit):
            kb = SIZE_CACHE.du_kb(p)
            if kb <= 0:
                continue
            rel = p.relative_to(root)
            row = {
                "kind": kind_for_path(p),
                "size": human(kb),
                "size_kb": str(kb),
                "root": str(root),
                "depth": str(len(rel.parts)),
                "path": str(p),
                "nested_under": "",
                "rollup_parent": "false",
            }
            raw.append(row)

    raw.sort(key=lambda r: int(r["size_kb"]), reverse=True)

    paths = [Path(r["path"]) for r in raw]
    size_by_path = {r["path"]: int(r["size_kb"]) for r in raw}

    for r in raw:
        p = Path(r["path"])
        ancestors = [a for a in paths if a != p and is_relative_to(p, a)]
        if ancestors:
            nearest = max(ancestors, key=lambda a: len(a.parts))
            r["nested_under"] = str(nearest)

        children = [c for c in paths if c != p and is_relative_to(c, p) and len(c.parts) == len(p.parts) + 1]
        if children:
            child_sum = sum(size_by_path.get(str(c), 0) for c in children)
            parent_size = int(r["size_kb"])
            if parent_size > 0 and child_sum / parent_size >= 0.75:
                r["rollup_parent"] = "true"

    specific_candidates = [r for r in raw if r["rollup_parent"] != "true"]
    specific: List[Dict[str, str]] = []
    selected_paths: List[Path] = []
    for r in sorted(specific_candidates, key=lambda x: int(x["size_kb"]), reverse=True):
        p = Path(r["path"])
        if any(is_relative_to(p, s) or is_relative_to(s, p) for s in selected_paths):
            continue
        specific.append(r.copy())
        selected_paths.append(p)

    specific.sort(key=lambda r: int(r["size_kb"]), reverse=True)
    return raw, specific


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only macOS app/cache/support storage audit v2")
    parser.add_argument("--top", type=int, default=30, help="Rows to print per section")
    parser.add_argument("--scan-depth", type=int, default=2, help="Depth to inspect under Caches/Application Support")
    parser.add_argument("--include-system", action="store_true", help="Also scan /System/Applications")
    parser.add_argument("--csv-prefix", default="mac_storage_audit_v2", help="CSV filename prefix")
    args = parser.parse_args()

    roots = [Path("/Applications"), HOME / "Applications"]
    if args.include_system:
        roots.append(Path("/System/Applications"))

    print("Read-only scan. Nothing will be deleted.\n")

    apps = find_apps(roots)
    add_candidates(apps, scan_depth=args.scan_depth)

    # Detect ambiguous/shared matched paths after safer matching.
    path_to_apps: Dict[Path, List[str]] = {}
    for app in apps:
        for p in app.candidates:
            path_to_apps.setdefault(p, []).append(app.name)

    by_app_rows: List[Dict[str, str]] = []
    path_rows: List[Dict[str, str]] = []

    for app in apps:
        cache_kb, support_kb, details = summarize_app_paths(app)
        total_related = cache_kb + support_kb
        if app.size_kb == 0 and total_related == 0:
            continue

        ambiguous = [str(p) for p in app.candidates if len(path_to_apps.get(p, [])) > 1]
        matched_preview = "; ".join(str(p) for p, _kind, _kb, _reason in details[:8])
        if len(details) > 8:
            matched_preview += f"; +{len(details) - 8} more"

        by_app_rows.append({
            "app": app.name,
            "bundle_id": app.bundle_id,
            "app_bundle": human(app.size_kb),
            "app_bundle_kb": str(app.size_kb),
            "cache_like": human(cache_kb),
            "cache_like_kb": str(cache_kb),
            "support_container": human(support_kb),
            "support_container_kb": str(support_kb),
            "total_related": human(total_related),
            "total_related_kb": str(total_related),
            "candidate_count": str(len(app.candidates)),
            "ambiguous_path_count": str(len(ambiguous)),
            "ambiguous_paths": "; ".join(ambiguous[:10]),
            "path": str(app.path),
            "matched_library_paths": matched_preview,
        })

        for p, kind, kb, reason in details:
            path_rows.append({
                "app": app.name,
                "bundle_id": app.bundle_id,
                "kind": kind,
                "size": human(kb),
                "size_kb": str(kb),
                "reason": reason,
                "path": str(p),
                "also_matched_by": ", ".join(x for x in path_to_apps.get(p, []) if x != app.name),
            })

    by_app_rows.sort(key=lambda r: int(r["total_related_kb"]), reverse=True)
    path_rows.sort(key=lambda r: int(r["size_kb"]), reverse=True)

    cache_rows = [r for r in sorted(by_app_rows, key=lambda r: int(r["cache_like_kb"]), reverse=True) if int(r["cache_like_kb"]) > 0]
    print_table(
        "Largest app-matched cache-like data",
        ["App", "Cache-like", "Support/container", "Ambig", "Matched paths"],
        [[r["app"], r["cache_like"], r["support_container"], r["ambiguous_path_count"], r["matched_library_paths"]] for r in cache_rows],
        args.top,
    )

    print_table(
        "Largest app-matched cache + support/container data",
        ["App", "Cache-like", "Support/container", "Total", "Ambig", "Matched paths"],
        [[r["app"], r["cache_like"], r["support_container"], r["total_related"], r["ambiguous_path_count"], r["matched_library_paths"]] for r in by_app_rows if int(r["total_related_kb"]) > 0],
        args.top,
    )

    print_table(
        "Largest installed app bundles",
        ["App", "App bundle", "Path"],
        [[r["app"], r["app_bundle"], r["path"]] for r in sorted(by_app_rows, key=lambda r: int(r["app_bundle_kb"]), reverse=True)],
        args.top,
    )

    raw_dirs, specific_dirs = build_large_dir_rows(scan_depth=args.scan_depth)

    print_table(
        "Largest specific Library directories to inspect manually",
        ["Kind", "Size", "Path"],
        [[r["kind"], r["size"], r["path"]] for r in specific_dirs],
        args.top,
    )

    prefix = Path(args.csv_prefix)
    write_csv(prefix.with_name(prefix.name + "_by_app.csv"), by_app_rows)
    write_csv(prefix.with_name(prefix.name + "_matched_paths.csv"), path_rows)
    write_csv(prefix.with_name(prefix.name + "_large_library_dirs_raw.csv"), raw_dirs)
    write_csv(prefix.with_name(prefix.name + "_large_library_dirs_specific.csv"), specific_dirs)

    print("\nCSV written:")
    print(f"  {prefix.name}_by_app.csv")
    print(f"  {prefix.name}_matched_paths.csv")
    print(f"  {prefix.name}_large_library_dirs_raw.csv")
    print(f"  {prefix.name}_large_library_dirs_specific.csv")
    if SIZE_CACHE.errors:
        print(f"\nSome paths could not be sized: {len(SIZE_CACHE.errors)}. This is usually permissions-related.")
    print("\nNothing was deleted.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
