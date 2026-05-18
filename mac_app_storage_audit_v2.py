#!/usr/bin/env python3
"""
Read-only macOS app storage audit with optional Dropbox-focused scan.

Finds installed .app bundles and estimates associated cache/support/container data.
Nothing is deleted or modified.

Changes vs the original draft:
  - Avoids broad substring fuzzy matching that caused cross-app false positives.
  - Flags shared/ambiguous paths that match more than one app.
  - Handles parent/child paths without double-counting total size.
  - Estimates cache-like children inside Application Support / Containers separately.
  - Adds raw and more-specific large Library directory CSVs.
  - Caches du results so repeated size lookups are faster.
  - Adds a Dropbox-specific File Provider / legacy root / cache locator.
"""

from __future__ import annotations

import argparse
import base64
import csv
import heapq
import json
import os
import plistlib
import re
import stat
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

CACHE_DESCENDANT_SCAN_DEPTH = 5

BY_APP_FIELDS = [
    "app",
    "bundle_id",
    "app_bundle",
    "app_bundle_kb",
    "cache_like",
    "cache_like_kb",
    "support_container",
    "support_container_kb",
    "total_related",
    "total_related_kb",
    "candidate_count",
    "ambiguous_path_count",
    "ambiguous_paths",
    "path",
    "matched_library_paths",
]

MATCHED_PATH_FIELDS = [
    "app",
    "bundle_id",
    "kind",
    "size",
    "size_kb",
    "reason",
    "path",
    "also_matched_by",
]

LARGE_DIR_FIELDS = [
    "kind",
    "size",
    "size_kb",
    "root",
    "depth",
    "path",
    "nested_under",
    "rollup_parent",
]

DROPBOX_NAME_TERMS = ("dropbox", "getdropbox")
DROPBOX_FILE_PROVIDER_SYNC_SUFFIX = ".com.getdropbox.dropbox.sync"

DROPBOX_LOCATION_FIELDS = [
    "category",
    "size",
    "size_kb",
    "cleanup_risk",
    "source",
    "nested_under",
    "path",
    "notes",
]

DROPBOX_TOP_CHILD_FIELDS = [
    "root_category",
    "root_path",
    "size",
    "size_kb",
    "path",
    "notes",
]

DROPBOX_LOCAL_FILE_FIELDS = [
    "root_category",
    "root_path",
    "allocated",
    "allocated_kb",
    "logical",
    "logical_bytes",
    "kind",
    "path",
]

DROPBOX_LOCAL_DIR_FIELDS = [
    "root_category",
    "root_path",
    "allocated",
    "allocated_kb",
    "logical",
    "logical_bytes",
    "file_count",
    "local_file_count",
    "zero_block_file_count",
    "depth",
    "path",
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

        child_caches = cache_like_descendants(parent, max_depth=CACHE_DESCENDANT_SCAN_DEPTH)
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


def write_csv(path: Path, rows: List[Dict[str, str]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_csv_fields(path: Path, fieldnames: List[str], rows: Iterable[Dict[str, str]]) -> None:
    write_csv(path, list(rows), fieldnames)


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


@dataclass
class DropboxLocation:
    path: Path
    category: str
    cleanup_risk: str
    source: str
    notes: str = ""


def safe_iterdir(path: Path) -> List[Path]:
    try:
        return list(path.iterdir())
    except Exception:
        return []


def path_name_has_dropbox(path: Path) -> bool:
    lowered = path.name.lower()
    return any(term in lowered for term in DROPBOX_NAME_TERMS)


def add_dropbox_location(
    locations: Dict[str, DropboxLocation],
    path: Path,
    category: str,
    cleanup_risk: str,
    source: str,
    notes: str = "",
) -> None:
    path = Path(os.path.expanduser(str(path)))
    try:
        exists = path.exists()
    except Exception:
        exists = False
    if not exists:
        return

    key = str(path)
    if key not in locations:
        locations[key] = DropboxLocation(path, category, cleanup_risk, source, notes)
        return

    old = locations[key]
    sources: List[str] = []
    for item in [old.source, source]:
        if item and item not in sources:
            sources.append(item)

    notes_items: List[str] = []
    for item in [old.notes, notes]:
        if item and item not in notes_items:
            notes_items.append(item)

    # Preserve the first category/risk so known exact classifications win.
    locations[key] = DropboxLocation(
        old.path,
        old.category,
        old.cleanup_risk,
        "; ".join(sources),
        "; ".join(notes_items),
    )


def dropbox_roots_from_info_json(locations: Dict[str, DropboxLocation]) -> List[Path]:
    roots: List[Path] = []
    info_path = HOME / ".dropbox" / "info.json"
    if not info_path.exists():
        return roots

    try:
        with info_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        add_dropbox_location(
            locations,
            info_path,
            "metadata/support",
            "Do not delete blindly; contains Dropbox account/link metadata.",
            "~/.dropbox/info.json could not be parsed",
            f"parse error: {exc}",
        )
        return roots

    if not isinstance(data, dict):
        return roots

    for account_name, details in data.items():
        if not isinstance(details, dict):
            continue
        for key in ("path", "dropbox_path", "directory"):
            value = details.get(key)
            if isinstance(value, str) and value.strip():
                root = Path(value).expanduser()
                if root.exists():
                    roots.append(root)
                    add_dropbox_location(
                        locations,
                        root,
                        "sync-root-local-files",
                        "Use Dropbox make-online-only/selective sync or app settings; do not delete the root directly.",
                        f"Dropbox metadata {info_path} account={account_name} key={key}",
                        "Disk usage here is local space used by synced/offline files plus Dropbox metadata under the root.",
                    )
    return roots


def decode_legacy_host_db_path(line: str) -> Optional[Path]:
    raw = line.strip()
    if not raw:
        return None

    for padded in [raw, raw + "=", raw + "==", raw + "==="]:
        try:
            decoded = base64.b64decode(padded, validate=False).decode("utf-8", "ignore").strip()
        except Exception:
            continue
        if decoded.startswith("/") or decoded.startswith("~"):
            return Path(decoded).expanduser()

    return None


def dropbox_roots_from_legacy_host_db(locations: Dict[str, DropboxLocation]) -> List[Path]:
    roots: List[Path] = []
    candidates = [
        HOME / ".dropbox" / "host.db",
        LIB / "Application Support" / "Dropbox" / "host.db",
    ]

    for host_db in candidates:
        if not host_db.exists():
            continue

        add_dropbox_location(
            locations,
            host_db,
            "metadata/support",
            "Do not delete blindly; contains Dropbox account/link metadata.",
            "legacy host.db metadata file",
            "Used by older Dropbox installs to remember the Dropbox root.",
        )

        try:
            lines = host_db.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            continue

        for line in lines:
            root = decode_legacy_host_db_path(line)
            if root is not None and root.exists() and root.is_dir() and root not in roots:
                roots.append(root)
                add_dropbox_location(
                    locations,
                    root,
                    "sync-root-local-files",
                    "Use Dropbox make-online-only/selective sync or app settings; do not delete the root directly.",
                    f"Dropbox legacy host.db {host_db}",
                    "Disk usage here is local space used by synced/offline files plus Dropbox metadata under the root.",
                )

    return roots


def add_dropbox_sync_roots(locations: Dict[str, DropboxLocation], search_volumes: bool) -> List[Path]:
    roots: List[Path] = []

    for root in dropbox_roots_from_info_json(locations):
        if root not in roots:
            roots.append(root)

    for root in dropbox_roots_from_legacy_host_db(locations):
        if root not in roots:
            roots.append(root)

    cloud_storage = LIB / "CloudStorage"
    for child in safe_iterdir(cloud_storage):
        if child.is_dir() and path_name_has_dropbox(child):
            add_dropbox_location(
                locations,
                child,
                "sync-root-local-files",
                "Use Dropbox make-online-only/selective sync or app settings; do not delete the root directly.",
                "Dropbox folder discovered under ~/Library/CloudStorage",
                "Dropbox File Provider roots normally live under ~/Library/CloudStorage on current macOS.",
            )
            if child not in roots:
                roots.append(child)

    for child in safe_iterdir(HOME):
        if not child.is_dir():
            continue
        if child.name.startswith("."):
            continue
        lower = child.name.lower()
        if "dropbox" in lower or lower.endswith(" dropbox"):
            add_dropbox_location(
                locations,
                child,
                "sync-root-local-files",
                "Use Dropbox make-online-only/selective sync or app settings; do not delete the root directly.",
                "Dropbox-like folder discovered directly under home",
                "This catches legacy roots such as ~/Dropbox, ~/Dropbox (Personal), and team folders.",
            )
            if child not in roots:
                roots.append(child)

    if search_volumes:
        volumes = Path("/Volumes")
        for volume in safe_iterdir(volumes):
            if not volume.is_dir():
                continue
            for child in safe_iterdir(volume):
                if child.is_dir() and path_name_has_dropbox(child):
                    add_dropbox_location(
                        locations,
                        child,
                        "sync-root-local-files",
                        "Use Dropbox make-online-only/selective sync or app settings; do not delete the root directly.",
                        "Dropbox-like folder discovered one level below /Volumes",
                        "Useful for File Provider external-drive or older moved Dropbox folders.",
                    )
                    if child not in roots:
                        roots.append(child)

    for root in list(roots):
        add_dropbox_location(
            locations,
            root / ".dropbox.cache",
            "legacy-sync-cache",
            "Cache-like; quit Dropbox before clearing. Prefer Dropbox's own cache-clear instructions.",
            "Hidden .dropbox.cache inside discovered Dropbox root",
            "Legacy/non-File Provider Dropbox cache location.",
        )
        add_dropbox_location(
            locations,
            root / ".dropbox",
            "root-metadata/support",
            "Do not delete blindly; may contain Dropbox metadata for this root.",
            "Hidden .dropbox folder inside discovered Dropbox root",
            "Usually small metadata, not a cleanup target.",
        )

    return roots


def add_known_dropbox_paths(locations: Dict[str, DropboxLocation]) -> None:
    known: List[Tuple[Path, str, str, str, str]] = [
        (Path("/Applications/Dropbox.app"), "app-bundle", "Uninstall only if you do not need Dropbox installed.", "standard app bundle", "Reinstalling brings most of this size back."),
        (HOME / "Applications" / "Dropbox.app", "app-bundle", "Uninstall only if you do not need Dropbox installed.", "per-user app bundle", "Reinstalling brings most of this size back."),
        (HOME / ".dropbox", "metadata/support", "Do not delete blindly; contains Dropbox account/link metadata.", "standard ~/.dropbox metadata directory", "May include info.json with linked account roots."),
        (LIB / "Application Support" / "Dropbox", "app-support", "Reset/relink risk; do not delete blindly.", "known Application Support location", "Can contain Dropbox application state and databases."),
        (LIB / "Application Support" / "com.getdropbox.dropbox", "app-support", "Reset/relink risk; do not delete blindly.", "known bundle-id Application Support location", "Can contain Dropbox application state and databases."),
        (LIB / "Caches" / "Dropbox", "app-cache", "Cache-like; quit Dropbox before clearing.", "known app cache location", "Usually safer than Application Support, but still inspect first."),
        (LIB / "Caches" / "com.getdropbox.dropbox", "app-cache", "Cache-like; quit Dropbox before clearing.", "known bundle-id cache location", "Usually safer than Application Support, but still inspect first."),
        (LIB / "HTTPStorages" / "com.getdropbox.dropbox", "app-cache", "Cache-like; quit Dropbox before clearing.", "known HTTPStorages location", "HTTP/web cache."),
        (LIB / "WebKit" / "com.getdropbox.dropbox", "app-cache", "Cache-like; quit Dropbox before clearing.", "known WebKit location", "WebKit cache/state."),
        (LIB / "Logs" / "Dropbox", "logs", "Usually low risk after quitting Dropbox; logs are mostly diagnostic.", "known logs location", "Inspect before deleting if troubleshooting."),
        (LIB / "Logs" / "Dropbox_debug.log", "logs", "Usually low risk after quitting Dropbox; logs are mostly diagnostic.", "known log file", "Inspect before deleting if troubleshooting."),
        (LIB / "Preferences" / "com.getdropbox.dropbox.plist", "preferences", "Low space impact; deleting can reset preferences.", "known preferences file", "Usually tiny."),
        (LIB / "Saved Application State" / "com.getdropbox.dropbox.savedState", "app-cache", "Low risk; saved window/app state only.", "known saved application state", "Usually tiny."),
        (LIB / "Containers" / "com.getdropbox.dropbox", "container/group-container", "Reset/relink risk; do not delete blindly.", "known sandbox container", "May contain File Provider or app state."),
        (LIB / "Containers" / "com.getdropbox.dropbox.FileProvider", "container/group-container", "Reset/relink risk; do not delete blindly.", "known File Provider container candidate", "May contain File Provider state."),
        (Path("/Library/Application Support/Dropbox"), "system-support", "System-level support; leave alone unless uninstalling Dropbox.", "system Application Support", "May require admin permissions."),
        (Path("/Library/Application Support/DropboxHelperTools"), "system-helper", "System-level helper tools; leave alone unless uninstalling Dropbox.", "system helper tools", "May require admin permissions."),
        (Path("/Library/PrivilegedHelperTools/com.dropbox.DropboxMacUpdate.agent"), "system-helper", "System-level updater helper; leave alone unless uninstalling Dropbox.", "privileged helper tool", "Usually not a space target."),
        (Path("/Library/LaunchDaemons/com.dropbox.DropboxMacUpdate.plist"), "system-helper", "System-level launch daemon; leave alone unless uninstalling Dropbox.", "launch daemon", "Usually tiny."),
        (Path("/Library/LaunchAgents/com.dropbox.DropboxMacUpdate.agent.plist"), "system-helper", "System-level launch agent; leave alone unless uninstalling Dropbox.", "launch agent", "Usually tiny."),
    ]

    for path, category, risk, source, notes in known:
        add_dropbox_location(locations, path, category, risk, source, notes)


def category_for_dropbox_discovery_root(root: Path) -> Tuple[str, str, str]:
    root_name = root.name.lower()
    root_str = str(root).lower()
    if "caches" in root_name or "httpstorages" in root_name or "webkit" in root_name:
        return "app-cache", "Cache-like; quit Dropbox before clearing.", "Dropbox-named direct child under a cache-like Library root"
    if "logs" in root_name:
        return "logs", "Usually low risk after quitting Dropbox; logs are mostly diagnostic.", "Dropbox-named direct child under Logs"
    if "preferences" in root_name:
        return "preferences", "Low space impact; deleting can reset preferences.", "Dropbox-named preference file"
    if "containers" in root_name or "group containers" in root_str:
        return "container/group-container", "Reset/relink risk; do not delete blindly.", "Dropbox-named container/group container"
    if "application support" in root_str:
        return "app-support", "Reset/relink risk; do not delete blindly.", "Dropbox-named Application Support item"
    return "discovered-dropbox-path", "Inspect manually before deleting.", "Dropbox-named path discovered by targeted scan"


def add_dropbox_library_discovery(locations: Dict[str, DropboxLocation]) -> None:
    roots = [
        LIB / "Application Support",
        LIB / "Caches",
        LIB / "HTTPStorages",
        LIB / "WebKit",
        LIB / "Logs",
        LIB / "Preferences",
        LIB / "Saved Application State",
        LIB / "Containers",
        LIB / "Group Containers",
        Path("/Library/Application Support"),
        Path("/Library/Caches"),
        Path("/Library/Logs"),
        Path("/Library/Preferences"),
        Path("/Library/PrivilegedHelperTools"),
        Path("/Library/LaunchAgents"),
        Path("/Library/LaunchDaemons"),
    ]

    for root in roots:
        for child in safe_iterdir(root):
            lname = child.name.lower()
            if not (path_name_has_dropbox(child) or lname.endswith(DROPBOX_FILE_PROVIDER_SYNC_SUFFIX)):
                continue
            category, risk, source = category_for_dropbox_discovery_root(root)
            add_dropbox_location(locations, child, category, risk, source, f"parent={root}")

    group_containers = LIB / "Group Containers"
    for child in safe_iterdir(group_containers):
        lname = child.name.lower()
        if lname.endswith(DROPBOX_FILE_PROVIDER_SYNC_SUFFIX) or "com.getdropbox.dropbox.sync" in lname:
            add_dropbox_location(
                locations,
                child,
                "container/group-container",
                "File Provider state; do not delete the whole container blindly.",
                "Dropbox File Provider sync group container",
                "Dropbox says the unique prefix may vary; this matches the suffix.",
            )
            add_dropbox_location(
                locations,
                child / "root-mount",
                "file-provider-cache",
                "Dropbox File Provider cache-like data; quit Dropbox and wait for DropboxFileProviderExtension to stop before clearing.",
                "Dropbox File Provider cache root-mount",
                "Current Dropbox Help identifies root-mount inside the .com.getdropbox.dropbox.sync Group Container as the File Provider cache target.",
            )


def walk_dropbox_named_paths(
    search_roots: List[Path],
    max_depth: int,
    skip_under: List[Path],
) -> Iterator[Path]:
    skip_resolved: List[Path] = []
    for p in skip_under:
        try:
            skip_resolved.append(p.resolve())
        except Exception:
            skip_resolved.append(p)

    for search_root in search_roots:
        if not search_root.exists():
            continue
        root_parts = len(search_root.parts)
        for dirpath, dirnames, filenames in os.walk(search_root, followlinks=False):
            current = Path(dirpath)
            try:
                current_resolved = current.resolve()
            except Exception:
                current_resolved = current

            if any(current_resolved == s or is_relative_to(current_resolved, s) for s in skip_resolved):
                dirnames[:] = []
                continue

            rel_depth = len(current.parts) - root_parts
            if rel_depth >= max_depth:
                dirnames[:] = []

            for name in list(dirnames) + list(filenames):
                lower = name.lower()
                if lower == ".dropbox.cache" or "dropbox" in lower or "getdropbox" in lower:
                    yield current / name


def add_dropbox_deep_discovery(
    locations: Dict[str, DropboxLocation],
    sync_roots: List[Path],
    search_volumes: bool,
    max_depth: int,
) -> None:
    search_roots = [HOME, LIB, Path("/Library"), Path("/Users/Shared")]
    if search_volumes:
        search_roots.append(Path("/Volumes"))

    for path in walk_dropbox_named_paths(search_roots, max_depth=max_depth, skip_under=sync_roots):
        lname = path.name.lower()
        if lname == ".dropbox.cache":
            category = "legacy-sync-cache"
            risk = "Cache-like; quit Dropbox before clearing. Prefer Dropbox's own cache-clear instructions."
            source = "optional deep discovery found .dropbox.cache"
        elif "cache" in lname:
            category = "app-cache"
            risk = "Cache-like; quit Dropbox before clearing."
            source = "optional deep discovery found Dropbox-named cache path"
        else:
            category = "discovered-dropbox-path"
            risk = "Inspect manually before deleting."
            source = "optional deep discovery found Dropbox-named path"
        add_dropbox_location(
            locations,
            path,
            category,
            risk,
            source,
            "Deep discovery is best-effort and may include non-Dropbox items with Dropbox in the name.",
        )


def build_dropbox_location_rows(locations: Dict[str, DropboxLocation]) -> List[Dict[str, str]]:
    locs = list(locations.values())
    paths = [loc.path for loc in locs]
    rows: List[Dict[str, str]] = []

    for loc in locs:
        kb = SIZE_CACHE.du_kb(loc.path)
        nested_under = ""
        ancestors = [a for a in paths if a != loc.path and is_relative_to(loc.path, a)]
        if ancestors:
            nested_under = str(max(ancestors, key=lambda a: len(a.parts)))
        rows.append({
            "category": loc.category,
            "size": human(kb),
            "size_kb": str(kb),
            "cleanup_risk": loc.cleanup_risk,
            "source": loc.source,
            "nested_under": nested_under,
            "path": str(loc.path),
            "notes": loc.notes,
        })

    rows.sort(key=lambda r: int(r["size_kb"]), reverse=True)
    return rows


def direct_children(path: Path) -> List[Path]:
    children = []
    for child in safe_iterdir(path):
        try:
            children.append(child)
        except Exception:
            continue
    return children


def build_dropbox_top_child_rows(
    locations: Dict[str, DropboxLocation],
    per_root_limit: int,
) -> List[Dict[str, str]]:
    if per_root_limit <= 0:
        return []

    root_categories = {"sync-root-local-files", "legacy-sync-cache", "file-provider-cache"}
    rows: List[Dict[str, str]] = []

    for loc in locations.values():
        if loc.category not in root_categories:
            continue
        if not loc.path.is_dir():
            continue
        child_rows: List[Dict[str, str]] = []
        for child in direct_children(loc.path):
            kb = SIZE_CACHE.du_kb(child)
            if kb <= 0:
                continue
            if loc.category == "sync-root-local-files":
                note = "Actual disk blocks used under the Dropbox root; use make-online-only/selective sync rather than deleting blindly."
            elif loc.category == "file-provider-cache":
                note = "Child inside Dropbox File Provider cache root-mount."
            else:
                note = "Child inside legacy .dropbox.cache."
            child_rows.append({
                "root_category": loc.category,
                "root_path": str(loc.path),
                "size": human(kb),
                "size_kb": str(kb),
                "path": str(child),
                "notes": note,
            })
        child_rows.sort(key=lambda r: int(r["size_kb"]), reverse=True)
        rows.extend(child_rows[:per_root_limit])

    rows.sort(key=lambda r: int(r["size_kb"]), reverse=True)
    return rows


def kb_from_bytes(value: int) -> int:
    if value <= 0:
        return 0
    return (value + 1023) // 1024


def allocated_bytes_from_stat(st: os.stat_result) -> int:
    return int(getattr(st, "st_blocks", 0) or 0) * 512


def file_kind(mode: int) -> str:
    if stat.S_ISREG(mode):
        return "regular-file"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISDIR(mode):
        return "directory"
    return "other"


def local_inventory_roots(locations: Dict[str, DropboxLocation]) -> List[DropboxLocation]:
    categories = {"sync-root-local-files", "legacy-sync-cache", "file-provider-cache"}
    selected: List[DropboxLocation] = []
    seen: Set[str] = set()
    for loc in locations.values():
        if loc.category not in categories:
            continue
        if not loc.path.exists() or not loc.path.is_dir():
            continue
        key = str(loc.path)
        if key in seen:
            continue
        seen.add(key)
        selected.append(loc)
    return selected


def scan_dropbox_local_inventory(
    roots: List[DropboxLocation],
    prefix: Path,
    min_local_kb: int,
    dir_depth: int,
    top_limit: int,
) -> Tuple[List[Dict[str, str]], List[Dict[str, str]], Path, List[str]]:
    """Inventory Dropbox files that occupy local disk blocks."""
    local_files_path = prefix.with_name(prefix.name + "_dropbox_local_files.csv")
    local_files_path.parent.mkdir(parents=True, exist_ok=True)

    dir_rows: List[Dict[str, str]] = []
    errors: List[str] = []
    top_heap: List[Tuple[int, int, Dict[str, str]]] = []
    sequence = 0

    with local_files_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=DROPBOX_LOCAL_FILE_FIELDS)
        writer.writeheader()

        for loc in roots:
            root = loc.path
            dir_alloc: Dict[str, int] = {}
            dir_logical: Dict[str, int] = {}
            dir_file_count: Dict[str, int] = {}
            dir_local_file_count: Dict[str, int] = {}
            dir_zero_block_file_count: Dict[str, int] = {}

            def onerror(err: OSError) -> None:
                errors.append(f"{err.filename}: {err.strerror}")

            for dirpath, dirnames, filenames in os.walk(root, topdown=False, followlinks=False, onerror=onerror):
                current = Path(dirpath)
                alloc_total = 0
                logical_total = 0
                file_count = 0
                local_file_count = 0
                zero_block_file_count = 0

                try:
                    st_current = os.lstat(current)
                    alloc_total += allocated_bytes_from_stat(st_current)
                    logical_total += int(getattr(st_current, "st_size", 0) or 0)
                except OSError as exc:
                    errors.append(f"{current}: {exc}")

                for name in filenames:
                    fp = current / name
                    try:
                        st = os.lstat(fp)
                    except OSError as exc:
                        errors.append(f"{fp}: {exc}")
                        continue

                    allocated = allocated_bytes_from_stat(st)
                    logical = int(getattr(st, "st_size", 0) or 0)
                    alloc_total += allocated
                    logical_total += logical
                    file_count += 1
                    if allocated > 0:
                        local_file_count += 1
                    else:
                        zero_block_file_count += 1

                    allocated_kb = kb_from_bytes(allocated)
                    if allocated > 0 and allocated_kb >= min_local_kb:
                        row = {
                            "root_category": loc.category,
                            "root_path": str(root),
                            "allocated": human(allocated_kb),
                            "allocated_kb": str(allocated_kb),
                            "logical": human(kb_from_bytes(logical)),
                            "logical_bytes": str(logical),
                            "kind": file_kind(st.st_mode),
                            "path": str(fp),
                        }
                        writer.writerow(row)
                        sequence += 1
                        heapq.heappush(top_heap, (allocated_kb, sequence, row))
                        if len(top_heap) > top_limit:
                            heapq.heappop(top_heap)

                for name in dirnames:
                    child = current / name
                    child_key = str(child)
                    if child_key in dir_alloc:
                        alloc_total += dir_alloc[child_key]
                        logical_total += dir_logical.get(child_key, 0)
                        file_count += dir_file_count.get(child_key, 0)
                        local_file_count += dir_local_file_count.get(child_key, 0)
                        zero_block_file_count += dir_zero_block_file_count.get(child_key, 0)
                    else:
                        try:
                            st_child = os.lstat(child)
                            alloc_total += allocated_bytes_from_stat(st_child)
                            logical_total += int(getattr(st_child, "st_size", 0) or 0)
                        except OSError:
                            pass

                current_key = str(current)
                dir_alloc[current_key] = alloc_total
                dir_logical[current_key] = logical_total
                dir_file_count[current_key] = file_count
                dir_local_file_count[current_key] = local_file_count
                dir_zero_block_file_count[current_key] = zero_block_file_count

            for key, allocated in dir_alloc.items():
                path = Path(key)
                try:
                    rel = path.relative_to(root)
                    depth = 0 if str(rel) == "." else len(rel.parts)
                except ValueError:
                    depth = 0

                include = depth <= dir_depth or path.name in {".dropbox.cache", ".dropbox", "root-mount"}
                if not include:
                    continue

                allocated_kb = kb_from_bytes(allocated)
                if allocated_kb <= 0:
                    continue

                logical_bytes = dir_logical.get(key, 0)
                dir_rows.append({
                    "root_category": loc.category,
                    "root_path": str(root),
                    "allocated": human(allocated_kb),
                    "allocated_kb": str(allocated_kb),
                    "logical": human(kb_from_bytes(logical_bytes)),
                    "logical_bytes": str(logical_bytes),
                    "file_count": str(dir_file_count.get(key, 0)),
                    "local_file_count": str(dir_local_file_count.get(key, 0)),
                    "zero_block_file_count": str(dir_zero_block_file_count.get(key, 0)),
                    "depth": str(depth),
                    "path": key,
                })

    dir_rows.sort(key=lambda r: int(r["allocated_kb"]), reverse=True)
    top_rows = [row for _kb, _seq, row in sorted(top_heap, key=lambda item: item[0], reverse=True)]
    return dir_rows, top_rows, local_files_path, errors


def run_dropbox_scan(args: argparse.Namespace) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    print("\nDropbox-focused read-only scan")
    print("================================")

    locations: Dict[str, DropboxLocation] = {}
    add_known_dropbox_paths(locations)
    sync_roots = add_dropbox_sync_roots(locations, search_volumes=args.dropbox_search_volumes)
    add_dropbox_library_discovery(locations)

    if args.dropbox_deep_discovery:
        add_dropbox_deep_discovery(
            locations,
            sync_roots=sync_roots,
            search_volumes=args.dropbox_search_volumes,
            max_depth=args.dropbox_discovery_depth,
        )

    location_rows = build_dropbox_location_rows(locations)
    child_rows = build_dropbox_top_child_rows(locations, per_root_limit=args.dropbox_top_children)
    inventory_dir_rows: List[Dict[str, str]] = []
    inventory_top_file_rows: List[Dict[str, str]] = []
    inventory_file_csv: Optional[Path] = None
    inventory_errors: List[str] = []

    if args.dropbox_local_inventory:
        inventory_roots = local_inventory_roots(locations)
        inventory_dir_rows, inventory_top_file_rows, inventory_file_csv, inventory_errors = scan_dropbox_local_inventory(
            roots=inventory_roots,
            prefix=Path(args.csv_prefix).expanduser(),
            min_local_kb=args.dropbox_min_local_kb,
            dir_depth=args.dropbox_inventory_depth,
            top_limit=max(args.top, 50),
        )

    if not location_rows:
        print("No existing Dropbox-related paths were found by the targeted scan.")
    else:
        print_table(
            "Largest Dropbox-related locations",
            ["Category", "Size", "Risk", "Nested under", "Path"],
            [[r["category"], r["size"], r["cleanup_risk"], r["nested_under"], r["path"]] for r in location_rows],
            args.top,
        )

    if child_rows:
        print_table(
            "Largest local children inside Dropbox roots/cache roots",
            ["Root category", "Size", "Path"],
            [[r["root_category"], r["size"], r["path"]] for r in child_rows],
            args.top,
        )

    if inventory_dir_rows:
        print_table(
            "Largest local Dropbox inventory directories",
            ["Root category", "Allocated", "Logical", "Local files", "Path"],
            [[r["root_category"], r["allocated"], r["logical"], r["local_file_count"], r["path"]] for r in inventory_dir_rows],
            args.top,
        )

    if inventory_top_file_rows:
        print_table(
            "Largest local Dropbox files written to CSV",
            ["Allocated", "Logical", "Kind", "Path"],
            [[r["allocated"], r["logical"], r["kind"], r["path"]] for r in inventory_top_file_rows],
            args.top,
        )

    prefix = Path(args.csv_prefix).expanduser()
    output_paths = [
        (prefix.with_name(prefix.name + "_dropbox_locations.csv"), location_rows, DROPBOX_LOCATION_FIELDS),
        (prefix.with_name(prefix.name + "_dropbox_top_children.csv"), child_rows, DROPBOX_TOP_CHILD_FIELDS),
    ]
    if args.dropbox_local_inventory:
        output_paths.append((prefix.with_name(prefix.name + "_dropbox_local_dirs.csv"), inventory_dir_rows, DROPBOX_LOCAL_DIR_FIELDS))

    for output_path, rows, fieldnames in output_paths:
        write_csv(output_path, rows, fieldnames)

    print("\nDropbox CSV written:")
    for output_path, _rows, _fieldnames in output_paths:
        print(f"  {output_path}")

    if args.dropbox_local_inventory:
        if inventory_file_csv is not None:
            print(f"  {inventory_file_csv}")
        if args.dropbox_min_local_kb > 0:
            print(f"  local-files threshold: >= {args.dropbox_min_local_kb} KiB allocated; use --dropbox-min-local-kb 0 for every local file occupying blocks")
        if inventory_errors:
            print(f"  inventory warnings: {len(inventory_errors)} permission/stat issues")

    print("\nDropbox scan notes:")
    print("  - sync-root-local-files is local disk used by your Dropbox folder/root; make files online-only or adjust selective sync instead of deleting the root.")
    print("  - legacy-sync-cache and file-provider-cache are the most cache-like Dropbox locations.")
    print("  - app-support and container/group-container can contain account state/databases; do not delete blindly.")
    print("  - nested_under means that path is already included in the parent path's size, so do not add both together.")
    return location_rows, child_rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only macOS app/cache/support storage audit with optional Dropbox scan")
    parser.add_argument("--top", type=int, default=30, help="Rows to print per section")
    parser.add_argument("--scan-depth", type=int, default=2, help="Depth to inspect under Caches/Application Support")
    parser.add_argument("--include-system", action="store_true", help="Also scan /System/Applications")
    parser.add_argument("--csv-prefix", default="mac_storage_audit_v2", help="CSV filename prefix")
    parser.add_argument("--dropbox", action="store_true", help="Also run a Dropbox-specific local-files/cache/location scan")
    parser.add_argument("--dropbox-only", action="store_true", help="Only run the Dropbox-specific scan")
    parser.add_argument("--dropbox-search-volumes", action="store_true", help="Also look one level under /Volumes for Dropbox roots")
    parser.add_argument("--dropbox-deep-discovery", action="store_true", help="Optional slower best-effort search for Dropbox-named paths")
    parser.add_argument("--dropbox-discovery-depth", type=int, default=5, help="Max depth for --dropbox-deep-discovery")
    parser.add_argument("--dropbox-top-children", type=int, default=40, help="Top children to list per Dropbox root/cache root; use 0 to disable")
    parser.add_argument("--dropbox-local-inventory", action="store_true", help="Walk Dropbox roots/cache roots and write CSVs of local files/directories occupying disk blocks")
    parser.add_argument("--dropbox-min-local-kb", type=int, default=1024, help="Minimum allocated KiB for rows in dropbox_local_files.csv; use 0 for every local file occupying blocks")
    parser.add_argument("--dropbox-inventory-depth", type=int, default=2, help="Directory depth to include in dropbox_local_dirs.csv; files are still scanned recursively")
    args = parser.parse_args()

    if args.dropbox_only:
        run_dropbox_scan(args)
        if SIZE_CACHE.errors:
            print(f"\nSome paths could not be sized: {len(SIZE_CACHE.errors)}. This is usually permissions-related.")
        print("\nNothing was deleted.")
        return 0

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

    prefix = Path(args.csv_prefix).expanduser()
    output_paths = [
        (prefix.with_name(prefix.name + "_by_app.csv"), by_app_rows, BY_APP_FIELDS),
        (prefix.with_name(prefix.name + "_matched_paths.csv"), path_rows, MATCHED_PATH_FIELDS),
        (prefix.with_name(prefix.name + "_large_library_dirs_raw.csv"), raw_dirs, LARGE_DIR_FIELDS),
        (prefix.with_name(prefix.name + "_large_library_dirs_specific.csv"), specific_dirs, LARGE_DIR_FIELDS),
    ]

    for output_path, rows, fieldnames in output_paths:
        write_csv(output_path, rows, fieldnames)

    print("\nCSV written:")
    for output_path, _rows, _fieldnames in output_paths:
        print(f"  {output_path}")

    if args.dropbox:
        run_dropbox_scan(args)

    if SIZE_CACHE.errors:
        print(f"\nSome paths could not be sized: {len(SIZE_CACHE.errors)}. This is usually permissions-related.")
    print("\nNothing was deleted.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
